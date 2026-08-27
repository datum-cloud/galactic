// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package radv sends IPv6 Router Advertisements (RFC 4861) out a tap
// interface's host side so a VM guest attached to it (Kata, Firecracker,
// kraftlet/Unikraft) can learn a default route. A VM guest is an opaque
// kernel this codebase has no netlink access into — unlike a veth-attached
// container, whose guest netns galactic-veth configures directly (address
// and default route both) via internal/cni/netns.go — so an RA is the only
// channel available to tell it about a gateway at all.
//
// Sending is deliberately split from tracking which tap interfaces need it:
// this file only knows how to construct and send one RA, and how long to
// wait before the next one (RFC 4861 §6.2.4's jittered interval). State.go
// owns the durable, cross-process record of which host interfaces are
// currently attached, which internal/cnitap (galactic-tap, short-lived, one
// exec per CNI ADD/DEL) writes and internal/installer's long-lived daemon
// (one process per node, for as long as the node has any tap attachments)
// reads to keep resending on that jittered schedule — see state.go's own
// doc comment for why a single send at ADD time is not sufficient on its
// own.
package radv

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

// MaxRtrAdvInterval and MinRtrAdvInterval bound the delay between
// unsolicited RAs, per RFC 4861 §6.2.1 (valid range 4–1800s for Max; Min
// MUST be no less than 3s and no greater than .75 * Max). radvd's own
// widely-deployed default is Max=600s/Min≈198s (0.33 * Max) — this package
// runs tighter than that: there is exactly one router (this node) per tap
// link, so the multi-router synchronization concern the wider default range
// guards against doesn't apply, and there's no meaningful bandwidth cost to
// a shorter interval on a single point-to-point tap link. Min=220s keeps
// comfortably under the .75 * Max = 225s ceiling while staying close to
// Max, so a guest converges quickly without spending unsolicited RAs it
// doesn't need. Package-level vars (not consts), matching
// internal/installer's ebpfHealthCheckInterval override pattern, so tests
// can shrink them.
var (
	MaxRtrAdvInterval = 300 * time.Second
	MinRtrAdvInterval = 220 * time.Second
)

// RouterLifetime is the RouterLifetime advertised in every RA this package
// sends (RFC 4861 §4.2) — how long a receiving guest should keep treating
// the advertising link-local address as its default router absent another
// RA. RFC 4861 §6.2.1 requires RouterLifetime >= MaxRtrAdvInterval (and <=
// 9000s, the protocol's hard cap); 900s (3x MaxRtrAdvInterval) gives a
// guest two full resend cycles of margin before its route would go stale,
// while still expiring a guest's route reasonably soon after a tap
// attachment disappears without a clean DEL (e.g. a hard node/VMM crash) —
// unlike the one-shot version of this package, which used the 9000s hard
// cap directly because nothing existed to refresh it before then.
var RouterLifetime = 900 * time.Second

// allNodesMulticast is the RFC 4861 §6.2.3 destination for unsolicited RAs —
// every host on the link, not just one that solicited.
var allNodesMulticast = netip.MustParseAddr("ff02::1")

// NextInterval returns a random delay in [MinRtrAdvInterval,
// MaxRtrAdvInterval) before the next unsolicited RA should be sent, per RFC
// 4861 §6.2.4 — routers are required to jitter rather than fire on a fixed
// clock specifically so that multiple routers on the same link don't
// synchronize their RAs into bursts. Callers reschedule with a fresh call to
// this function after every send (see internal/installer's radvTimer),
// rather than using a fixed-period ticker.
func NextInterval() time.Duration {
	span := MaxRtrAdvInterval - MinRtrAdvInterval
	return MinRtrAdvInterval + rand.N(span)
}

// SendRouterAdvertisement sends a single unsolicited Router Advertisement out
// iface (a tap interface's host side), sourced from that interface's
// kernel-assigned IPv6 link-local address. galactic-cni never programs a
// link-local address of its own onto a veth or tap interface — see
// internal/cni/tap's and internal/cni/veth's own doc comments — so this
// relies entirely on the kernel's automatic fe80::/10 assignment as the RA's
// source; ndp.Listen(ifi, ndp.LinkLocal) reads that address back rather than
// creating one.
//
// The RA carries no Prefix Information option: a tap-attached guest gets its
// address from IPAM, not IPv6 SLAAC, so the only thing being announced is
// "this link-local address is your default router" plus the link's MTU —
// nothing about how to self-assign an address. Callers are expected to
// invoke this repeatedly, spaced per NextInterval, for as long as the
// attachment exists (see state.go) rather than relying on one call to be
// sufficient; a single call at CNI ADD time can race the guest's own boot
// and land before anything is listening.
func SendRouterAdvertisement(iface string, mtu int) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", iface, err)
	}

	conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("open NDP connection on %q: %w", iface, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  RouterLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      ifi.HardwareAddr,
			},
			ndp.NewMTU(uint32(mtu)),
		},
	}

	if err := conn.WriteTo(ra, nil, allNodesMulticast); err != nil {
		return fmt.Errorf("send router advertisement on %q: %w", iface, err)
	}

	return nil
}
