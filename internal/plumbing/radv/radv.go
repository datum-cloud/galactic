// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package radv sends IPv6 Router Advertisements out a tap interface's host
// side, so a VM guest attached to it can learn a default route. A guest is an
// opaque kernel this codebase has no netlink access into, unlike a
// veth-attached container whose namespace the CNI configures directly, so an RA
// is the only channel available to tell it about a gateway.
//
// Sending is deliberately split from tracking which taps need it. This file
// knows only how to construct and send one RA and how long to wait before the
// next. state.go owns the durable, cross-process record of which host
// interfaces are attached: the short-lived tap plugin writes it, and the
// long-lived node daemon reads it to keep resending on the jittered
// schedule.
package radv

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

// MaxRtrAdvInterval and MinRtrAdvInterval bound the delay between unsolicited
// RAs. RFC 4861 allows 4 to 1800 seconds for the maximum, and requires the
// minimum to be at least 3 seconds and no more than three quarters of it.
//
// These run tighter than the widely deployed defaults. There is exactly one
// router, this node, per tap link, so the multi-router synchronization concern
// behind the wider range does not apply, and a shorter interval costs nothing
// on a point-to-point link. The minimum stays just under the three-quarters
// ceiling, so a guest converges quickly without spending RAs it does not need.
//
// Vars rather than consts so tests can shrink them.
var (
	MaxRtrAdvInterval = 300 * time.Second
	MinRtrAdvInterval = 220 * time.Second
)

// RouterLifetime is advertised in every RA: how long a receiving guest keeps
// treating the advertising link-local address as its default router without
// another RA. RFC 4861 requires it to be at least MaxRtrAdvInterval and at most
// 9000 seconds.
//
// Three times the maximum interval gives a guest two full resend cycles of
// margin before its route goes stale, while still expiring it reasonably soon
// after an attachment disappears without a clean teardown, such as a node or
// VMM crash.
var RouterLifetime = 900 * time.Second

// allNodesMulticast is the destination for unsolicited RAs, and for a reply to
// a solicitation whose source was unspecified: every host on the link rather
// than just the one that solicited.
var allNodesMulticast = netip.MustParseAddr("ff02::1")

// allRoutersMulticast is the destination a guest sends Router Solicitations to.
// An actor joins this group on its tap host interface so its socket actually
// receives them, ICMPv6 multicast not being delivered to a socket that has not
// joined the group.
var allRoutersMulticast = netip.MustParseAddr("ff02::2")

// NextInterval returns a random delay in [MinRtrAdvInterval, MaxRtrAdvInterval)
// before the next unsolicited RA. Routers are required to jitter rather than
// fire on a fixed clock, so several on one link do not synchronize into bursts.
// Callers reschedule with a fresh call after every send rather than using a
// fixed-period ticker.
func NextInterval() time.Duration {
	span := MaxRtrAdvInterval - MinRtrAdvInterval
	return MinRtrAdvInterval + rand.N(span)
}

// MinDelayBetweenRAs and MaxRADelayTime are the fixed protocol constants
// governing solicited replies: no more than one advertisement within
// MinDelayBetweenRAs of the last one sent, solicited or not, and a random delay
// in [0, MaxRADelayTime) before replying, so several solicitations arriving
// together do not each provoke a synchronized reply.
//
// Vars rather than consts so tests can shrink them; unlike the intervals above,
// the RFC does not intend these to be tunable in production.
var (
	MinDelayBetweenRAs = 3 * time.Second
	MaxRADelayTime     = 500 * time.Millisecond
)

// nextResponseDelay returns a random delay in [0, MaxRADelayTime) to wait
// before replying to a Router Solicitation.
func nextResponseDelay() time.Duration {
	return rand.N(MaxRADelayTime)
}

// buildAdvertisement constructs the Router Advertisement both the unsolicited
// resend and the solicited reply send, so the two paths cannot drift apart on
// hop limit, lifetime, or options.
func buildAdvertisement(mtu int, hwAddr net.HardwareAddr) *ndp.RouterAdvertisement {
	return &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  RouterLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      hwAddr,
			},
			ndp.NewMTU(uint32(mtu)),
		},
	}
}

// SendRouterAdvertisement sends one unsolicited Router Advertisement out iface,
// a tap interface's host side, sourced from that interface's kernel-assigned
// link-local address. Nothing in this codebase programs a link-local address
// onto a veth or tap, so this relies on the kernel's automatic assignment; the
// listen call reads that address back rather than creating one. mtu is
// advertised as the link's MTU.
//
// The RA carries no prefix information option: a tap-attached guest gets its
// address from IPAM rather than autoconfiguration, so the only things announced
// are the default router and the MTU.
//
// A standalone one-shot sender. Production use is RunActor, which keeps one
// connection open per attachment for its whole lifetime, handling both the
// periodic resend and solicitation replies. This remains for a caller needing a
// single send with no solicitation handling.
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

	ra := buildAdvertisement(mtu, ifi.HardwareAddr)
	if err := conn.WriteTo(ra, nil, allNodesMulticast); err != nil {
		return fmt.Errorf("send router advertisement on %q: %w", iface, err)
	}

	return nil
}
