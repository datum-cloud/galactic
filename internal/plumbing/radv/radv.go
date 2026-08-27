// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package radv sends a one-shot, unsolicited ICMPv6 Router Advertisement
// (RFC 4861 Section 4.2) out a tap attachment's host-side interface, so a
// freshly attached VM/unikernel guest installs a default route toward this
// host without any guest-side static configuration or metadata channel.
//
// This is a stopgap, not the durable mechanism described in
// docs/agents/ARCHITECTURE-CNI.md: galactic-tap's cmdAdd runs once per
// attachment and exits (the standard CNI exec-per-command model — see
// internal/cnitap's own doc comment), so nothing here re-sends the
// advertisement before its RouterLifetime expires. A guest that stays
// attached longer than DefaultRouterLifetime loses its default route until
// this is replaced by something that can react to Router Solicitations and
// refresh the lifetime periodically — e.g. a per-node radvd instance driven
// by a config stanza this plugin writes on ADD/DEL, or a ticker in the
// long-lived galactic-cni "run" process (internal/installer.Run).
//
// No Prefix Information option is sent: tap attachments get their address
// from IPAM, not SLAAC (see internal/hostgw's doc comment on why the
// gateway address is installed with a full-length mask), so the guest only
// needs a default router, not an autoconfigured global address.
package radv

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

// DefaultRouterLifetime is how long the guest should keep this host in its
// default router list before the route is considered stale. Long enough to
// outlast a short test session; a real deployment needs periodic
// re-advertisement well before this expires (see package doc).
const DefaultRouterLifetime = 9000 * time.Second

// defaultCurrentHopLimit is advertised so the guest adopts it as its own
// outgoing unicast hop limit, matching the value used for veth guests
// elsewhere in this codebase.
const defaultCurrentHopLimit = 64

// allNodesMulticast is the standard destination for an unsolicited Router
// Advertisement (RFC 4861 Section 6.2.3): every IPv6 host on the link
// listens on ff02::1, so no prior Router Solicitation is required.
var allNodesMulticast = netip.MustParseAddr("ff02::1")

// SendRouterAdvertisement sends a single unsolicited Router Advertisement
// out iface, announcing this host — via the interface's own link-local
// address and MAC — as a default router with DefaultRouterLifetime and the
// given MTU.
func SendRouterAdvertisement(iface string, mtu int) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", iface, err)
	}

	conn, src, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("open NDP connection on %q: %w", iface, err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: defaultCurrentHopLimit,
		RouterLifetime:  DefaultRouterLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      ifi.HardwareAddr,
			},
			ndp.NewMTU(uint32(mtu)),
		},
	}

	if err := conn.WriteTo(ra, nil, allNodesMulticast); err != nil {
		return fmt.Errorf("send router advertisement from %s on %q: %w", src, iface, err)
	}
	return nil
}
