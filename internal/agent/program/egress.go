// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package program installs and removes kernel egress routes for
// remote pods learned via BGP. Replaces internal/agent/srv6/routeegress
// in the MQTT-driven design. The netlink primitive is identical; the
// trigger and the input shape change.
//
// The package owns the hex→base62 conversion at the kernel-facing
// boundary. Inputs are hex (the agent's lingua franca above the kernel
// layer); netlink names are base62 (the kernel-friendly form). See
// PLAN-bgp-cutover.md "Identifier-encoding boundary."
package program

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.datum.net/galactic/pkg/common/util"
	"go.datum.net/galactic/pkg/common/vrf"
)

// LoopbackDevice is the loopback used as link-index for egress routes.
// Mirrors the convention in the legacy routeegress package.
const LoopbackDevice = "lo-galactic"

// vrfLookupFn is injected by tests; production calls vrf.GetVRFIdForVPC
// directly. Defined as a package-level var so the regression-guard test
// can verify that base62 strings reach the lookup, not hex.
var vrfLookupFn = vrf.GetVRFIdForVPC

// Add installs an SRv6 egress route for the given remote prefix into
// this attachment's VRF. segments is the SRv6 segment list — for
// Galactic's single-hop service-SID design this is exactly one IPv6
// address (the remote node's service SID).
func Add(vpcHex, attachHex string, prefix *net.IPNet, segments []net.IP) error {
	vrfId, err := lookupVRF(vpcHex, attachHex)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(LoopbackDevice)
	if err != nil {
		return fmt.Errorf("loopback %q: %w", LoopbackDevice, err)
	}
	encap := &netlink.SEG6Encap{
		Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: segments,
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(vrfId),
		LinkIndex: link.Attrs().Index,
		Encap:     encap,
	}
	return netlink.RouteReplace(route)
}

// Delete removes the egress route. Idempotent — a missing route is not
// an error.
func Delete(vpcHex, attachHex string, prefix *net.IPNet) error {
	vrfId, err := lookupVRF(vpcHex, attachHex)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(LoopbackDevice)
	if err != nil {
		return fmt.Errorf("loopback %q: %w", LoopbackDevice, err)
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(vrfId),
		LinkIndex: link.Attrs().Index,
	}
	if err := netlink.RouteDel(route); err != nil {
		// Match the legacy package's leniency: missing routes during
		// teardown are common and not interesting to surface.
		if err.Error() == "no such process" {
			return nil
		}
		return err
	}
	return nil
}

// lookupVRF performs the explicit hex→base62 conversion required at
// the kernel-facing boundary. Errors are surfaced rather than silently
// ignored — see PLAN-bgp-cutover.md.
func lookupVRF(vpcHex, attachHex string) (uint32, error) {
	vpcB62, err := util.HexToBase62(vpcHex)
	if err != nil {
		return 0, fmt.Errorf("HexToBase62 vpc %q: %w", vpcHex, err)
	}
	attachB62, err := util.HexToBase62(attachHex)
	if err != nil {
		return 0, fmt.Errorf("HexToBase62 attach %q: %w", attachHex, err)
	}
	return vrfLookupFn(vpcB62, attachB62)
}
