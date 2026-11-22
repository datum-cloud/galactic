// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// ensurePodVRF creates vpc's VRF in the calling process's network namespace,
// with its table from the sidecar's range and the unreachable defaults
// vrf.AddInRange installs, unless a VRF of that name in that range exists.
// A VRF of that name with a table outside the range is an error.
func ensurePodVRF(vpc string) error {
	name := intf.GenerateInterfaceNameVRF(vpc)
	l, err := netlink.LinkByName(name)
	if err == nil {
		if v, ok := l.(*netlink.Vrf); ok && v.Table >= sidecarTableIDMin && v.Table <= sidecarTableIDMax {
			return nil
		}
	} else if !errors.As(err, &netlink.LinkNotFoundError{}) {
		return fmt.Errorf("look up VRF %s: %w", name, err)
	}
	if err := vrf.AddInRange(vpc, sidecarTableIDMin, sidecarTableIDMax); err != nil {
		if errors.Is(err, vrf.ErrTableOutOfRange) {
			return fmt.Errorf("create VRF for vpc %s: %w; an older sidecar created it in this pod, "+
				"so replace the pod rather than restarting the container", vpc, err)
		}
		return fmt.Errorf("create VRF for vpc %s: %w", vpc, err)
	}
	return nil
}

// configureRoutedPodLink enslaves podEnd to the VRF named vrfName, assigns it
// the gateway addresses and sets it up, and makes the routed link the VRF's
// only unicast default route: through podEnd to hostLL, with the first IPv6
// gateway address as its source. It removes every other route of
// podLinkProtocol in the VRF's table, such as a Local backend's /128 an
// in-pod encapsulating sidecar made. The error wraps errVRFMissing when the
// VRF does not exist.
func configureRoutedPodLink(vrfName, podEnd string, gateway []netip.Addr, hostLL netip.Addr) error {
	vrfLink, pl, err := wirePodEnd(vrfName, podEnd, gateway)
	if err != nil {
		return err
	}
	if pl.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(pl); err != nil {
			return fmt.Errorf("set %s up: %w", podEnd, err)
		}
	}
	src := gatewaySource(gateway)
	if src != nil {
		// The kernel refuses a route source that is still tentative.
		waitAddrUsable(pl, src)
	}
	if err := ensureLinkDefault(vrfLink.Table, pl.Attrs().Index, net.IP(hostLL.AsSlice()), src); err != nil {
		return err
	}
	return removePodLinkHostRoutes(vrfLink.Table)
}

// ensureLinkDefault makes table's only unicast IPv6 default route the one
// through the link with index linkIdx to gw, with source src (none when nil)
// and protocol podLinkProtocol. Other unicast default routes, such as one
// into an in-pod encapsulating datapath, are removed. Routes of other types,
// such as the VRF's unreachable default, stay.
func ensureLinkDefault(table uint32, linkIdx int, gw, src net.IP) error {
	isOurs := func(r netlink.Route) bool {
		return r.LinkIndex == linkIdx && r.Gw.Equal(gw) && r.Protocol == podLinkProtocol && r.Src.Equal(src)
	}
	defaults, err := unicastDefaults(table)
	if err != nil {
		return err
	}
	have := false
	for _, r := range defaults {
		if isOurs(r) {
			have = true
			break
		}
	}
	if !have {
		// A default route at the same metric, as one into the in-pod
		// datapath, is replaced in place, so the VRF is never without one.
		r := &netlink.Route{Table: int(table), Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Gw: gw, LinkIndex: linkIdx, Src: src, Protocol: podLinkProtocol}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route the default of table %d via %s through ifindex %d: %w", table, gw, linkIdx, err)
		}
		if defaults, err = unicastDefaults(table); err != nil {
			return err
		}
	}
	kept := false
	for _, r := range defaults {
		if !kept && isOurs(r) {
			kept = true
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove default route via %s from table %d: %w", r.Gw, table, err)
		}
	}
	return nil
}

// unicastDefaults returns table's unicast IPv6 default routes.
func unicastDefaults(table uint32) ([]netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes of VRF table %d: %w", table, err)
	}
	var out []netlink.Route
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		if r.Dst == nil {
			out = append(out, r)
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); ones == 0 && bits == 128 {
			out = append(out, r)
		}
	}
	return out, nil
}

// removePodLinkHostRoutes removes every route of podLinkProtocol in table
// other than a default route.
func removePodLinkHostRoutes(table uint32) error {
	have, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table), Protocol: podLinkProtocol},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("list routes of table %d: %w", table, err)
	}
	for _, r := range have {
		if r.Dst == nil {
			continue
		}
		if ones, _ := r.Dst.Mask.Size(); ones == 0 {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove route %s from table %d: %w", r.Dst, table, err)
		}
	}
	return nil
}

// waitAddrUsable waits up to 2s for a on l to leave the tentative state,
// which an address added with NODAD does shortly after the add returns. It
// returns early when a is not assigned, and leaves a failure to the caller's
// next step.
func waitAddrUsable(l netlink.Link, a net.IP) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
		if err != nil {
			return
		}
		found, tentative := false, false
		for _, x := range addrs {
			if x.IP.Equal(a) {
				found, tentative = true, x.Flags&unix.IFA_F_TENTATIVE != 0
			}
		}
		if !found || !tentative || time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
