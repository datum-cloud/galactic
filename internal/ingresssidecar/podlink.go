// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// podLinkProtocol marks the routes kernelPodLink makes, so it removes only
// its own: a Local backend's /128 through the routed link.
const podLinkProtocol = netlink.RouteProtocol(0x47)

// kernelPodLink is the production PodLink, in the calling process's network
// namespace, which is the proxy pod's.
type kernelPodLink struct{}

// NewKernelPodLink returns the production PodLink. Requires CAP_NET_ADMIN.
func NewKernelPodLink() PodLink { return kernelPodLink{} }

// Configure implements PodLink.
func (kernelPodLink) Configure(vpc, podEnd string, gateway []netip.Addr, hostLL netip.Addr, local []netip.Addr) error {
	return configurePodLink(intf.GenerateInterfaceNameVRF(vpc), podEnd, gateway, hostLL, local)
}

// configurePodLink configures podEnd in the VRF named vrfName.
func configurePodLink(vrfName, podEnd string, gateway []netip.Addr, hostLL netip.Addr, local []netip.Addr) error {
	vl, err := netlink.LinkByName(vrfName)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("%w: %s", errVRFMissing, vrfName)
		}
		return fmt.Errorf("look up VRF %s: %w", vrfName, err)
	}
	vrfLink, ok := vl.(*netlink.Vrf)
	if !ok {
		return fmt.Errorf("%s is a %s, not a VRF", vrfName, vl.Type())
	}
	pl, err := netlink.LinkByName(podEnd)
	if err != nil {
		return fmt.Errorf("look up the routed link's pod end %s: %w", podEnd, err)
	}
	if pl.Attrs().MasterIndex != vrfLink.Index {
		if err := netlink.LinkSetMasterByIndex(pl, vrfLink.Index); err != nil {
			return fmt.Errorf("enslave %s to %s: %w", podEnd, vrfName, err)
		}
	}
	for _, a := range gateway {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		if err := ensureGateway(pl, vrfLink.Table, a); err != nil {
			return err
		}
	}
	if err := removeStaleGateways(pl, gateway); err != nil {
		return err
	}
	if pl.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(pl); err != nil {
			return fmt.Errorf("set %s up: %w", podEnd, err)
		}
	}
	return syncLocalRoutes(vrfLink.Table, pl.Attrs().Index, hostLL, local)
}

// ensureGateway assigns the gateway address a to the pod end l and makes
// sure the kernel's local route for it exists in the VRF's table. Without
// that route the pod treats the gateway as an on-link neighbor instead of
// its own address, and answers nothing sent to it. Replacing an address that
// is already assigned removes that local route, so ensureGateway adds a only
// when it is missing, and deletes and re-adds it when its local route is gone.
// The gateway addresses are this pod's own: no other host on the link can hold
// them, so duplicate address detection would only delay them.
func ensureGateway(l netlink.Link, table uint32, a netip.Addr) error {
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD}
	assigned, err := hasAddr(l, a)
	if err != nil {
		return err
	}
	if assigned {
		ok, err := hasLocalRoute(table, l.Attrs().Index, a)
		if err != nil || ok {
			return err
		}
		if err := netlink.AddrDel(l, addr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("remove gateway %s from %s to restore its local route: %w", a, l.Attrs().Name, err)
		}
	}
	if err := netlink.AddrAdd(l, addr); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("assign gateway %s to %s: %w", a, l.Attrs().Name, err)
	}
	return nil
}

// hasAddr reports whether a is assigned to l.
func hasAddr(l netlink.Link, a netip.Addr) (bool, error) {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
	if err != nil {
		return false, fmt.Errorf("list addresses of %s: %w", l.Attrs().Name, err)
	}
	for _, x := range addrs {
		if ip, ok := netip.AddrFromSlice(x.IP); ok && ip.Unmap() == a {
			return true, nil
		}
	}
	return false, nil
}

// hasLocalRoute reports whether table holds the kernel's local route for a
// on the link with index linkIdx.
func hasLocalRoute(table uint32, linkIdx int, a netip.Addr) (bool, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table), Type: unix.RTN_LOCAL},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		return false, fmt.Errorf("list local routes of table %d: %w", table, err)
	}
	for _, r := range routes {
		if dst, ok := routeDst(r); ok && dst == a && r.LinkIndex == linkIdx {
			return true, nil
		}
	}
	return false, nil
}

// syncLocalRoutes makes the routes podLinkProtocol owns in table exactly a
// /128 to each address in local through the link with index linkIdx to
// hostLL. They override the VRF's default route, which leads into the
// encapsulating datapath, for backends on this node.
func syncLocalRoutes(table uint32, linkIdx int, hostLL netip.Addr, local []netip.Addr) error {
	have, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table), Protocol: podLinkProtocol},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("list routes of table %d: %w", table, err)
	}
	want := map[netip.Addr]bool{}
	for _, a := range local {
		if a.Is6() && !a.Is4In6() {
			want[a] = true
		}
	}
	gw := net.IP(hostLL.AsSlice())
	for _, r := range have {
		dst, ok := routeDst(r)
		if ok && want[dst] && r.LinkIndex == linkIdx && r.Gw.Equal(gw) {
			delete(want, dst)
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove route %s from table %d: %w", r.Dst, table, err)
		}
	}
	for a := range want {
		r := &netlink.Route{Table: int(table), Dst: &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(128, 128)},
			Gw: gw, LinkIndex: linkIdx, Protocol: podLinkProtocol}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route %s via %s in table %d: %w", a, hostLL, table, err)
		}
	}
	return nil
}

// routeDst returns r's destination address when it is a /128.
func routeDst(r netlink.Route) (netip.Addr, bool) {
	if r.Dst == nil {
		return netip.Addr{}, false
	}
	if ones, bits := r.Dst.Mask.Size(); ones != 128 || bits != 128 {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(r.Dst.IP)
	return a.Unmap(), ok
}

// removeStaleGateways removes the global /128 addresses on the pod end l
// that are no longer gateway addresses, as after the proxy attachment's
// addresses changed. Configure assigns only such addresses to the link.
func removeStaleGateways(l netlink.Link, gateway []netip.Addr) error {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list addresses of %s: %w", l.Attrs().Name, err)
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || ip.IsLinkLocalUnicast() {
			continue
		}
		if ones, bits := a.Mask.Size(); ones != 128 || bits != 128 {
			continue
		}
		if slices.Contains(gateway, ip.Unmap()) {
			continue
		}
		if err := netlink.AddrDel(l, &a); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("remove stale gateway %s from %s: %w", ip, l.Attrs().Name, err)
		}
	}
	return nil
}
