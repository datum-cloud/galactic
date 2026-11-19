// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

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
	// The gateway addresses are this pod's own: no other host on the link
	// can hold them, so duplicate address detection would only delay them.
	for _, a := range gateway {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(128, 128)},
			Flags: unix.IFA_F_NODAD}
		if err := netlink.AddrReplace(pl, addr); err != nil {
			return fmt.Errorf("assign gateway %s to %s: %w", a, podEnd, err)
		}
	}
	if pl.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(pl); err != nil {
			return fmt.Errorf("set %s up: %w", podEnd, err)
		}
	}
	return syncLocalRoutes(vrfLink.Table, pl.Attrs().Index, hostLL, local)
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
