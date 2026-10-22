// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ErrDrift is wrapped by Readback when the kernel does not hold the state the
// attachment requires.
var ErrDrift = errors.New("hostattach: kernel state does not match the attachment")

// Readback reads the attachment's links, addresses, neighbors and routes back
// from both namespaces and reports every difference from a, wrapped in
// ErrDrift. A successful netlink write is not proof the state is in place, so
// an attachment is only programmed once Readback passes.
func Readback(host, pod *Namespace, a Attachment) error {
	if err := verifyBoth(host, pod); err != nil {
		return err
	}
	hostH, err := host.netlink()
	if err != nil {
		return err
	}
	defer func() { _ = hostH.Close() }()
	podH, err := pod.netlink()
	if err != nil {
		return err
	}
	defer func() { _ = podH.Close() }()

	var drift []error
	add := func(format string, args ...any) { drift = append(drift, fmt.Errorf(format, args...)) }

	hostTable, err := vrfTable(hostH, a.HostVRF)
	if err != nil {
		return fmt.Errorf("%w: canonical host VRF: %w", ErrDrift, err)
	}
	hostLink, err := checkLink(hostH, a.HostLink, a.HostVRF, add)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDrift, err)
	}
	if hostLink.Attrs().Alias != ownerAlias(a.ID) {
		add("host link %q has owner %q, want %q", a.HostLink, hostLink.Attrs().Alias, ownerAlias(a.ID))
	}
	podLink, err := checkLink(podH, a.PodLink, a.PodVRF, add)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDrift, err)
	}
	if podTable, err := vrfTable(podH, a.PodVRF); err != nil || podTable != a.PodTable {
		add("pod VRF %q table %d, want %d (%v)", a.PodVRF, podTable, a.PodTable, err)
	}
	checkAddr(podH, podLink, a.Address, add)
	checkAddr(podH, podLink, podLinkLocal, add)
	checkAddr(hostH, hostLink, hostLinkLocal, add)
	checkNeigh(hostH, hostLink, a.Address, podLink.Attrs().HardwareAddr, add)
	checkNeigh(podH, podLink, hostLinkLocal, hostLink.Attrs().HardwareAddr, add)

	hostIdx := hostLink.Attrs().Index
	checkExtraRoutes(hostH, hostIdx, hostTable, hostPrefixes(a), add)
	checkRoute(hostH, hostTable, netip.PrefixFrom(a.Address, 128), hostIdx, netip.Addr{}, add)
	for _, p := range a.Prefixes {
		checkRoute(hostH, hostTable, p, hostIdx, a.Address, add)
	}
	checkRoute(podH, a.PodTable, netip.PrefixFrom(netip.IPv6Unspecified(), 0), podLink.Attrs().Index, hostLinkLocal, add)
	checkUnreachableDefault(podH, a.PodTable, add)
	checkLocalRoute(podH, a.PodTable, a.Address, add)

	if a.TUN != nil {
		tun, err := checkLink(podH, a.TUN.Name, a.PodVRF, add)
		if err == nil {
			checkExtraRoutes(podH, tun.Attrs().Index, a.PodTable, a.Prefixes, add)
			if tun.Attrs().Alias != ownerAlias(a.ID) {
				add("TUN ownership does not match attachment")
			}
			if t, ok := tun.(*netlink.Tuntap); ok && (t.Owner != a.TUN.Owner || t.Group != a.TUN.Group) {
				add("TUN %q owner %d:%d, want %d:%d", a.TUN.Name, t.Owner, t.Group, a.TUN.Owner, a.TUN.Group)
			}
			for _, p := range a.Prefixes {
				checkRoute(podH, a.PodTable, p, tun.Attrs().Index, netip.Addr{}, add)
			}
			if err := pod.do(func() error {
				b, err := os.ReadFile(filepath.Join("/proc/sys", podForwarding))
				if err == nil && strings.TrimSpace(string(b)) != "1" {
					add("IPv6 forwarding is off in the pod")
				}
				return err
			}); err != nil {
				add("read pod forwarding: %v", err)
			}
		} else {
			add("%v", err)
		}
	}

	if len(drift) > 0 {
		return fmt.Errorf("%w: %w", ErrDrift, errors.Join(drift...))
	}
	return nil
}

func checkLink(h *netlink.Handle, name, master string, add func(string, ...any)) (netlink.Link, error) {
	link, err := h.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("link %q: %w", name, err)
	}
	vrfLink, err := h.LinkByName(master)
	if err != nil {
		return nil, fmt.Errorf("VRF %q: %w", master, err)
	}
	if link.Attrs().MasterIndex != vrfLink.Attrs().Index {
		add("link %q is not enslaved to %q", name, master)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		add("link %q is down", name)
	}
	return link, nil
}

func checkAddr(h *netlink.Handle, link netlink.Link, want netip.Addr, add func(string, ...any)) {
	addrs, err := h.AddrList(link, unix.AF_INET6)
	if err != nil {
		add("list addresses on %q: %v", link.Attrs().Name, err)
		return
	}
	for _, a := range addrs {
		if got, ok := netip.AddrFromSlice(a.IP); ok && got == want {
			if a.Flags&unix.IFA_F_TENTATIVE != 0 {
				add("address %s on %q is tentative", want, link.Attrs().Name)
			}
			return
		}
	}
	add("address %s missing on %q", want, link.Attrs().Name)
}

func checkNeigh(h *netlink.Handle, link netlink.Link, ip netip.Addr, mac net.HardwareAddr, add func(string, ...any)) {
	neighs, err := h.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		add("list neighbors on %q: %v", link.Attrs().Name, err)
		return
	}
	for _, n := range neighs {
		if got, ok := netip.AddrFromSlice(n.IP); ok && got == ip {
			if n.State != netlink.NUD_PERMANENT || n.HardwareAddr.String() != mac.String() {
				add("neighbor %s on %q is %s state %#x, want %s permanent",
					ip, link.Attrs().Name, n.HardwareAddr, n.State, mac)
			}
			return
		}
	}
	add("neighbor %s missing on %q", ip, link.Attrs().Name)
}

// checkRoute requires a unicast route for dst in table through ifindex, via gw
// when gw is valid and directly otherwise.
func checkRoute(
	h *netlink.Handle, table uint32, dst netip.Prefix, ifindex int, gw netip.Addr, add func(string, ...any),
) {
	routes, err := h.RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		add("list routes in table %d: %v", table, err)
		return
	}
	for _, r := range routes {
		if !sameDst(r.Dst, dst) || r.Type != unix.RTN_UNICAST {
			continue
		}
		gotGw, _ := netip.AddrFromSlice(r.Gw)
		if r.LinkIndex == ifindex && gotGw == gw {
			return
		}
		add("route %s in table %d uses ifindex %d via %s, want ifindex %d via %s",
			dst, table, r.LinkIndex, gotGw, ifindex, gw)
		return
	}
	add("route %s missing in table %d", dst, table)
}

func checkUnreachableDefault(h *netlink.Handle, table uint32, add func(string, ...any)) {
	routes, err := h.RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		add("list routes in table %d: %v", table, err)
		return
	}
	for _, r := range routes {
		if r.Type == unix.RTN_UNREACHABLE && sameDst(r.Dst, netip.PrefixFrom(netip.IPv6Unspecified(), 0)) {
			return
		}
	}
	add("unreachable default missing in table %d", table)
}

// checkLocalRoute requires the kernel's local route for addr in table, without
// which the pod VRF does not deliver traffic addressed to the attachment.
func checkLocalRoute(h *netlink.Handle, table uint32, addr netip.Addr, add func(string, ...any)) {
	routes, err := h.RouteListFiltered(unix.AF_INET6,
		&netlink.Route{Table: int(table), Type: unix.RTN_LOCAL}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		add("list local routes in table %d: %v", table, err)
		return
	}
	for _, r := range routes {
		if sameDst(r.Dst, netip.PrefixFrom(addr, 128)) {
			return
		}
	}
	add("local route %s missing in table %d", addr, table)
}

func sameDst(got *net.IPNet, want netip.Prefix) bool {
	if got == nil {
		return want.Bits() == 0
	}
	addr, ok := netip.AddrFromSlice(got.IP)
	if !ok {
		return false
	}
	ones, _ := got.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones) == want
}

func checkExtraRoutes(h *netlink.Handle, index int, table uint32, want []netip.Prefix, add func(string, ...any)) {
	extras, err := extraRoutes(h, index, table, want)
	if err != nil {
		add("%v", err)
		return
	}
	for _, r := range extras {
		add("unexpected route %s in table %d through ifindex %d", r.Dst, table, index)
	}
}
