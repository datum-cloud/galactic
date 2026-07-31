// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// configureInterfaceInNetns applies IP addresses and default routes to the
// guest interface inside the container network namespace. ipv4Net/ipv4GW are
// nil for an IPv6-only attachment.
func configureInterfaceInNetns(
	netnsPath, ifName string,
	ipv6Net *net.IPNet, ipv6GW net.IP,
	ipv4Net *net.IPNet, ipv4GW net.IP,
) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	if err := containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find guest interface %q: %w", ifName, err)
		}

		if err := addAddrAndDefaultRoute(handle, link, ifName, ipv6Net, ipv6GW); err != nil {
			return err
		}
		if err := addAddrAndDefaultRoute(handle, link, ifName, ipv4Net, ipv4GW); err != nil {
			return err
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("set interface %q up: %w", ifName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	slog.Debug("netns: guest interface configured", "ifName", ifName, "netns", netnsPath,
		"ipv6Address", ipv6Net, "ipv6Gateway", ipv6GW, "ipv4Address", ipv4Net, "ipv4Gateway", ipv4GW)
	return nil
}

// addAddrAndDefaultRoute assigns ipNet to link and, if gateway is set,
// installs a default route via it. No-op when ipNet is nil (family not in
// use for this attachment). Both the address and the route are added
// idempotently: a call that finds its target already in place (e.g. a
// retried CNI ADD against a netns that a previous, non-DEL'd ADD already
// configured) succeeds without touching kernel state; a call that finds
// different, conflicting state fails loudly instead of overwriting it.
func addAddrAndDefaultRoute(
	handle *netlink.Handle, link netlink.Link, ifName string, ipNet *net.IPNet, gateway net.IP,
) error {
	if ipNet == nil {
		return nil
	}

	if err := addAddrIfMissing(handle, link, ifName, ipNet); err != nil {
		return err
	}

	if gateway == nil {
		return nil
	}
	return addDefaultRouteIfMissing(handle, link, ifName, gateway)
}

// addrFamily returns the netlink address family for an IP, so callers can
// scope AddrList/RouteList lookups to the family being configured.
func addrFamily(ip net.IP) int {
	if ip.To4() != nil {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// addAddrIfMissing adds ipNet to link unless an identical address (same IP
// and prefix length) is already present, in which case it is a no-op. A
// link can legitimately carry multiple distinct addresses per family, so no
// existing address is ever treated as a conflict here — only an exact match
// short-circuits the add.
func addAddrIfMissing(handle *netlink.Handle, link netlink.Link, ifName string, ipNet *net.IPNet) error {
	want := netlink.Addr{IPNet: ipNet}

	existing, err := handle.AddrList(link, addrFamily(ipNet.IP))
	if err != nil {
		return fmt.Errorf("list addresses on %q: %w", ifName, err)
	}
	for _, addr := range existing {
		if addr.Equal(want) {
			return nil // already configured by a previous ADD
		}
	}

	if err := handle.AddrAdd(link, &want); err != nil {
		return fmt.Errorf("add IP %s to %q: %w", ipNet, ifName, err)
	}
	return nil
}

// addDefaultRouteIfMissing installs a default route via gateway on link
// unless a default route via that same gateway already exists, in which
// case it is a no-op. If a default route via a *different* gateway already
// exists, that's a real misconfiguration (not something a retried ADD
// should paper over), so it is returned as an error instead.
func addDefaultRouteIfMissing(handle *netlink.Handle, link netlink.Link, ifName string, gateway net.IP) error {
	existing, err := handle.RouteList(link, addrFamily(gateway))
	if err != nil {
		return fmt.Errorf("list routes on %q: %w", ifName, err)
	}
	for _, r := range existing {
		if !isDefaultRouteDst(r.Dst) {
			continue
		}
		if r.Gw.Equal(gateway) {
			return nil // already configured by a previous ADD
		}
		return fmt.Errorf("default route on %q already points via %s, refusing to add conflicting route via %s",
			ifName, r.Gw, gateway)
	}

	// onlink: the IPv4 pool allocates a /32 host address (no on-link subnet
	// route to the gateway), so the kernel refuses this route with
	// ENETUNREACH unless told to treat the gateway as directly reachable.
	// IPv6's /96 subnet allocation already covers the gateway, so the flag
	// is a no-op there — safe to set unconditionally for both families.
	defaultRoute := &netlink.Route{
		Dst:       nil, // default route
		Gw:        gateway,
		LinkIndex: link.Attrs().Index,
		Flags:     int(netlink.FLAG_ONLINK),
	}
	if err := handle.RouteAdd(defaultRoute); err != nil {
		return fmt.Errorf("add default route via %s: %w", gateway, err)
	}
	return nil
}

// isDefaultRouteDst reports whether dst represents a default route
// (0.0.0.0/0 or ::/0). netlink represents this as a nil Dst on routes it
// creates itself, but routes read back from the kernel may instead carry an
// explicit zero-length-prefix net.IPNet.
func isDefaultRouteDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}

// flushGuestNetnsConfig removes any IP addresses and default routes
// configured on ifName inside the container netns, without deleting the
// link itself. No-op if ifName is not present.
//
// DEL normally relies on hostDevice DEL moving the guest veth end back out
// of the container netns to flush this state as a side effect: the kernel
// strips a link's addresses/routes when it genuinely crosses a namespace
// boundary. But that move is a no-op — and so triggers no such flush — when
// the "container" netns is the same namespace the link already lives in
// (e.g. a hostNetwork pod with a Multus secondary attachment, where
// args.Netns resolves to the host's own root netns rather than a distinct
// per-sandbox namespace). Left unflushed, that state survives indefinitely
// (there is no ephemeral sandbox netns to tear down and reclaim it), and the
// next ADD on that same interface fails with "file exists" trying to add a
// default route that never went away. Calling this unconditionally in DEL,
// ahead of hostDevice DEL, makes cleanup reliable regardless of whether the
// move-triggered flush fires.
func flushGuestNetnsConfig(netnsPath, ifName string) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			return nil // interface not present — nothing to flush
		}

		for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
			routes, err := handle.RouteList(link, family)
			if err != nil {
				return fmt.Errorf("list routes on %q: %w", ifName, err)
			}
			for _, route := range routes {
				if !isDefaultRouteDst(route.Dst) {
					continue
				}
				if err := handle.RouteDel(&route); err != nil {
					return fmt.Errorf("delete default route on %q: %w", ifName, err)
				}
			}

			addrs, err := handle.AddrList(link, family)
			if err != nil {
				return fmt.Errorf("list addresses on %q: %w", ifName, err)
			}
			for _, addr := range addrs {
				if addr.IP.IsLinkLocalUnicast() {
					continue
				}
				if err := handle.AddrDel(link, &addr); err != nil {
					return fmt.Errorf("delete address %s on %q: %w", addr.IPNet, ifName, err)
				}
			}
		}

		slog.Debug("netns: flushed guest interface addresses/routes", "ifName", ifName, "netns", netnsPath)
		return nil
	})
}

// readGuestInterface reads the MAC and MTU of the guest veth endpoint
// inside the container network namespace.
func readGuestInterface(netnsPath, ifName string) (string, int, error) {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return "", 0, fmt.Errorf("open container netns %s: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	var mac string
	var mtu int
	err = containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find interface %s: %w", ifName, err)
		}
		attrs := link.Attrs()
		mac = attrs.HardwareAddr.String()
		mtu = attrs.MTU
		return nil
	})
	return mac, mtu, err
}

// cleanupContainerNetns removes any existing veth interface with the given name
// from the container network namespace. This is needed to handle stale state
// from previous CNI ADD runs that may have left interfaces behind.
//
// Only *netlink.Veth interfaces are deleted; other types produce a clear error
// to prevent accidental deletion of unrelated interfaces.
func cleanupContainerNetns(netnsPath, ifName string) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			// Interface does not exist in container netns — nothing to clean up.
			return nil
		}
		if _, ok := link.(*netlink.Veth); !ok {
			return fmt.Errorf("interface %q is not a veth (type: %T), refusing to delete", ifName, link)
		}
		if err := handle.LinkDel(link); err != nil {
			return fmt.Errorf("delete stale interface %q in container netns: %w", ifName, err)
		}
		slog.Warn("netns: removed stale interface left behind by a previous ADD attempt",
			"ifName", ifName, "netns", netnsPath)
		return nil
	})
}
