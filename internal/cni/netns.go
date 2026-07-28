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
// use for this attachment).
func addAddrAndDefaultRoute(
	handle *netlink.Handle, link netlink.Link, ifName string, ipNet *net.IPNet, gateway net.IP,
) error {
	if ipNet == nil {
		return nil
	}

	if err := handle.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("add IP %s to %q: %w", ipNet, ifName, err)
	}

	if gateway == nil {
		return nil
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
