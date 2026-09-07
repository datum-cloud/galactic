// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vip manages loopback-style VIP binding on backend nodes: a node binds
// a service VIP to its own dummy interface, letting the node verifiably answer
// on that address without the reply passing back through the gateway. Requires
// CAP_NET_ADMIN.
//
// This alone delivers nothing to a VRF-isolated backend pod. The dummy interface
// lives in the node's root namespace, enslaved to no tenant VRF, while a
// forwarded ingress packet is decapsulated straight into the owning tenant's VRF
// table, which has no route to an address existing only outside it. The address
// translation in the eBPF map layer covers that half.
package vip

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// InterfaceName is the dummy link this package owns exclusively for VIP
// addresses. Not loopback, which already carries the SRv6 locator address the
// underlay depends on: mixing VIP churn onto it risks disturbing that.
const InterfaceName = "galactic-vip0"

// vipMu serializes Bind and Unbind within one process. There is no
// cross-process lock here because, unlike VRF creation, every caller runs inside
// one long-lived process.
var vipMu sync.Mutex

// Bind idempotently assigns addr to InterfaceName, creating the interface if
// this is the first VIP bound on this node. Safe to call repeatedly for the same
// address.
func Bind(addr net.IP) error {
	vipMu.Lock()
	defer vipMu.Unlock()

	link, err := ensureInterface()
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: hostNet(addr)}); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("bind VIP %s to %s: %w", addr, InterfaceName, err)
	}
	return nil
}

// Unbind idempotently removes addr from InterfaceName. No-op (not an error)
// if the interface or the address is already absent.
func Unbind(addr net.IP) error {
	vipMu.Lock()
	defer vipMu.Unlock()

	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return nil // interface never existed -- nothing to unbind
	}

	if err := netlink.AddrDel(link, &netlink.Addr{IPNet: hostNet(addr)}); err != nil {
		if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ESRCH) {
			return nil // already absent -- idempotent
		}
		return fmt.Errorf("unbind VIP %s from %s: %w", addr, InterfaceName, err)
	}
	return nil
}

// Verify confirms addr is live: present in the interface's address list and
// resolvable as a local route in the kernel's own table. That is more than the
// add having returned successfully, since an address duplicate-address detection
// has since removed would still have been accepted at the time.
//
// It does not contact any listener on the address: whether something is
// listening is the workload's concern.
func Verify(addr net.IP) error {
	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return fmt.Errorf("vip: %s does not exist: %w", InterfaceName, err)
	}

	family := unix.AF_INET6
	if addr.To4() != nil {
		family = unix.AF_INET
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return fmt.Errorf("vip: list addresses on %s: %w", InterfaceName, err)
	}
	found := false
	for _, a := range addrs {
		if a.IP.Equal(addr) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("vip: %s is not present on %s", addr, InterfaceName)
	}

	routes, err := netlink.RouteGet(addr)
	if err != nil {
		return fmt.Errorf("vip: route lookup for %s: %w", addr, err)
	}
	for _, r := range routes {
		if r.Type == unix.RTN_LOCAL {
			return nil
		}
	}
	return fmt.Errorf("vip: %s is not resolvable as a local route", addr)
}

// ensureInterface returns InterfaceName, creating it as a dummy link and
// bringing it up the first time this is called on a node. Idempotent by name.
func ensureInterface() (netlink.Link, error) {
	if link, err := netlink.LinkByName(InterfaceName); err == nil {
		return link, nil
	}

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: InterfaceName}}
	if err := netlink.LinkAdd(dummy); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("create %s: %w", InterfaceName, err)
	}

	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("find %s after create: %w", InterfaceName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("bring up %s: %w", InterfaceName, err)
	}
	return link, nil
}

// hostNet returns addr as its own host route, the mask needed to bind a single
// VIP without claiming a whole subnet on the interface.
func hostNet(addr net.IP) *net.IPNet {
	if v4 := addr.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: addr.To16(), Mask: net.CIDRMask(128, 128)}
}
