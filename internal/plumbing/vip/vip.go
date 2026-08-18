// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vip manages loopback-style VIP binding on backend nodes -- one
// half of the DSR/Maglev gateway redesign's veth/container case (design
// plan §0.1, §1): a backend node binds a service VIP to its own dedicated
// dummy interface, letting the node itself verifiably answer on that
// address (see Verify) without the reply ever passing back through
// galactic-gateway. Requires CAP_NET_ADMIN, mirroring internal/plumbing/vrf.
//
// This alone does not deliver anything to a VRF-isolated backend pod,
// though: the dummy interface lives in the node's root network namespace,
// not enslaved to any tenant VRF, and a DSR-forwarded ingress packet is
// decapsulated straight into the owning tenant's own VRF routing table --
// which has no route to an address that only exists outside it. The other
// half, internal/plumbing/ebpf/vipxlatmap's vip_xlat_table translation
// (originally built for the tap case only), now also runs for veth for
// exactly this reason -- see
// internal/controller.ServiceVIPBindingReconciler's own doc comment for
// the live containerlab finding that surfaced this gap.
package vip

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// InterfaceName is the dedicated dummy link this package owns exclusively
// for VIP addresses — not lo, since lo already carries the SRv6 locator
// address internal/plumbing/loaddr.Detect reads; mixing VIP churn onto that
// same interface risks disturbing the one address the fabric underlay
// depends on.
const InterfaceName = "galactic-vip0"

// vipMu serializes Bind/Unbind within a single process, mirroring
// internal/plumbing/vrf's identical vrfMu — this package has no
// cross-process lock file of its own because, unlike VRF creation (raced by
// separate CNI plugin processes), every caller of this package runs inside
// one long-lived galactic-router process.
var vipMu sync.Mutex

// Bind idempotently assigns addr to InterfaceName, creating the interface
// first if this is the first VIP ever bound on this node. Safe to call
// repeatedly for the same address.
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

// Verify confirms addr is actually live: present in InterfaceName's address
// list AND resolvable as a local (RTN_LOCAL) route via the kernel's own
// route table -- not just "AddrAdd returned nil" (an address the kernel
// duplicate-address-detection has since removed, for example, would still
// have been accepted by AddrAdd at the time). Verify does not attempt to
// contact any application-level listener on addr:port -- whether something
// is actually listening on it is the workload's concern, not this
// package's.
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

// ensureInterface returns InterfaceName, creating it as a dummy link (and
// bringing it up) the first time this is called on a node -- idempotent by
// name, mirroring internal/plumbing/vrf.Add's identical
// LinkByName-then-LinkAdd pattern.
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

// hostNet returns addr expressed as its own host route (a /32 for IPv4, a
// /128 for IPv6) -- the mask AddrAdd/AddrDel need to bind a single VIP
// without claiming a whole subnet on InterfaceName.
func hostNet(addr net.IP) *net.IPNet {
	if v4 := addr.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: addr.To16(), Mask: net.CIDRMask(128, 128)}
}
