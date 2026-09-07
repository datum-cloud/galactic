// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostgw configures the host-side gateway address and the VRF-table
// pod-subnet route for a VPC attachment's allocated addresses.
//
// This is kernel-interface work on the interface a master plugin created, not
// BGP or eBPF publishing, so it lives here rather than in the BGP plugin. That
// plugin is a separate process invoked after the master has printed its result,
// and having no interface to configure is the whole point of the split. Both
// master plugins call this directly before building their result; the BGP
// plugin reads whatever addresses ended up in the previous result and never
// touches the interface.
package hostgw

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// ConfigureHostGateway assigns each configured family's gateway address on this
// attachment's host-side interface and installs an explicit pod-subnet route
// for that family into the VPC's shared VRF table. IPv4 is skipped entirely on
// an IPv6-only attachment.
//
// The gateway address stays on the attachment's own link rather than the shared
// VRF device. IPv6 neighbor resolution for an address only works on links that
// address is configured on, or that carry an explicit proxy entry: unlike
// IPv4's proxy ARP, enabling proxy NDP does not make the kernel answer for an
// address it can merely route to through another interface. A VRF master and
// its enslaved links are separate segments to NDP, so an address bound only to
// the VRF device is invisible to solicitations arriving on any attachment's own
// link, and every guest's default-route resolution fails. Each attachment has
// its own gateway address from its own subnet anyway, so nothing is duplicated
// by keeping it per attachment.
//
// A full-length gateway address, rather than the pod subnet mask, keeps the
// kernel from auto-creating a subnet-router anycast entry in the VRF's local
// table. Where the pod address equals the subnet's network address, that
// anycast absorbs decapsulated inner packets before they reach the guest. The
// explicit subnet route replaces the connected route the wider mask would have
// produced.
//
// A tap interface instead gets its IPv4 gateway as a /25, so the address on the
// interface reflects a real subnet as VM guests expect. That reintroduces the
// wider-mask hazard, so the address is added with the no-prefix-route flag: the
// kernel skips the connected route entirely, leaving the explicit pod-subnet
// route as the only thing governing delivery.
//
// guestHWAddr is the guest-side veth's MAC, used to prime a permanent neighbor
// entry for the pod's address. It is nil for a tap, which has no guest-side
// link in this namespace to read a MAC from.
func ConfigureHostGateway(vpc, vpcAttachment string, res *cniipam.IPAMResult, guestHWAddr net.HardwareAddr) error {
	if res == nil {
		return nil
	}
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		return fmt.Errorf("get VRF table ID for pod subnet route: %w", err)
	}

	if res.IPv6Gateway != nil {
		gwNet := &net.IPNet{IP: res.IPv6Gateway, Mask: net.CIDRMask(128, 128)}
		if err := installGatewayAddress(hostLink, gwNet, 0); err != nil {
			return err
		}
		if err := installPodSubnetRoute(hostLink, res.IPv6Subnet, netlink.FAMILY_V6, int(tableID)); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.IPv6Subnet.IP, netlink.FAMILY_V6, guestHWAddr); err != nil {
				return err
			}
		}
	}
	if res.IPv4Gateway != nil {
		ipv4Mask, addrFlags := ipv4GatewayAddrParams(hostLink)
		gwNet := &net.IPNet{IP: res.IPv4Gateway, Mask: ipv4Mask}
		if err := installGatewayAddress(hostLink, gwNet, addrFlags); err != nil {
			return err
		}
		ipv4Subnet := &net.IPNet{IP: res.IPv4Address, Mask: net.CIDRMask(32, 32)}
		if err := installPodSubnetRoute(hostLink, ipv4Subnet, netlink.FAMILY_V4, int(tableID)); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.IPv4Address, netlink.FAMILY_V4, guestHWAddr); err != nil {
				return err
			}
		}
	}
	return nil
}

// installGatewayNeighbor installs a permanent neighbor entry mapping podIP to
// guestHWAddr on hostLink for the given family.
//
// The uSID ingress datapath decapsulates traffic, resolves the inner packet's
// egress with bpf_fib_lookup, and redirects straight to the resolved neighbor,
// never touching the normal forwarding stack. That lookup does not trigger
// neighbor resolution the way ordinary forwarding does, so without an existing
// entry it fails and the datapath drops the packet. A permanent entry installed
// once at CNI ADD, from the guest veth's known MAC, removes that dependency
// entirely.
func installGatewayNeighbor(hostLink netlink.Link, podIP net.IP, family int, guestHWAddr net.HardwareAddr) error {
	neigh := &netlink.Neigh{
		LinkIndex:    hostLink.Attrs().Index,
		Family:       family,
		State:        netlink.NUD_PERMANENT,
		IP:           podIP,
		HardwareAddr: guestHWAddr,
	}
	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("add permanent neighbor %s -> %s on host interface %q: %w",
			podIP, guestHWAddr, hostLink.Attrs().Name, err)
	}
	return nil
}

// ipv4GatewayAddrParams returns the IPv4 gateway mask and address flags for
// hostLink. A tap gets a /25, so the address reflects a real subnet, with the
// no-prefix-route flag stopping the kernel creating a connected route for that
// wider mask. A veth keeps a plain host address with no flags.
func ipv4GatewayAddrParams(hostLink netlink.Link) (net.IPMask, int) {
	if _, isTap := hostLink.(*netlink.Tuntap); isTap {
		return net.CIDRMask(25, 32), unix.IFA_F_NOPREFIXROUTE
	}
	return net.CIDRMask(32, 32), 0
}

// installGatewayAddress assigns gwNet on hostLink with addrFlags. Idempotent:
// an identical address already installed by a prior attempt is not an error.
func installGatewayAddress(hostLink netlink.Link, gwNet *net.IPNet, addrFlags int) error {
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: gwNet, Flags: addrFlags}); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("add gateway address %s to host interface %q: %w", gwNet, hostLink.Attrs().Name, err)
		}
	}
	return nil
}

// installPodSubnetRoute installs an explicit route to subnet in the given VRF
// table, pointing at hostLink, for one address family. Idempotent: a matching
// route is left alone, and a conflicting one is an error rather than being
// overwritten.
func installPodSubnetRoute(hostLink netlink.Link, subnet *net.IPNet, family, tableID int) error {
	desiredRoute := &netlink.Route{
		Dst:       subnet,
		LinkIndex: hostLink.Attrs().Index,
		Table:     tableID,
	}

	existingRoutes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: tableID},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return fmt.Errorf("list routes in VRF table: %w", err)
	}
	for _, r := range existingRoutes {
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() != desiredRoute.Dst.String() {
			continue
		}
		if routeConflicts(&r, desiredRoute) {
			return fmt.Errorf(
				"existing route %v to %s conflicts with desired route %v",
				r, desiredRoute.Dst, desiredRoute,
			)
		}
		return nil
	}

	if err := netlink.RouteAdd(desiredRoute); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil
		}
		return fmt.Errorf("add pod subnet route to VRF table: %w", err)
	}
	return nil
}

// routeConflicts reports whether existing conflicts with the desired
// pod-subnet route: the destination matches but the gateway or link differs.
func routeConflicts(existing, desired *netlink.Route) bool {
	if existing.Dst == nil || desired.Dst == nil {
		return false
	}
	if existing.Dst.String() != desired.Dst.String() {
		return false
	}
	if (existing.Gw != nil) != (desired.Gw != nil) {
		return true
	}
	if existing.Gw != nil && !existing.Gw.Equal(desired.Gw) {
		return true
	}
	if existing.LinkIndex != 0 && desired.LinkIndex != 0 && existing.LinkIndex != desired.LinkIndex {
		return true
	}
	return false
}
