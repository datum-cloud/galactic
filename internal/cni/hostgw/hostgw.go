// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostgw configures the host-side gateway address and VRF-table
// pod-subnet route for a VPC attachment's allocated IPAM addresses.
//
// This is kernel-interface work (netlink address/route/neighbor
// manipulation on the interface a master plugin — galactic-cni,
// galactic-tap-cni — itself created), not BGP/SRv6/eBPF publish, so it
// lives here rather than in internal/cnibgp: once galactic-bgp became its
// own chain-invoked plugin (a separate process, invoked after the master
// has already printed its own result), it no longer has any interface to
// configure — "zero kernel-interface dependency" is the whole reason that
// split was worth doing in the first place. Both master plugins call this
// directly, before building their own CNI result; galactic-bgp reads
// whatever addresses ended up in prevResult and never touches the kernel
// interface at all.
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

// ConfigureHostGateway assigns each configured family's gateway address as a
// host address (/128 for IPv6, /32 for IPv4 on veth) on the host-side
// interface (veth or tap) and installs an explicit pod-subnet route for that
// family into the VRF table. IPv4 is skipped entirely when the attachment is
// IPv6-only.
//
// Using a full-length host address (not the pod subnet mask) prevents the
// kernel from auto-creating a subnet-router anycast entry in the VRF local
// table. When the pod address equals the subnet network address the anycast
// absorbs seg6local-decapped inner packets before they reach the guest
// interface. The explicit subnet route replaces the one the kernel would
// have created from the wider mask.
//
// For tap interfaces, the IPv4 gateway is instead assigned as a /25 so the
// address reported on the interface reflects a real subnet (VM guests expect
// this). That reintroduces the wider-mask hazard described above, so the
// address is added with IFA_F_NOPREFIXROUTE: the kernel skips auto-creating
// the connected /25 route entirely, leaving the explicit pod-subnet route
// below as the only thing that governs delivery to this VM's address.
//
// guestHWAddr is the guest-side veth's MAC address, used to prime a
// permanent neighbor table entry for the pod's own address (see
// installGatewayNeighbor). It is nil for tap attachments, which have no
// separate guest-side link in this netns to resolve a MAC from.
func ConfigureHostGateway(vpc, vpcAttachment string, res *cniipam.IPAMResult, guestHWAddr net.HardwareAddr) error {
	if res == nil {
		return nil
	}
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	tableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return fmt.Errorf("get VRF table ID for pod subnet route: %w", err)
	}

	if res.IPv6Gateway != nil {
		gwNet := &net.IPNet{IP: res.IPv6Gateway, Mask: net.CIDRMask(128, 128)}
		if err := installGatewayRoute(hostLink, gwNet, res.IPv6Subnet, netlink.FAMILY_V6, int(tableID), 0); err != nil {
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
		ipv4Subnet := &net.IPNet{IP: res.IPv4Address, Mask: net.CIDRMask(32, 32)}
		if err := installGatewayRoute(hostLink, gwNet, ipv4Subnet, netlink.FAMILY_V4, int(tableID), addrFlags); err != nil {
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

// installGatewayNeighbor installs a permanent neighbor table entry mapping
// podIP to guestHWAddr on hostLink.
//
// The eBPF uSID ingress datapath (internal/plumbing/ebpf/prog/usid.c)
// decapsulates SRv6 traffic and calls bpf_fib_lookup() to resolve the
// egress path for the inner packet, then redirects it straight to the
// resolved neighbor — entirely in-kernel, never touching the normal
// forwarding stack. bpf_fib_lookup() does not itself trigger ARP/NDP
// resolution the way ordinary kernel packet forwarding does, so without a
// pre-existing neighbor table entry it fails with BPF_FIB_LKUP_RET_NO_NEIGH
// and the datapath drops the packet. A permanent entry (installed once, at
// CNI ADD, using the guest veth's own known MAC) means this resolution
// never depends on dynamic ARP/NDP at all.
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

// ipv4GatewayAddrParams returns the IPv4 gateway mask and netlink address
// flags to use for hostLink. Tap interfaces get a /25 (so the address
// reported on the interface reflects a real subnet) with
// IFA_F_NOPREFIXROUTE, which stops the kernel from auto-creating a connected
// route for the wider mask. Veth interfaces keep the plain /32 host address
// with no flags.
func ipv4GatewayAddrParams(hostLink netlink.Link) (net.IPMask, int) {
	if _, isTap := hostLink.(*netlink.Tuntap); isTap {
		return net.CIDRMask(25, 32), unix.IFA_F_NOPREFIXROUTE
	}
	return net.CIDRMask(32, 32), 0
}

// installGatewayRoute assigns gwNet as a host address on hostLink and
// installs an explicit route to subnet into the given VRF table, for one
// address family. Idempotent: existing matching routes/addresses are left
// alone, and conflicting ones return an error rather than being overwritten.
func installGatewayRoute(hostLink netlink.Link, gwNet, subnet *net.IPNet, family, tableID, addrFlags int) error {
	hostName := hostLink.Attrs().Name
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: gwNet, Flags: addrFlags}); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("add gateway address %s to host interface %q: %w", gwNet, hostName, err)
		}
	}

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

// routeConflicts reports whether an existing route conflicts with the desired
// pod-subnet route. A conflict occurs when the destination matches but the
// gateway or link index differs.
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
