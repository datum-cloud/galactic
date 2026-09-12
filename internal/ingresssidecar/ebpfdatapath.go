// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// ebpfPinDir is the bpffs directory this file's registrations read from and
// attach against. A package var so tests can override it. In production it is
// attach.PinDir: this sidecar mounts the same host /sys/fs/bpf that the CNI
// control daemon pins usid_egress and its maps under, so these are the same
// kernel objects, not a private second copy.
var ebpfPinDir = attach.PinDir

// ingressSidecarBlock is the fixed, synthetic uSID Block this file registers
// every vrf_table and ifindex_vrf_table entry under, standing in for the real
// locator-derived Block a genuine tenant CNI attachment uses.
//
// A synthetic value is correct here because vrf_table's key is consulted by
// usid_egress purely as a local lookup into this node's own map. It is never
// put on the wire and never interpreted by another node, unlike the Block a
// real SID's outer header carries. These entries only need to avoid colliding
// with any (block, argument) pair the CNI path might register for a tenant VPC
// on this same node, and to stay consistent between this file's own two map
// writes.
//
// uformat.BlockMax buys the first: as a prefix it is ffff:ffff:ffff::/48, which
// no operator would assign as a real locator, so these entries sit in a corner
// of the keyspace no CNI attachment can reach whatever argument it was
// allocated. One reserved Block with per-VPC disambiguation left to argument is
// simpler than deriving a Block per VPC and no less collision-safe, since the
// whole Block is already carved out.
//
// This sidecar has no BGP runtime and no per-node identity, so it cannot read a
// real locator the way the CNI path does.
const ingressSidecarBlock = uformat.BlockMax

// argumentForTableID derives the uSID Argument for a VPC's VRF from its Linux
// routing table ID rather than allocating a separate value. The table ID is
// already unique per VPC on this node, which is the only property Argument
// needs here, so reusing it avoids a second allocator.
//
// Fails if tableID does not fit Argument's 12-bit range. Table IDs are
// allocated from 1 upward, so this needs about 4095 live VPCs on one node, but
// a silently aliased Argument would be a cross-VPC datapath bug rather than a
// safe fallback.
func argumentForTableID(tableID uint32) (uint16, error) {
	if tableID < uint32(uformat.ArgumentMin) || tableID > uint32(uformat.ArgumentMax) {
		return 0, fmt.Errorf(
			"ingresssidecar: VRF table id %d does not fit uSID Argument's range [%#x,%#x]",
			tableID, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	return uint16(tableID), nil
}

// vrfLinkForTable returns the kernel VRF link whose routing table is tableID,
// the interface EnsureVRF already created. Found by table ID rather than by
// name because this file's callers carry only a tableID forward, not the vpc
// string it came from.
func vrfLinkForTable(tableID uint32) (*netlink.Vrf, error) {
	links, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF interfaces: %w", err)
	}
	for _, link := range links {
		if link.Table == tableID {
			return link, nil
		}
	}
	return nil, fmt.Errorf("no VRF interface found for table %d", tableID)
}

// egressVethNames derives a VPC's veth pair names from tableID alone, since the
// callers carry only a tableID forward. Collision-free because table IDs are
// already unique per VPC on this node, and comfortably inside IFNAMSIZ, since a
// table ID that fits Argument's 12-bit range is at most 4 decimal digits.
func egressVethNames(tableID uint32) (inner, peer string) {
	return fmt.Sprintf("ivs%d", tableID), fmt.Sprintf("ivp%d", tableID)
}

// ensureEgressVeth creates, or finds, the interface pair usid_egress
// intercepts this VPC's traffic on. inner is enslaved into vrfLink with a
// default route in that VRF's table pointed at it, so every destination
// egress_route_table might match has somewhere real to go once the kernel
// redoes its route lookup inside the VRF. peer stays outside the VRF, in the
// pod's main namespace, and is where usid_egress actually attaches.
//
// Idempotent: an existing name counts as already done, and the route is
// replaced rather than added, so it is safe on every call that ensures a
// VRF.
func ensureEgressVeth(vrfLink *netlink.Vrf, inner, peer string) (netlink.Link, error) {
	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("look up veth peer %q: %w", peer, err)
		}
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: inner},
			PeerName:  peer,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return nil, fmt.Errorf("add veth pair %q/%q: %w", inner, peer, err)
		}
		peerLink, err = netlink.LinkByName(peer)
		if err != nil {
			return nil, fmt.Errorf("look up newly-created veth peer %q: %w", peer, err)
		}
	}

	innerLink, err := netlink.LinkByName(inner)
	if err != nil {
		return nil, fmt.Errorf("look up veth inner end %q: %w", inner, err)
	}
	if err := netlink.LinkSetMaster(innerLink, vrfLink); err != nil {
		return nil, fmt.Errorf("enslave %q into VRF %q: %w", inner, vrfLink.Attrs().Name, err)
	}
	if err := netlink.LinkSetUp(innerLink); err != nil {
		return nil, fmt.Errorf("set %q up: %w", inner, err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		return nil, fmt.Errorf("set %q up: %w", peer, err)
	}

	// The inner hop the kernel takes once a packet enters this VRF: a route in
	// the VRF's own table, which otherwise has no route anywhere.
	//
	// Routed via the peer's link-local address rather than as a bare on-link
	// route. An on-link default makes the kernel resolve a neighbor for the
	// packet's final destination before it ever reaches usid_egress, and
	// nothing answers for a destination egress_route_table is about to
	// rewrite, so the kernel gives up and the packet never reaches the qdisc.
	// A gateway route means only one neighbor is ever resolved, the peer,
	// which is always present and always answers, whatever the destination.
	peerLinkLocal, err := waitForLinkLocalAddr(peerLink)
	if err != nil {
		return nil, fmt.Errorf("wait for veth peer %q's own link-local address: %w", peer, err)
	}
	defaultRoute := &netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Table:     int(vrfLink.Table),
		LinkIndex: innerLink.Attrs().Index,
		Gw:        peerLinkLocal,
	}
	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return nil, fmt.Errorf("install default route in VRF table %d via %q: %w", vrfLink.Table, inner, err)
	}

	return peerLink, nil
}

// waitForLinkLocalAddr returns link's kernel-assigned link-local IPv6 address,
// polling briefly because that assignment happens asynchronously to LinkSetUp
// returning. The address is normally present on the first poll, so the bound is
// headroom rather than an expected wait.
func waitForLinkLocalAddr(link netlink.Link) (net.IP, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return nil, fmt.Errorf("list addresses on %q: %w", link.Attrs().Name, err)
		}
		for _, a := range addrs {
			if a.IP.IsLinkLocalUnicast() {
				return a.IP, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%q never acquired a link-local address", link.Attrs().Name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ensureNodeSourceAddress registers this node's underlay-facing SRv6 source
// address into node_src_addr_table. Idempotent and cheap, so it is safe on
// every call.
//
// It prefers a resolver configured through SetNodeSourceAddressResolver over
// local auto-detection, which in this sidecar resolves to the pod's own overlay
// address rather than the node's real one.
func ensureNodeSourceAddress() error {
	var (
		addr net.IP
		err  error
	)
	if resolver := getNodeSourceAddressResolver(); resolver != nil {
		addr, err = resolver.ResolveNodeSourceAddress()
	} else {
		addr, err = srv6.ResolveNodeSourceAddress()
	}
	if err != nil {
		return fmt.Errorf("resolve node source address: %w", err)
	}
	nodeSrc, closer, err := egressroutemap.OpenPinnedNodeSourceAddress(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned node_src_addr_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return nodeSrc.Set(addr)
}

// ensureEgressDatapath makes usid_egress's VRF resolution, from
// ifindex_vrf_table through vrf_table to a Linux VRF table ID, resolve for
// vpc's VRF, then attaches usid_egress where it intercepts that VRF's traffic.
// Without it, EnsureRoute's egress_route_table entries have nothing attached in
// this pod's namespace to read them.
//
// The attachment goes on the peer end's ingress hook, not the VRF device's
// egress hook. A VRF master device's TC egress hook never fires for traffic
// routed through it, however correctly the maps are populated. The CNI path has
// the same shape for a real tenant: it attaches to a veth's ingress hook from
// the host side, because that is where the tenant's egress traffic arrives.
// ensureEgressVeth supplies the equivalent veth here.
//
// Attaching to the pod's shared eth0 instead does not work either: eth0 is
// shared by every VPC this sidecar serves, and ifindex_vrf_table holds one
// (block, argument) per ifindex, so a single registration could resolve at most
// one VPC.
//
// tableID is the VPC's Linux routing table. vpc is used to derive that VPC's
// return-path gateway address when one is configured.
//
// Idempotent: every step is a replace, so a repeat call for an
// already-provisioned VPC is in effect a no-op.
func ensureEgressDatapath(vpc string, tableID uint32) error {
	// node_src_addr_table is a per-node singleton, not per-VPC. usid_egress
	// fails open, uncounted, on every encapsulation attempt until something
	// sets it, and the CNI path only registers it as a side effect of a real
	// tenant ADD landing on this node, which a node running only this
	// sidecar's synthetic attachments never sees. An otherwise correct
	// attachment then produces no encapsulated traffic at all.
	//
	// Non-fatal, as at the CNI call site and for the same reason: resolving
	// the address needs a converged underlay default route, which this pod can
	// transiently lack right after a restart.
	if err := ensureNodeSourceAddress(); err != nil {
		slog.Warn("ensureEgressDatapath: could not register this node's own SRv6 source address; "+
			"egress routing will fail open until this succeeds", "err", err)
	}

	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}

	vrfLink, err := vrfLinkForTable(tableID)
	if err != nil {
		return err
	}

	inner, peer := egressVethNames(tableID)
	peerLink, err := ensureEgressVeth(vrfLink, inner, peer)
	if err != nil {
		return fmt.Errorf("ensure egress veth for VRF table %d: %w", tableID, err)
	}

	// Assign this VPC's return-path gateway address, when one is configured,
	// to the VRF-slave veth enslaved above. Non-fatal, like
	// ensureNodeSourceAddress: a missing gateway address degrades the return
	// path without making the forward path any worse.
	if err := ensureGatewayAddress(vpc, inner); err != nil {
		slog.Warn("ensureEgressDatapath: could not assign this VPC's own gateway address", "vpc", vpc, "err", err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF vrf_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	// EgressKindVeth is a don't-care here, not a claim about this device's link
	// type. EgressKind steers only usid_ingress's redirect, and usid_ingress is
	// never attached in this pod's namespace, since this sidecar has no decap
	// side. usid_egress never reads it.
	if err := registry.VRF.Register(ingressSidecarBlock, argument, tableID, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}

	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = ifindexCloser.Close() }()

	// Keyed by the veth peer's ifindex, not the VRF's, because usid_egress has
	// to see this traffic arrive on that interface's ingress hook.
	if err := ifindexTable.Register(uint32(peerLink.Attrs().Index), ingressSidecarBlock, argument); err != nil {
		return fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}

	program, err := ebpf.LoadPinnedProgram(filepath.Join(ebpfPinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	if err := attach.AttachEgress(program, peerLink.Attrs().Name); err != nil {
		return fmt.Errorf("attach usid_egress to VRF %d's veth peer %q: %w", tableID, peerLink.Attrs().Name, err)
	}
	return nil
}

// removeEgressDatapath undoes ensureEgressDatapath's registrations for the VPC
// whose VRF table is tableID. It runs before RemoveVRF deletes the VRF
// interface, while the veth names can still be derived.
//
// Best-effort and idempotent: every step is attempted even if an earlier one
// failed, and the failures are joined and returned together rather than the
// first one aborting cleanup.
//
// usid_egress needs no explicit detach. Deleting the veth pair removes both
// ends and every qdisc and filter on them.
func removeEgressDatapath(tableID uint32) error {
	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}

	inner, peer := egressVethNames(tableID)
	var errs []error

	if peerLink, lerr := netlink.LinkByName(peer); lerr != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(lerr, &notFound) {
			errs = append(errs, fmt.Errorf("look up veth peer %q: %w", peer, lerr))
		}
		// Absent is not an error (idempotent teardown) -- nothing more to
		// unregister or delete for it below.
	} else {
		if ifindexTable, closer, oerr := ifindexvrfmap.OpenPinned(ebpfPinDir); oerr != nil {
			errs = append(errs, fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", oerr))
		} else {
			if err := ifindexTable.Unregister(uint32(peerLink.Attrs().Index)); err != nil {
				errs = append(errs, fmt.Errorf("unregister eBPF ifindex_vrf_table entry: %w", err))
			}
			_ = closer.Close()
		}
		if err := netlink.LinkDel(peerLink); err != nil {
			errs = append(errs, fmt.Errorf("delete veth pair %q/%q: %w", inner, peer, err))
		}
	}

	if registry, closer, oerr := usidmap.OpenPinnedRegistry(ebpfPinDir); oerr != nil {
		errs = append(errs, fmt.Errorf("open pinned eBPF vrf_table: %w", oerr))
	} else {
		if err := registry.VRF.Unregister(ingressSidecarBlock, argument); err != nil {
			errs = append(errs, fmt.Errorf("unregister eBPF vrf_table entry: %w", err))
		}
		_ = closer.Close()
	}

	return errors.Join(errs...)
}

// ensureRedirectRoute installs a plain host route for prefix into this pod's
// main routing table, out the VRF interface for tableID as a bare nexthop
// device. A VRF master device needs no gateway address: naming it as the link
// re-dispatches the packet through that device, which is where usid_egress is
// attached.
//
// Nothing else pulls this pod's outbound traffic for prefix off its default
// route. Neither Envoy nor the cluster CNI knows this destination belongs to a
// VPC VRF, so an unbound socket's ordinary lookup would resolve prefix out eth0
// like any other destination. Callers always pass a /128, so this route wins
// longest-prefix match over the default without the CNI knowing anything about
// VPC address space or Envoy binding its sockets to anything.
func ensureRedirectRoute(prefix *net.IPNet, tableID uint32) error {
	link, err := vrfLinkForTable(tableID)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     unix.RT_TABLE_MAIN,
		LinkIndex: link.Attrs().Index,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("install main-table redirect route for %s via %q: %w", prefix, link.Attrs().Name, err)
	}
	return nil
}

// removeRedirectRoute removes the main-table route ensureRedirectRoute
// installed for prefix. Deleting by destination and table alone is enough to
// identify it.
//
// An absent route is the outcome a removal asks for, so ESRCH counts as
// success. Reporting failure instead retries a teardown that can never
// complete, and keeps the entry alive to collide with the next tenant given
// this address.
func removeRedirectRoute(prefix *net.IPNet) error {
	err := netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: unix.RT_TABLE_MAIN,
	})
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
