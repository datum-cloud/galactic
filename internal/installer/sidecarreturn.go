// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// The ingress sidecar's return path, host side.
//
// internal/ingresssidecar gives an Envoy pod one Linux VRF per tenant VPC
// inside its own netns, and advertises a per-VPC gateway address into EVPN so a
// backend's reply has an SRv6 route to follow. A remote node encapsulates that
// reply toward this node's SID for the advertised Argument.
//
// The receiving half cannot live in the sidecar. usid_ingress runs in the host
// netns, while the sidecar's VRFs, routing tables, and veth pairs are in the
// pod's, and a container there cannot install host-netns routes. The sidecar
// also registers only what usid_egress reads, under a synthetic Block
// usid_ingress never matches.
//
// This side reads annotations rather than going to look, for the mirror-image
// reason. Pointing a reply at the right pod needs that pod's host-side veth and
// MAC, and reading those from here means entering its namespace, which needs
// CAP_SYS_ADMIN. This container drops ALL and adds only BPF, NET_ADMIN, and
// NET_RAW. The sidecar reads both from inside with no privilege and publishes
// them on the advertisement it already writes.
//
// Per advertised gateway address, a decapsulated reply needs:
//
//  1. locator_table and function_table entries for this node's Block and
//     Node-ID, so usid_ingress claims the packet rather than passing it to a
//     stack with no tunnel device to hand it to. A node hosting only sidecars
//     has no CNI attachment, so nothing else writes these.
//  2. A vrf_table entry under this node's real Block, keyed on the Argument the
//     advertisement was published with, pointing at a routing table this file
//     owns, with EgressKindVeth so the redirect crosses into the pod's netns.
//  3. In that table, a route for the gateway address out the host side of the
//     pod's veth, so bpf_fib_lookup resolves to an interface
//     bpf_redirect_peer can cross.
//  4. A permanent neighbor for that address on the same interface, because
//     bpf_fib_lookup does not trigger NDP and an unresolved neighbor is a
//     silent drop.
//
// The Argument is the subtlety worth stating, because getting it wrong is
// invisible. The sidecar keys its own vrf_table registrations on its pod-netns
// table ID, while the advertisement, and so the SID a remote node encapsulates
// toward, carries the BGPVRFInstance VRFID. Those are different numbers for the
// same VPC. This file keys on the advertised VRFID, which is what arrives on
// the wire.

const (
	// sidecarReturnTableBase and sidecarReturnTableMax bound the Linux routing
	// table IDs this file allocates from. A dedicated range matters twice:
	// tenant VRF table IDs are handed out from 1 upward, so anything low would
	// eventually collide, and pruning deletes whole tables, which must never
	// reach one this file did not create.
	//
	// Sized to hold one table per Argument, the most sidecar VRFs a node can
	// have.
	sidecarReturnTableBase = 0xF000
	sidecarReturnTableMax  = sidecarReturnTableBase + uformat.ArgumentMax
)

// sidecarReturnTableID maps an advertised Argument to the routing table holding
// that VPC's return route. One table per Argument, so pruning a withdrawn VPC
// cannot disturb another's route.
func sidecarReturnTableID(vrfID uint16) (uint32, error) {
	if vrfID < uformat.ArgumentMin || vrfID > uformat.ArgumentMax {
		return 0, fmt.Errorf("sidecar return path: VRFID %d outside the valid Argument range [%#x,%#x]",
			vrfID, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	return uint32(sidecarReturnTableBase) + uint32(vrfID), nil
}

// sidecarEndpoint is one gateway address this node's sidecar has advertised:
// the Argument a remote node encodes into the SID it encapsulates replies
// toward, plus where on this node that pod can be reached.
type sidecarEndpoint struct {
	advName string
	addr    netip.Addr
	vrfID   uint16
	// hostIfindex is the ifindex, in the host namespace, of the peer of the
	// pod's primary interface, which is what bpf_redirect_peer must target to
	// enter that pod. hostMAC is the pod-side end's hardware address.
	//
	// Both come from the advertisement's annotations rather than being
	// discovered here, because reading them from this side means entering the
	// pod's namespace, which needs a privilege this container does not
	// carry.
	hostIfindex int
	hostMAC     net.HardwareAddr
}

// reconcileSidecarReturnPath is Run's non-fatal wrapper. A node with no
// sidecar, a not-yet-created BGPRouter, or a transient API error must never
// stop the installer daemon, and the caller's ticker retries.
func reconcileSidecarReturnPath(ctx context.Context, st ebpfDatapathState) {
	if st.k8sClient == nil || st.nodeName == "" {
		return
	}
	if err := ensureSidecarReturnPath(ctx, st.k8sClient, st.namespace, st.nodeName); err != nil {
		slog.Warn("Could not install the ingress sidecar's return path; "+
			"replies to this node's sidecar gateway addresses will be dropped until this succeeds", "err", err)
	}
}

// ensureSidecarReturnPath brings the host side of every advertised sidecar
// gateway address on this node up to date and prunes what no longer belongs.
// Idempotent, and safe on a node with no sidecar: with no matching
// advertisement it installs nothing and only prunes.
func ensureSidecarReturnPath(ctx context.Context, k8s client.Client, namespace, nodeName string) error {
	endpoints, err := sidecarGatewayEndpoints(ctx, k8s, namespace, nodeName)
	if err != nil {
		return err
	}

	// Prune first and unconditionally: a withdrawn advertisement must stop
	// being routed here even on a node whose identity has gone away, and
	// pruning is the only step that is correct with an empty endpoint set.
	live := make(map[uint32]netip.Addr, len(endpoints))
	for _, e := range endpoints {
		if table, terr := sidecarReturnTableID(e.vrfID); terr == nil {
			live[table] = e.addr
		}
	}
	if perr := pruneSidecarReturnRoutes(live); perr != nil {
		slog.Warn("Could not prune stale sidecar return routes", "err", perr)
	}

	if len(endpoints) == 0 {
		return nil
	}

	block, nodeID, ok, err := nodeLocatorIdentity(ctx, k8s, namespace, nodeName)
	if err != nil {
		return err
	}
	if !ok {
		// No SRv6 identity for this node yet. The advertisements exist but
		// nothing can be keyed off a Block we do not have; the ticker
		// retries.
		return nil
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(attach.PinDir)
	if err != nil {
		return fmt.Errorf("open pinned uSID maps for the sidecar return path: %w", err)
	}
	defer func() { _ = closer.Close() }()

	// Per-node, not per-endpoint, and the reason a sidecar-only node needs this
	// file at all: without these, usid_ingress rejects every arriving uSID
	// packet before reaching any Argument-specific decision.
	if err := registry.Locator.Register(block, nodeID); err != nil {
		return fmt.Errorf("register locator_table entry for the sidecar return path: %w", err)
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return fmt.Errorf("register function_table entry for the sidecar return path: %w", err)
	}

	var errs []error
	for _, e := range endpoints {
		if err := installSidecarReturn(registry, block, e); err != nil {
			// Per-endpoint and never fatal to the sweep: one Envoy pod still
			// starting must not stop another VPC's return path from being
			// installed.
			errs = append(errs, fmt.Errorf("advertisement %s: %w", e.advName, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("sidecar return path: %w", errors.Join(errs...))
	}
	return nil
}

// installSidecarReturn wires up one endpoint: the route, the neighbor, and the
// vrf_table entry that together point a decapsulated reply at the pod holding
// that gateway address.
func installSidecarReturn(registry *usidmap.Registry, block uint64, e sidecarEndpoint) error {
	// The interface the annotation names must still exist. The advertisement
	// outlives any single Envoy pod, so between a pod being replaced and its
	// sidecar republishing, this names a veth that is gone. Installing against
	// a stale ifindex would put a route for a tenant address on whatever now
	// holds that index.
	if _, err := netlink.LinkByIndex(e.hostIfindex); err != nil {
		return fmt.Errorf("host-side interface %d for gateway address %s is not present: %w",
			e.hostIfindex, e.addr, err)
	}

	table, err := sidecarReturnTableID(e.vrfID)
	if err != nil {
		return err
	}

	if err := ensureSidecarReturnRoute(table, e.addr, e.hostIfindex); err != nil {
		return err
	}
	if err := ensureSidecarReturnNeighbor(e.addr, e.hostIfindex, e.hostMAC); err != nil {
		return err
	}

	// EgressKindVeth is a real claim here, not a don't-care: the interface the
	// route resolves to is one end of a veth pair whose peer is in the pod's
	// netns, so the redirect must be bpf_redirect_peer. Plain bpf_redirect
	// would hand the packet to that interface's egress in this netns and never
	// reach the sidecar.
	if err := registry.VRF.Register(block, e.vrfID, table, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register vrf_table entry (block %#x, argument %d): %w", block, e.vrfID, err)
	}
	return nil
}

// ensureSidecarReturnRoute installs the /128 device route bpf_fib_lookup
// resolves against, in this file's table for that Argument. Replaced rather
// than added, so a pod that came back on a different host-side veth is followed
// rather than duplicated.
func ensureSidecarReturnRoute(table uint32, addr netip.Addr, hostIfindex int) error {
	route := &netlink.Route{
		Dst:       &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())},
		LinkIndex: hostIfindex,
		Table:     int(table),
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("install return route %s dev %d table %d: %w", addr, hostIfindex, table, err)
	}
	return nil
}

// ensureSidecarReturnNeighbor primes the neighbor entry bpf_fib_lookup needs
// but will not resolve itself. Permanent, unlike the tap sweep's entries: the
// pod-side MAC is read authoritatively rather than solicited, so a stale entry
// is not a risk, and a replaced pod is followed on the next tick.
func ensureSidecarReturnNeighbor(addr netip.Addr, hostIfindex int, mac net.HardwareAddr) error {
	neigh := &netlink.Neigh{
		LinkIndex:    hostIfindex,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           addr.AsSlice(),
		HardwareAddr: mac,
	}
	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("add permanent neighbor %s -> %s on ifindex %d: %w", addr, mac, hostIfindex, err)
	}
	return nil
}

// pruneSidecarReturnRoutes removes every route in this file's table range that
// live does not account for, so a withdrawn VPC stops being routed into a pod
// that may since have been replaced by an unrelated one.
//
// One listing across all tables, filtered to the reserved range, rather than one
// per table: the range spans every possible Argument, so per-table would be
// thousands of netlink round trips per tick to find a handful of routes.
//
// staleSidecarReturnRoute carries the safety argument, and is a pure predicate
// so the cases it must not match can be enumerated in a test. This deletes
// routes, and a range check that drifted from the constants would delete
// someone else's.
func pruneSidecarReturnRoutes(live map[uint32]netip.Addr) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes to prune the sidecar return path: %w", err)
	}

	var errs []error
	for i := range routes {
		r := routes[i]
		if !staleSidecarReturnRoute(r, live) {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil {
			errs = append(errs, fmt.Errorf("delete stale return route %v from table %d: %w",
				r.Dst, r.Table, err))
		}
	}
	return errors.Join(errs...)
}

// staleSidecarReturnRoute reports whether r is a route this file installed for
// an endpoint live no longer accounts for.
//
// Every condition guards against deleting something else. The table range
// confines this to tables this file allocates from, and a route with no
// destination, or whose table holds an address live still wants, is left
// alone.
func staleSidecarReturnRoute(r netlink.Route, live map[uint32]netip.Addr) bool {
	if r.Table < sidecarReturnTableBase || r.Table > sidecarReturnTableMax {
		return false
	}
	if r.Dst == nil {
		return false
	}
	keep, wanted := live[uint32(r.Table)]
	if !wanted {
		return true // no live endpoint maps to this table at all
	}
	got, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		return false
	}
	return got.Unmap() != keep
}

// sidecarGatewayEndpoints returns every gateway advertisement the ingress
// sidecar on this node has published.
//
// Identified by name rather than by shape. A sidecar's advertisement is a
// single /128 with an Argument and End.DT46, which is exactly what a real CNI
// attachment publishes for a pod address, and those must not be touched here,
// since the CNI path already registers a vrf_table entry pointing at the pod's
// host-netns VRF. The name is the only discriminator that cannot confuse the
// two.
func sidecarGatewayEndpoints(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) ([]sidecarEndpoint, error) {
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advs, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements in namespace %s: %w", namespace, err)
	}

	segment := crdnames.IngressAdvertisementSegment()
	var out []sidecarEndpoint
	for i := range advs.Items {
		a := &advs.Items[i]
		if a.Spec.RouterRef.Name != nodeName {
			continue
		}
		if !isIngressAdvertisementName(a.Name, nodeName, segment) {
			continue
		}
		if a.Spec.VRFID == nil {
			continue
		}
		hostIfindex, hostMAC, ok := ingressEntryPointAnnotations(a.Annotations)
		if !ok {
			// An advertisement from a sidecar that has not recorded its entry
			// point yet. Skipped quietly rather than errored: it resolves
			// itself the next time that sidecar republishes.
			slog.Debug("Sidecar gateway advertisement carries no host-side entry point yet",
				"advertisement", a.Name)
			continue
		}
		for _, p := range a.Spec.Prefixes {
			pref, err := netip.ParsePrefix(string(p))
			if err != nil || !pref.Addr().Is6() || pref.Bits() != pref.Addr().BitLen() {
				// A gateway address is always a single host route. Anything
				// else is not something this return path can point at a
				// pod.
				continue
			}
			out = append(out, sidecarEndpoint{
				advName:     a.Name,
				addr:        pref.Addr().Unmap(),
				vrfID:       uint16(*a.Spec.VRFID),
				hostIfindex: hostIfindex,
				hostMAC:     hostMAC,
			})
		}
	}
	return out, nil
}

// isIngressAdvertisementName reports whether name is what
// crdnames.BGPAdvertisementName renders for the ingress attachment on nodeName.
// Matched from the end, because a node name may contain the separator while the
// two leading segments never can.
func isIngressAdvertisementName(name, nodeName, segment string) bool {
	rest, ok := strings.CutSuffix(name, "-"+nodeName)
	if !ok {
		return false
	}
	idx := strings.LastIndex(rest, "-")
	if idx < 0 {
		return false
	}
	return rest[idx+1:] == segment
}

// nodeLocatorIdentity returns the Block and Node-ID this node's SIDs are built
// from. ok is false, with a nil error, when this node has no SRv6 identity
// configured yet.
func nodeLocatorIdentity(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (block uint64, nodeID uint16, ok bool, err error) {
	prefix, err := nodeLocatorPrefix(ctx, k8s, namespace, nodeName)
	if err != nil {
		return 0, 0, false, err
	}
	if !prefix.IsValid() {
		return 0, 0, false, nil
	}
	// Derived from the prefix already assembled rather than re-read from the
	// BGPRouter, so the two cannot disagree about which locator this node
	// owns.
	block, err = uformat.Block(prefix.Addr())
	if err != nil {
		return 0, 0, false, fmt.Errorf("derive uSID Block from node locator %s: %w", prefix, err)
	}
	nodeID, err = uformat.NodeID(prefix.Addr())
	if err != nil {
		return 0, 0, false, fmt.Errorf("derive uSID Node-ID from node locator %s: %w", prefix, err)
	}
	return block, nodeID, true, nil
}

// ingressEntryPointAnnotations reads the host-side ifindex and MAC the sidecar
// recorded on its advertisement. ok is false when either is absent or unusable,
// which the caller treats as not yet published rather than as a failure.
//
// Both are validated rather than trusted. They arrive from another component
// through the API server and are about to become a route and a permanent
// neighbor for a tenant address, so a zero or negative ifindex, or a malformed
// hardware address, must not reach netlink.
func ingressEntryPointAnnotations(annotations map[string]string) (int, net.HardwareAddr, bool) {
	if annotations == nil {
		return 0, nil, false
	}
	raw, ok := annotations[crdnames.AnnotationIngressHostIfindex]
	if !ok {
		return 0, nil, false
	}
	ifindex, err := strconv.Atoi(raw)
	if err != nil || ifindex <= 0 {
		return 0, nil, false
	}
	rawMAC, ok := annotations[crdnames.AnnotationIngressHostMAC]
	if !ok {
		return 0, nil, false
	}
	mac, err := net.ParseMAC(rawMAC)
	if err != nil {
		return 0, nil, false
	}
	return ifindex, mac, true
}
