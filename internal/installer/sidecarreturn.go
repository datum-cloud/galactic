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
// inside its *own* netns, and advertises a per-VPC gateway address into
// EVPN so a backend's reply -- addressed back to that gateway address --
// has an SRv6 route to follow (GatewayPublisher's doc comment). A remote
// node duly encapsulates that reply toward this node's own SID for the
// advertised Argument.
//
// Nothing on this node could take delivery of it. The sidecar registers
// only what usid_egress reads, under a synthetic Block that usid_ingress
// deliberately never matches (ingressSidecarBlock's doc comment), and it
// cannot register the ingress side itself for two reasons that both come
// down to which netns it is in: usid_ingress runs in the *host* netns,
// while the sidecar's VRFs, their routing tables, and both ends of their
// veth pairs are in the pod's, and a container in that pod cannot install
// host-netns routes. So the receiving half has to live here, in the host
// daemon, and this file is it.
//
// The split runs the other way too, which is why this reads annotations
// rather than going to look. Pointing a reply at the right pod needs that
// pod's host-side veth and MAC, and reading those from here means entering
// its namespace: setns wants CAP_SYS_ADMIN, and this container drops ALL
// and adds only BPF, NET_ADMIN and NET_RAW. The sidecar can read both from
// inside with no privilege at all, so it publishes them on the
// advertisement it already writes and this side consumes them. Each half
// does the part it has the rights for.
//
// What a decapsulated reply needs, and what this installs per advertised
// sidecar gateway address:
//
//  1. locator_table + function_table entries for this node's own Block and
//     Node-ID, so usid_ingress claims the packet at all rather than passing
//     it to a stack that has no tunnel device to hand it to. A node hosting
//     only sidecars has no CNI attachment, so nothing else ever writes
//     these -- internal/cnibgp's registerEBPFDatapath, their only other
//     writer, runs at CNI ADD.
//  2. A vrf_table entry under this node's *real* Block, keyed on the
//     Argument the advertisement was published with, pointing at a routing
//     table this file owns, with EgressKindVeth so step 9 uses
//     bpf_redirect_peer and crosses into the pod's netns.
//  3. In that table, a route for the gateway address out the *host* side of
//     the pod's netns-crossing veth, so step 8's bpf_fib_lookup resolves to
//     an interface bpf_redirect_peer can cross.
//  4. A permanent neighbor for that address on the same interface. As
//     internal/hostgw's installGatewayNeighbor records, bpf_fib_lookup does
//     not trigger NDP the way ordinary forwarding does, so an unresolved
//     neighbor is BPF_FIB_LKUP_RET_NO_NEIGH and a silent drop.
//
// The Argument is the one subtlety worth stating plainly, because getting
// it wrong is invisible. The sidecar's own vrf_table registrations key on
// argumentForTableID -- its pod-netns table id -- while the advertisement,
// and therefore the SID a remote node encapsulates toward, carries the
// BGPVRFInstance VRFID. Those are different numbers for the same VPC. This
// file keys on the advertised VRFID, since that is what actually arrives on
// the wire.

const (
	// sidecarReturnTableBase is the first Linux routing table id this file
	// allocates from, and sidecarReturnTableMax the last. A dedicated,
	// documented range matters twice over: internal/plumbing/vrf's own
	// allocator hands out table ids from 1 upward for real tenant VRFs, so
	// anything low would eventually collide with one, and pruning below
	// deletes whole tables, which must never be able to reach a table this
	// file did not create.
	//
	// The range is sized to hold one table per Argument
	// ([ArgumentMin,ArgumentMax], 12 bits), which is the most sidecar VRFs
	// a single node can ever have.
	sidecarReturnTableBase = 0xF000
	sidecarReturnTableMax  = sidecarReturnTableBase + uformat.ArgumentMax
)

// sidecarReturnTableID maps an advertised Argument to the routing table
// this file keeps that VPC's return route in. One table per Argument rather
// than one shared table so pruning a single withdrawn VPC cannot disturb
// another's route.
func sidecarReturnTableID(vrfID uint16) (uint32, error) {
	if vrfID < uformat.ArgumentMin || vrfID > uformat.ArgumentMax {
		return 0, fmt.Errorf("sidecar return path: VRFID %d outside the valid Argument range [%#x,%#x]",
			vrfID, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	return uint32(sidecarReturnTableBase) + uint32(vrfID), nil
}

// sidecarEndpoint is one gateway address this node's sidecar has advertised:
// the Argument a remote node will have encoded into the SID it encapsulates
// replies toward, plus where on this node that pod can be reached.
type sidecarEndpoint struct {
	advName string
	addr    netip.Addr
	vrfID   uint16
	// hostIfindex is the ifindex, in this (host) namespace, of the peer of
	// the pod's primary interface -- what bpf_redirect_peer has to target
	// to enter that pod. hostMAC is the pod-side end's hardware address.
	//
	// Both come from the advertisement's own annotations rather than being
	// discovered here, because only the sidecar can see them: reading them
	// from this side means entering the pod's namespace, and setns needs
	// CAP_SYS_ADMIN, which this container deliberately does not carry. See
	// crdnames.AnnotationIngressHostIfindex.
	hostIfindex int
	hostMAC     net.HardwareAddr
}

// reconcileSidecarReturnPath is Run's non-fatal wrapper, matching
// reconcileLocatorLocalRoute's contract: a node with no sidecar on it, a
// not-yet-created BGPRouter, or a transient API error must never stop the
// installer daemon, and the caller's ticker retries on its own.
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
// gateway address on this node up to date, and prunes what no longer
// belongs. Idempotent, and safe on a node with no sidecar at all: with no
// matching advertisement it installs nothing and only prunes.
func ensureSidecarReturnPath(ctx context.Context, k8s client.Client, namespace, nodeName string) error {
	endpoints, err := sidecarGatewayEndpoints(ctx, k8s, namespace, nodeName)
	if err != nil {
		return err
	}

	// Prune first, and unconditionally: a withdrawn advertisement has to
	// stop being routed here even on a node whose identity has since gone
	// away, and pruning is the only step that is correct with an empty
	// endpoint set.
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
		// No SRv6 identity configured for this node yet. The sidecar's
		// advertisements exist but nothing can be keyed off a Block we do
		// not have; the ticker retries.
		return nil
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(attach.PinDir)
	if err != nil {
		return fmt.Errorf("open pinned uSID maps for the sidecar return path: %w", err)
	}
	defer func() { _ = closer.Close() }()

	// Per-node, not per-endpoint, and the reason a sidecar-only node needs
	// this file at all: without them usid_ingress rejects every arriving
	// uSID packet before it reaches any Argument-specific decision.
	if err := registry.Locator.Register(block, nodeID); err != nil {
		return fmt.Errorf("register locator_table entry for the sidecar return path: %w", err)
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return fmt.Errorf("register function_table entry for the sidecar return path: %w", err)
	}

	var errs []error
	for _, e := range endpoints {
		if err := installSidecarReturn(registry, block, e); err != nil {
			// Per-endpoint, and never fatal to the sweep: one Envoy pod
			// still starting up must not stop another VPC's return path
			// being installed.
			errs = append(errs, fmt.Errorf("advertisement %s: %w", e.advName, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("sidecar return path: %w", errors.Join(errs...))
	}
	return nil
}

// installSidecarReturn wires up one endpoint: the route, the neighbor, and
// the vrf_table entry that together point a decapsulated reply at the pod
// holding that gateway address.
func installSidecarReturn(registry *usidmap.Registry, block uint64, e sidecarEndpoint) error {
	// The interface the annotation names has to still exist here. It may
	// not: the advertisement outlives any single Envoy pod, so between a
	// pod being replaced and its sidecar re-publishing, this names the veth
	// of a pod that is gone. Installing against a stale ifindex would put a
	// route to a tenant address on whatever now holds that index, so this
	// is checked rather than assumed.
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

	// EgressKindVeth is a real claim here, not a don't-care: the interface
	// the route above resolves to is one end of a veth pair whose peer is
	// in the pod's netns, so step 9 must use bpf_redirect_peer to cross
	// into it. Plain bpf_redirect would hand the packet to that interface's
	// own egress in this netns and never reach the sidecar.
	if err := registry.VRF.Register(block, e.vrfID, table, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register vrf_table entry (block %#x, argument %d): %w", block, e.vrfID, err)
	}
	return nil
}

// ensureSidecarReturnRoute installs the /128 device route step 8's
// bpf_fib_lookup resolves against, in this file's own table for that
// Argument. RouteReplace so a pod that came back on a different host-side
// veth is followed rather than duplicated.
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
// but will not resolve for itself. Permanent, unlike internal/hostgw's tap
// sweep and for the opposite reason: the pod-side MAC here is read
// authoritatively from the kernel rather than solicited, so a stale entry
// is not a risk -- and if the pod is replaced, the next tick reads the new
// MAC and RouteReplace/NeighSet overwrite this one.
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

// pruneSidecarReturnRoutes removes every route in this file's own table
// range that live does not account for, so a withdrawn VPC stops being
// routed into a pod that may since have been replaced by an unrelated one.
//
// One listing across all tables, filtered down to the reserved range here,
// rather than a listing per table: the range spans every possible Argument,
// so per-table would be 4096 netlink round trips on every tick to find the
// handful of routes that exist.
//
// staleSidecarReturnRoute is the whole safety argument, and it is a pure
// predicate so the cases it must not match can be enumerated in a test --
// this deletes routes, and a range check that drifted from the constants
// would delete somebody else's.
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

// staleSidecarReturnRoute reports whether r is a route this file installed
// for an endpoint that live no longer accounts for.
//
// Every condition here is a guard against deleting something else. The
// table range is what confines this to tables this file allocates from; a
// route with no destination, or one whose table holds the address live still
// wants, is left alone.
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
// sidecar on *this* node has published.
//
// Identified by name rather than by shape. A sidecar's advertisement is a
// single /128 with an Argument and End.DT46, which is also exactly what a
// real CNI attachment publishes for a pod address -- and those must not be
// touched here, since internal/cnibgp already registers a vrf_table entry
// pointing at the pod's real host-netns VRF. The name is the only
// discriminator that cannot confuse the two, which is why
// crdnames.IngressAdvertisementSegment is exported for it.
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
			// An advertisement from a sidecar that has not recorded its own
			// entry point. Skipped rather than errored, and quietly: this is
			// what an advertisement written by an older sidecar looks like,
			// and it resolves itself the next time that sidecar republishes.
			slog.Debug("Sidecar gateway advertisement carries no host-side entry point yet",
				"advertisement", a.Name)
			continue
		}
		for _, p := range a.Spec.Prefixes {
			pref, err := netip.ParsePrefix(string(p))
			if err != nil || !pref.Addr().Is6() || pref.Bits() != pref.Addr().BitLen() {
				// A gateway address is always a single host route. Anything
				// else is not something this return path knows how to point
				// at a pod.
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
// crdnames.BGPAdvertisementName renders for the ingress attachment on
// nodeName. Matched from the end because a node name may itself contain the
// separator, while the two leading segments never can.
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

// nodeLocatorIdentity returns the Block and Node-ID this node's own SIDs are
// built from. ok is false, with a nil error, when this node has no SRv6
// identity configured yet -- the same "nothing to do" case
// nodeLocatorPrefix returns its zero Prefix for.
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
	// Derived from the prefix nodeLocatorPrefix already assembled rather
	// than re-read from the BGPRouter, so the two can never disagree about
	// which locator this node owns.
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

// ingressEntryPointAnnotations reads the host-side ifindex and MAC the
// sidecar recorded on its own advertisement. ok is false when either is
// absent or unusable, which the caller treats as "not published yet"
// rather than as a failure.
//
// Both are validated rather than trusted. They come from another component
// via the API server, and they are about to become a route and a permanent
// neighbor for a tenant address: a zero or negative ifindex, or a malformed
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
