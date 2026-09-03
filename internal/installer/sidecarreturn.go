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
	"os"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
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

// sidecarEndpoint is one gateway address this node's sidecar has advertised,
// and the Argument a remote node will have encoded into the SID it
// encapsulates replies toward.
type sidecarEndpoint struct {
	advName string
	addr    netip.Addr
	vrfID   uint16
}

// podNetNS is one network namespace on this node other than our own, with
// the two things a return path needs from it: which host-side interface
// crosses into it, and every address reachable inside it.
type podNetNS struct {
	path string
	// hostIfindex is the ifindex, in *this* (host) netns, of the peer of
	// the netns-crossing veth found inside. That is the interface
	// bpf_redirect_peer has to target to enter this namespace.
	hostIfindex int
	// mac is the pod-side end's hardware address, which is what a frame
	// entering the namespace is addressed to.
	mac net.HardwareAddr
	// addrs is every unicast address assigned on any link inside, across
	// every VRF -- a sidecar's gateway address sits on a veth inside one of
	// the pod's own VRFs, not on its primary interface, so matching has to
	// consider all of them.
	addrs map[netip.Addr]struct{}
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

	namespaces, err := discoverPodNetNS()
	if err != nil {
		return err
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
		if err := installSidecarReturn(registry, namespaces, block, e); err != nil {
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

// installSidecarReturn wires up one endpoint: locate the netns holding its
// gateway address, then install the route, the neighbor, and the vrf_table
// entry that point at it.
func installSidecarReturn(
	registry *usidmap.Registry, namespaces []podNetNS, block uint64, e sidecarEndpoint,
) error {
	target := findNetNSForAddr(namespaces, e.addr)
	if target == nil {
		// The ordinary not-yet case, and the reason this is a warn-and-retry
		// reconcile rather than a one-shot: the advertisement outlives any
		// single Envoy pod, so between a pod restart and its sidecar
		// re-creating the VRF there is a window where the address it names
		// exists nowhere on this node.
		return fmt.Errorf("no network namespace on this node holds gateway address %s yet", e.addr)
	}

	table, err := sidecarReturnTableID(e.vrfID)
	if err != nil {
		return err
	}

	if err := ensureSidecarReturnRoute(table, e.addr, target.hostIfindex); err != nil {
		return err
	}
	if err := ensureSidecarReturnNeighbor(e.addr, target.hostIfindex, target.mac); err != nil {
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
		for _, p := range a.Spec.Prefixes {
			pref, err := netip.ParsePrefix(string(p))
			if err != nil || !pref.Addr().Is6() || pref.Bits() != pref.Addr().BitLen() {
				// A gateway address is always a single host route. Anything
				// else is not something this return path knows how to point
				// at a namespace.
				continue
			}
			out = append(out, sidecarEndpoint{
				advName: a.Name,
				addr:    pref.Addr().Unmap(),
				vrfID:   uint16(*a.Spec.VRFID),
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

// discoverPodNetNS enumerates every network namespace on this node other
// than our own.
//
// By enumeration rather than by asking. The sidecar cannot tell us where it
// is: a netns is only addressable as /proc/<pid>/ns/net, and a pid is not
// something a container can meaningfully publish about itself for another
// process to reuse later. The gateway address is the identity that matters
// anyway, and matching on it is self-validating -- if the address is in a
// namespace, that is the namespace replies to it belong in.
//
// Errors on individual namespaces are skipped rather than returned: a
// process exiting mid-walk is entirely ordinary, and one unreadable
// namespace must not hide every other.
func discoverPodNetNS() ([]podNetNS, error) {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("read own network namespace: %w", err)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("enumerate /proc: %w", err)
	}

	seen := make(map[string]struct{})
	var out []podNetNS
	for _, entry := range entries {
		if _, cerr := strconv.Atoi(entry.Name()); cerr != nil {
			continue // not a pid
		}
		path := "/proc/" + entry.Name() + "/ns/net"
		target, rerr := os.Readlink(path)
		if rerr != nil {
			continue
		}
		if target == self {
			continue // our own namespace: usid_ingress already runs here
		}
		if _, dup := seen[target]; dup {
			continue // another process in a namespace already inspected
		}
		seen[target] = struct{}{}

		inspected, ierr := inspectPodNetNS(path)
		if ierr != nil {
			slog.Debug("Could not inspect network namespace for the sidecar return path",
				"path", path, "err", ierr)
			continue
		}
		out = append(out, *inspected)
	}
	return out, nil
}

// inspectPodNetNS reads the one namespace at path: every address inside,
// and the host-side ifindex plus pod-side MAC of the veth that crosses into
// it.
func inspectPodNetNS(path string) (*podNetNS, error) {
	handle, err := ns.GetNS(path)
	if err != nil {
		return nil, fmt.Errorf("open network namespace %s: %w", path, err)
	}
	defer handle.Close() //nolint:errcheck // netns close on teardown

	result := &podNetNS{path: path, addrs: make(map[netip.Addr]struct{})}
	err = handle.Do(func(_ ns.NetNS) error {
		links, lerr := netlink.LinkList()
		if lerr != nil {
			return fmt.Errorf("list links: %w", lerr)
		}
		byIndex := make(map[int]netlink.Link, len(links))
		for _, l := range links {
			byIndex[l.Attrs().Index] = l
		}
		for _, l := range links {
			attrs := l.Attrs()
			// Prefer the primary interface when there is one, so a pod with
			// more than one way in (a Multus secondary, say) resolves to the
			// same interface on every pass rather than to whichever the
			// kernel happened to list first.
			better := result.hostIfindex == 0 || attrs.Name == primaryPodInterface
			if better && crossingVeth(l, byIndex) {
				result.hostIfindex = attrs.ParentIndex
				result.mac = append(net.HardwareAddr(nil), attrs.HardwareAddr...)
			}
			addrs, aerr := netlink.AddrList(l, netlink.FAMILY_V6)
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				if got, ok := netip.AddrFromSlice(a.IP); ok {
					got = got.Unmap()
					if got.IsGlobalUnicast() {
						result.addrs[got] = struct{}{}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result.hostIfindex == 0 {
		return nil, fmt.Errorf("no netns-crossing veth found in %s", path)
	}
	return result, nil
}

// primaryPodInterface is the name Kubernetes gives a pod's own interface,
// and so the netns-crossing veth to prefer when a pod has more than one.
const primaryPodInterface = "eth0"

// crossingVeth reports whether link is a veth whose peer is outside this
// namespace, i.e. the one interface a packet can be redirected in through.
// byIndex is every link in this same namespace, keyed by ifindex.
//
// A pod netns holds two kinds of veth: its primary interface, whose peer is
// the host-side end, and (for an Envoy pod running the ingress sidecar) a
// pair per tenant VPC with *both* ends inside this same namespace. Only the
// first is a way in, and the second must never be mistaken for one.
//
// Distinguished by reciprocity, not by whether the peer ifindex resolves
// here. Ifindices are per-namespace and collide freely across them, so a
// pod whose primary interface happens to peer with host ifindex 12 while
// this namespace also has some link 12 would look internal and be skipped,
// leaving that pod unreachable with nothing to indicate why. A genuine
// same-namespace pair points back: the peer's own ParentIndex is this
// link's index. A coincidental collision does not.
func crossingVeth(link netlink.Link, byIndex map[int]netlink.Link) bool {
	if _, isVeth := link.(*netlink.Veth); !isVeth {
		return false
	}
	attrs := link.Attrs()
	peerIndex := attrs.ParentIndex
	if peerIndex <= 0 {
		return false
	}
	if peer, ok := byIndex[peerIndex]; ok && peer.Attrs().ParentIndex == attrs.Index {
		return false // a real pair with both ends here: an internal veth
	}
	return true
}

// findNetNSForAddr returns the namespace holding addr, or nil.
func findNetNSForAddr(namespaces []podNetNS, addr netip.Addr) *podNetNS {
	for i := range namespaces {
		if _, ok := namespaces[i].addrs[addr]; ok {
			return &namespaces[i]
		}
	}
	return nil
}
