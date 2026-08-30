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
	"go.datum.net/galactic/internal/plumbing/ebpf/markvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// ebpfPinDir is the bpffs directory this file's registrations read from and
// attach against -- a package-level var, not a bare use of attach.PinDir,
// so tests can override it the same way internal/plumbing/srv6's own
// pinDir does. Production always uses attach.PinDir: this sidecar mounts
// the same host /sys/fs/bpf hostPath (see its DaemonSet volume) that
// galactic-cni's own control daemon already loads and pins usid_egress and
// its maps under, so the pins this file opens are the very same
// kernel-side objects, not a second, sidecar-private instance of them.
var ebpfPinDir = attach.PinDir

// ingressSidecarBlock is the fixed, synthetic uSID Block this file uses for
// every vrf_table entry it registers, standing in for the real, per-router
// bgp.srv6Locator-derived Block internal/cnibgp's own registerEBPFDatapath
// uses for a genuine tenant CNI attachment.
//
// Why a synthetic value is correct here, not a shortcut: vrf_table's key
// (block<<12 | argument) is consulted by usid_egress purely as a local,
// opaque lookup into this *one node's* own vrf_table -- never embedded in
// a packet, never interpreted by any other node (contrast the real,
// wire-significant Block a genuine SID's outer header carries). Nothing
// about correctness requires this sidecar's own entries to share the
// node's real BGPRouter locator; they only need to (a) never collide with
// a real (block, argument) pair internal/cnibgp might independently
// register for some other tenant VPC's CNI attachment sharing this same
// node, and (b) stay internally consistent between this file's own
// mark_vrf_table and vrf_table writes.
//
// (a) is what this constant buys: uformat.BlockMax is the all-ones 48-bit
// value -- as an IPv6 prefix, ffff:ffff:ffff::/48, a pattern no fabric
// operator would plausibly assign as a real SRv6 locator (every real one
// in this fleet today is a normal-looking GUA/ULA prefix, e.g.
// 2607:ed40:8002::/48) -- so this file's entries occupy a corner of
// vrf_table's keyspace no real CNI attachment's own (block, argument) pair
// can ever land in, regardless of which argument/vrfID it was allocated.
// Deliberately not derived from the VPC identifier or anything else
// per-VPC: a single reserved Block, with per-VPC disambiguation left
// entirely to argument (see argumentForTableID), is simpler and no less
// collision-safe, since this whole Block is already carved out.
//
// See internal/ingresssidecar's own package-level "no BGP runtime, CRD
// scheme, or per-node identity" design constraint (cmd/galactic-vrf's
// runCmd doc comment) for why this file cannot simply read a real
// bgp.srv6Locator the way internal/cnibgp does.
const ingressSidecarBlock = uformat.BlockMax

// trunkInnerName and trunkPeerName are the fixed names of this pod's one
// shared trunk veth pair (see ensureTrunk). Fixed, not derived from any
// per-pod identifier: cmd/galactic-vrf runs one process per pod, in that
// pod's own network namespace (its own appDesc: "per-pod VPC backend
// VRF/SRv6 route lifecycle") -- nothing else in that namespace creates
// interfaces, so "one trunk per pod" already collapses to "one trunk per
// process" without needing a name unique across pods.
const (
	trunkInnerName = "gtrunk"
	trunkPeerName  = "gtrunkp"
)

// argumentForTableID derives this file's uSID Argument for vpc's VRF from
// its own Linux kernel routing table ID, rather than allocating a separate
// value: vrf.TableID(vpc) already guarantees node-local uniqueness per VPC
// (that is its entire purpose), which is the only property Argument needs
// here (see ingressSidecarBlock's own doc comment) -- so reusing it avoids
// needing a second, redundant allocator. Fails if tableID does not fit in
// Argument's 12-bit range: vrf.Add allocates table IDs starting from 1 and
// counting up, so this is not expected to happen in any deployment with
// anywhere near 4095 VPCs live on one node, but a silently wrapped/aliased
// Argument would be a real cross-VPC datapath bug, not a safe fallback.
func argumentForTableID(tableID uint32) (uint16, error) {
	if tableID < uint32(uformat.ArgumentMin) || tableID > uint32(uformat.ArgumentMax) {
		return 0, fmt.Errorf(
			"ingresssidecar: VRF table id %d does not fit uSID Argument's range [%#x,%#x]",
			tableID, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	return uint16(tableID), nil
}

// markForTableID derives this VPC's SO_MARK/mark_vrf_table key from its own
// VRF table ID, mirroring argumentForTableID's exact reasoning:
// vrf.TableID(vpc) is already guaranteed node-local-unique, so reusing it
// avoids needing a second, redundant allocator for mark values too. Rejects
// tableID 0 specifically (never expected in practice -- vrf.Add's own
// allocator starts from 1) because an unmarked skb's mark is conventionally
// 0 in the kernel; a mark_vrf_table entry keyed on 0 would make every
// unmarked packet arriving on the shared trunk silently resolve to
// whichever VPC happened to get that mark, rather than failing the
// ifindex/mark lookup the way it should.
//
// PLACEHOLDER: this is not the mark value domain network-services-operator
// will actually stamp via SO_MARK in production -- that is
// network-services-operator's own phase-2 work (feat/srv6-routing-identity,
// unmerged as of this file's own last update), which this file has no
// visibility into and cannot anticipate. Treat this as an opaque uint32
// lookup key with no protocol meaning, exactly like ingressSidecarBlock and
// argumentForTableID already are for Block/Argument -- every call site of
// this function must remain grep-discoverable so it can be swapped for
// whatever phase 2 settles on.
func markForTableID(tableID uint32) (uint32, error) {
	if tableID == 0 {
		return 0, errors.New("ingresssidecar: VRF table id 0 is not a valid mark source")
	}
	return tableID, nil
}

// vrfLinkForTable returns the kernel VRF link whose own routing table is
// tableID -- the interface EnsureVRF already created for this table, found
// by table id rather than by name since this file's callers (EnsureRoute,
// EnsureEgressDatapath and their Remove counterparts) only ever carry a
// tableID forward, not the vpc string it came from (mirroring Backend's
// own EnsureRoute/RemoveRoute signatures).
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

// ensureTrunk creates (or finds) this pod's one shared trunk veth pair and
// attaches usid_egress to its peer's ingress hook -- the real interception
// point for every VPC's egress traffic this pod's Envoy Gateway serves, not
// a dedicated pair per VPC. This replaces the former per-VPC ensureEgressVeth:
// that approach enslaved each VPC's own inner end into that VPC's own VRF,
// which doesn't scale to one shared trunk serving many VPCs -- a Linux link
// can only ever have one master. inner is deliberately left unenslaved
// here; ensureVRFRoute below installs each VPC's own gateway route into
// that VPC's own table without requiring inner to be a member of it.
//
// usid_egress attaches on the peer's *ingress* hook, not the trunk's own
// egress hook: packet capture confirmed (back when this file used a
// dedicated veth per VPC) that a Linux VRF/veth master device's own TC
// egress hook never actually fires for traffic routed through it, however
// correctly every map involved is populated. internal/cnibgp's own
// attachUsidEgress never attaches to a VRF either, for the same reason --
// it attaches to a real tenant veth's ingress hook from the host side,
// because that is where the tenant's own egress traffic actually arrives.
// This attaches the exact same way, via attach.AttachEgress, not the
// removed attach.AttachLocalEgress.
//
// Attaching on this pod's own shared eth0 instead, tempting since that is
// where cilium ultimately hands the packet off, was considered and
// rejected: eth0 is shared by every VPC this sidecar serves, and
// ifindex_vrf_table can only carry one (block, argument) per ifindex -- a
// single eth0 registration could resolve at most one of this pod's VPCs
// correctly. The trunk's own peer ifindex is deliberately never registered
// into ifindex_vrf_table for the identical reason; that absence is exactly
// what makes usid_egress's mark_vrf_table fallback (usid.c's own dispatch
// comment) engage for trunk-arriving traffic instead.
//
// Idempotent: LinkAdd against an already-existing name, and
// attach.AttachEgress's own netlink.FilterReplace, are each already
// no-ops/overwrites on a repeat call -- safe to call on every
// ensureEgressDatapath, not just the first VPC a pod activates, and the
// trunk pair and its attachment are never torn down by removeEgressDatapath;
// they persist for this process's own lifetime (see removeEgressDatapath's
// own doc comment).
func ensureTrunk() (netlink.Link, error) {
	peerLink, err := netlink.LinkByName(trunkPeerName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("look up trunk peer %q: %w", trunkPeerName, err)
		}
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: trunkInnerName},
			PeerName:  trunkPeerName,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return nil, fmt.Errorf("add trunk veth pair %q/%q: %w", trunkInnerName, trunkPeerName, err)
		}
		peerLink, err = netlink.LinkByName(trunkPeerName)
		if err != nil {
			return nil, fmt.Errorf("look up newly-created trunk peer %q: %w", trunkPeerName, err)
		}
	}

	innerLink, err := netlink.LinkByName(trunkInnerName)
	if err != nil {
		return nil, fmt.Errorf("look up trunk inner end %q: %w", trunkInnerName, err)
	}
	if err := netlink.LinkSetUp(innerLink); err != nil {
		return nil, fmt.Errorf("set %q up: %w", trunkInnerName, err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		return nil, fmt.Errorf("set %q up: %w", trunkPeerName, err)
	}

	program, err := ebpf.LoadPinnedProgram(filepath.Join(ebpfPinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	if err := attach.AttachEgress(program, peerLink.Attrs().Name); err != nil {
		return nil, fmt.Errorf("attach usid_egress to trunk peer %q: %w", peerLink.Attrs().Name, err)
	}

	return peerLink, nil
}

// ensureVRFRoute installs one VPC's own default route into vrfLink's own
// table, pointed at the shared trunk's inner end via peer's link-local
// address as an explicit gateway -- the second, inner hop vrf_xmit() takes
// once a packet actually enters this VRF, without which this VRF's own
// table has no route of its own to anywhere. This is the same route the
// former per-VPC ensureEgressVeth always installed, just no longer paired
// 1:1 with a dedicated veth per VPC: many VPCs' own ensureVRFRoute calls
// can all legitimately name the same shared trunk inner end as nexthop,
// each isolated in its own table.
//
// Routed via the peer's own link-local address, deliberately not a bare
// on-link route (LinkIndex alone, no Gw): an on-link default forces the
// kernel to resolve a neighbor for the packet's own final destination
// before it ever reaches usid_egress's TC hook at all -- nothing answers
// that (there is no real host at an arbitrary destination this VRF's
// egress_route_table is about to rewrite), so the kernel gives up with
// "destination unreachable" and the packet never reaches the interface's
// qdisc, let alone the ingress filter on it. Routing via a gateway instead
// means the kernel only ever has to resolve *one* neighbor -- the peer,
// always present and always answerable -- regardless of what the packet's
// own destination address is.
//
// Idempotent: netlink.RouteReplace overwrites rather than errors on a
// second call for the same table.
func ensureVRFRoute(vrfLink *netlink.Vrf, peerLink netlink.Link) error {
	innerLink, err := netlink.LinkByName(trunkInnerName)
	if err != nil {
		return fmt.Errorf("look up trunk inner end %q: %w", trunkInnerName, err)
	}
	peerLinkLocal, err := waitForLinkLocalAddr(peerLink)
	if err != nil {
		return fmt.Errorf("wait for trunk peer %q's own link-local address: %w", trunkPeerName, err)
	}
	defaultRoute := &netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Table:     int(vrfLink.Table),
		LinkIndex: innerLink.Attrs().Index,
		Gw:        peerLinkLocal,
	}
	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return fmt.Errorf("install default route in VRF table %d via %q: %w", vrfLink.Table, trunkInnerName, err)
	}
	return nil
}

// removeVRFRoute removes the per-VPC route ensureVRFRoute installed in
// vrfLink's own table -- by Table alone (mirrors srv6.RouteMainDel's
// identical shape), since only one such route is ever installed per table.
// It must not, and does not, touch the shared trunk veth pair or
// usid_egress's attachment to it -- both persist across this and every
// other VPC's own teardown; see ensureTrunk's own doc comment.
func removeVRFRoute(vrfLink *netlink.Vrf) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Table: int(vrfLink.Table),
	})
}

// waitForLinkLocalAddr returns link's own global-scope-eligible link-local
// IPv6 address (kernel-assigned via SLAAC/EUI-64 the moment the link comes
// up), polling briefly since that assignment happens asynchronously to
// LinkSetUp returning -- confirmed live to normally already be present
// within the first poll, this bound is headroom, not an expected steady-
// state wait.
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

// ensureNodeSourceAddress registers this node's own SRv6/underlay-facing
// source address into node_src_addr_table, mirroring
// internal/cnibgp's own registerNodeSourceAddress -- see
// ensureEgressDatapath's own call site for why this sidecar cannot rely on
// that copy alone having already run on this node. Idempotent and cheap
// (one netlink query, one map write), safe to call on every
// ensureEgressDatapath the same way srv6.ResolveNodeSourceAddress's own
// per-node-constant result already tolerates being redone.
func ensureNodeSourceAddress() error {
	addr, err := srv6.ResolveNodeSourceAddress()
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

// ensureEgressDatapath makes usid_egress's own VRF resolution resolve
// correctly for vpc's VRF interface, then makes sure this pod's one shared
// trunk exists and is attached where it actually intercepts every VPC's
// traffic -- the actual enforcement point that was entirely missing before
// this file existed: EnsureRoute's egress_route_table entries had nothing
// anywhere in this pod's netns ever attached to read them.
//
// Idempotent: every step here is a plain overwrite/replace/register
// operation, safe to call on every SetDesired that ensures a VRF (a repeat
// call for an already-provisioned VPC, e.g. after this sidecar's own
// restart, is a no-op in effect), and safe to call once per VPC this pod
// activates even though ensureTrunk's own work only actually needs doing
// once per process.
func ensureEgressDatapath(tableID uint32) error {
	// node_src_addr_table is a per-node singleton, not per-VPC: usid_egress
	// fails open (TC_ACT_UNSPEC, uncounted) on every encapsulation attempt
	// until some caller sets it, and internal/cnibgp's own registration
	// only ever runs as a side effect of a real tenant CNI ADD landing on
	// this node -- something a node running only this sidecar's
	// attachments, with no real tenant CNI attachment at all, never gets.
	// An otherwise fully correct attachment (VRF, veth, ifindex_vrf_table,
	// egress_route_table all resolving) can therefore silently produce no
	// encapsulated traffic at all, traced to this exact gap. Non-fatal on
	// failure, same as
	// internal/cnibgp's own call site and for the identical reason --
	// ResolveNodeSourceAddress needs a converged underlay default route,
	// which this pod can transiently lack right after this sidecar itself
	// restarts.
	if err := ensureNodeSourceAddress(); err != nil {
		slog.Warn("ensureEgressDatapath: could not register this node's own SRv6 source address; "+
			"egress routing will fail open until this succeeds", "err", err)
	}

	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}

	mark, err := markForTableID(tableID)
	if err != nil {
		return err
	}

	vrfLink, err := vrfLinkForTable(tableID)
	if err != nil {
		return err
	}

	peerLink, err := ensureTrunk()
	if err != nil {
		return fmt.Errorf("ensure shared trunk: %w", err)
	}

	if err := ensureVRFRoute(vrfLink, peerLink); err != nil {
		return fmt.Errorf("ensure VRF route for table %d: %w", tableID, err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF vrf_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	// EgressKindVeth: a don't-care here, not a real claim about the trunk's
	// own link type. EgressKind only steers usid_ingress's own step-9
	// redirect (usid.c's own doc comment on enum egress_kind), and
	// usid_ingress is never attached anywhere in this pod's netns -- this
	// sidecar has no ingress/decap side at all (its own package doc
	// comment). usid_egress, the only program this file's registrations
	// ever feed, never reads EgressKind.
	if err := registry.VRF.Register(ingressSidecarBlock, argument, tableID, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}

	markTable, markCloser, err := markvrfmap.OpenPinned(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF mark_vrf_table: %w", err)
	}
	defer func() { _ = markCloser.Close() }()

	if err := markTable.Register(mark, ingressSidecarBlock, argument); err != nil {
		return fmt.Errorf("register eBPF mark_vrf_table entry: %w", err)
	}

	return nil
}

// removeEgressDatapath undoes ensureEgressDatapath's own per-VPC
// registrations and route for the VPC whose VRF table is tableID -- called
// before RemoveVRF deletes the VRF interface itself (backend.go's
// RemoveVRF), while that interface can still be resolved by table id.
// Best-effort and idempotent, matching every other teardown step in this
// package (Unregister is already "absent is not an error"): every step is
// attempted even if an earlier one failed, and every failure is joined and
// returned together, rather than a first error aborting the rest of
// cleanup.
//
// Unlike the removed per-VPC veth this replaces, this does NOT delete any
// interface and does NOT detach usid_egress from anything: the shared
// trunk and its attachment are this process's own, not this one VPC's, and
// must survive every individual VPC's own teardown -- they only ever go
// away with the process itself (cmd/galactic-vrf's root.go: no proactive
// VRF/route teardown on exit, so the next instance reconciles from
// scratch).
func removeEgressDatapath(tableID uint32) error {
	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}
	mark, err := markForTableID(tableID)
	if err != nil {
		return err
	}

	var errs []error

	if vrfLink, verr := vrfLinkForTable(tableID); verr != nil {
		errs = append(errs, fmt.Errorf("look up VRF link for table %d: %w", tableID, verr))
	} else if err := removeVRFRoute(vrfLink); err != nil {
		errs = append(errs, fmt.Errorf("remove VRF route for table %d: %w", tableID, err))
	}

	if markTable, closer, oerr := markvrfmap.OpenPinned(ebpfPinDir); oerr != nil {
		errs = append(errs, fmt.Errorf("open pinned eBPF mark_vrf_table: %w", oerr))
	} else {
		if err := markTable.Unregister(mark); err != nil {
			errs = append(errs, fmt.Errorf("unregister eBPF mark_vrf_table entry: %w", err))
		}
		_ = closer.Close()
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

// ensureRedirectRoute installs a plain (unencapsulated, no SEG6 involved)
// host route for prefix into this pod's own main routing table, forwarding
// out the VRF interface for tableID as a bare nexthop device -- no gateway
// address, since a Linux VRF master device needs none: a route naming it
// as LinkIndex alone re-dispatches the packet through that device's own
// egress hook, which is exactly where ensureEgressDatapath already
// attached usid_egress.
//
// This exists because nothing else pulls this pod's outbound traffic for
// prefix off its ordinary default route: neither Envoy nor cilium has any
// notion of this destination belonging to a VPC VRF (see this fix's own
// design notes), so an unbound socket's normal FIB lookup would otherwise
// resolve prefix via the default route out eth0 exactly like any other
// "world" destination. A route this specific (EnsureRoute's own callers
// always pass a /128 -- see DesiredRoute.Prefix) wins ordinary
// longest-prefix-match over that default route without needing cilium to
// know anything about the VPC address space, or Envoy to bind its sockets
// to anything.
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

// removeRedirectRoute removes the main-table redirect route ensureRedirectRoute
// installed for prefix -- ensureRedirectRoute's own counterpart, mirroring
// srv6.RouteMainDel's identical shape (a plain netlink.RouteDel by Dst and
// Table alone, no LinkIndex needed to identify it).
func removeRedirectRoute(prefix *net.IPNet) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: unix.RT_TABLE_MAIN,
	})
}
