// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
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
// every vrf_table/ifindex_vrf_table entry it registers, standing in for
// the real, per-router bgp.srv6Locator-derived Block internal/cnibgp's own
// registerEBPFDatapath uses for a genuine tenant CNI attachment.
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
// ifindex_vrf_table and vrf_table writes.
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

// egressVethNames derives this VPC's own veth pair names from tableID
// alone -- ensureEgressDatapath/removeEgressDatapath only ever carry a
// tableID forward, not the vpc string vrf.Add itself was keyed on
// (vrfLinkForTable's own doc comment). Collision-free the same way
// vrf.TableID(vpc) already is (that is its whole purpose), and
// comfortably inside IFNAMSIZ: tableID fits uSID Argument's 12-bit range
// (argumentForTableID's own check), so at most 4 decimal digits.
func egressVethNames(tableID uint32) (inner, peer string) {
	return fmt.Sprintf("ivs%d", tableID), fmt.Sprintf("ivp%d", tableID)
}

// ensureEgressVeth creates (or finds) the one real interface pair
// usid_egress actually intercepts this VPC's traffic on: inner enslaved
// into vrfLink itself, with a default route in vrfLink's own table
// pointed at it, so every destination this VPC's egress_route_table might
// ever match has somewhere real to go once the kernel's own vrf_xmit()
// redoes its route lookup inside that table. peer -- left outside the
// VRF, in this pod's main netns -- is where usid_egress actually attaches
// (see ensureEgressDatapath's own doc comment for why the VRF's own
// egress hook doesn't work for that).
//
// Idempotent: LinkAdd against an already-existing name is treated as
// already-done, and RouteReplace overwrites rather than errors on a
// second call -- the same "safe on every SetDesired that ensures a VRF"
// contract every other step in this file already has.
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

	// The second, inner hop vrf_xmit() takes once a packet actually
	// enters this VRF -- a route in the VRF's own table, not the main
	// table ensureRedirectRoute installs, which otherwise has no route of
	// its own to anywhere.
	//
	// Routed via the peer's own link-local address, deliberately not a
	// bare on-link route (LinkIndex alone, no Gw): confirmed live in
	// us-central-1-staging-lab, an on-link default forces the kernel to
	// resolve a neighbor for the packet's own final destination before
	// it ever reaches usid_egress's TC hook at all -- nothing answers
	// that (there is no real host at an arbitrary destination this VRF's
	// egress_route_table is about to rewrite), so the kernel gives up
	// with "destination unreachable" and the packet never reaches the
	// interface's qdisc, let alone the ingress filter on it. Routing via
	// a gateway instead means the kernel only ever has to resolve *one*
	// neighbor -- the peer, always present and always answerable, the
	// same real ND exchange proven to complete in under a millisecond
	// earlier in this investigation -- regardless of what the packet's
	// own destination address is.
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

// ensureEgressDatapath makes usid_egress's own VRF resolution
// (ifindex_vrf_table -> vrf_table -> Linux VRF table id, usid.c's own
// doc comment on usid_egress) resolve correctly for vpc's VRF interface,
// then attaches usid_egress where it actually intercepts that VRF's
// traffic -- the actual enforcement point that was entirely missing
// before this file existed: EnsureRoute's egress_route_table entries had
// nothing anywhere in this pod's netns ever attached to read them.
//
// This used to attach directly to the VRF interface's own TC *egress*
// hook (attach.AttachLocalEgress). That looked right -- the VRF is where
// usid_egress's ifindex_vrf_table lookup needs a 1:1 ifindex<->VRF
// mapping anyway, the same shape internal/cnibgp's own
// registerEBPFDatapath relies on for a genuine tenant veth/tap attachment
// -- but did not hold up: confirmed live in us-central-1-staging-lab via
// packet capture, a Linux VRF master device's own TC egress hook never
// actually fires for traffic routed through it, for any tenant, however
// correctly every map involved is populated. internal/cnibgp's own
// attachUsidEgress never attaches to a VRF at all; it attaches to a real
// tenant veth's *ingress* hook from the host side, because that is where
// the tenant's own egress traffic actually arrives. ensureEgressVeth
// gives this file the equivalent of that real veth -- enslaved into the
// VRF so vrf_xmit() has somewhere to send a packet once it resolves
// there -- and this attaches the exact same way internal/cnibgp already
// does, on its peer's ingress hook via attach.AttachEgress, not
// attach.AttachLocalEgress.
//
// Attaching on this pod's own shared eth0 instead, tempting since that is
// where cilium ultimately hands the packet off, was considered and
// rejected: eth0 is shared by every VPC this sidecar serves, and
// ifindex_vrf_table can only carry one (block, argument) per ifindex -- a
// single eth0 registration could resolve at most one of this pod's VPCs
// correctly.
//
// Idempotent: every step here is a plain overwrite/replace operation,
// safe to call on every SetDesired that ensures a VRF (a repeat call for
// an already-provisioned VPC, e.g. after this sidecar's own restart, is a
// no-op in effect).
func ensureEgressDatapath(tableID uint32) error {
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

	registry, closer, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF vrf_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	// EgressKindVeth: a don't-care here, not a real claim about this VRF
	// device's own link type. EgressKind only steers usid_ingress's own
	// step-9 redirect (usid.c's own doc comment on enum egress_kind), and
	// usid_ingress is never attached anywhere in this pod's netns -- this
	// sidecar has no ingress/decap side at all (its own package doc
	// comment). usid_egress, the only program this file's registrations
	// ever feed, never reads EgressKind.
	if err := registry.VRF.Register(ingressSidecarBlock, argument, tableID, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}

	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = ifindexCloser.Close() }()

	// Keyed by the veth peer's ifindex, not the VRF's own -- see this
	// function's own doc comment for why usid_egress has to see this
	// traffic arriving on that interface's ingress hook, not the VRF's
	// egress.
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

// removeEgressDatapath undoes ensureEgressDatapath's own registrations for
// the VPC whose VRF table is tableID -- called before RemoveVRF deletes
// the VRF interface itself (backend.go's RemoveVRF), while the veth
// pair's own names can still be derived. Best-effort and idempotent,
// matching every other teardown step in this package (Unregister is
// already "absent is not an error"): every step is attempted even if an
// earlier one failed, and every failure is joined and returned together,
// rather than a first error aborting the rest of cleanup.
//
// No explicit detach call for usid_egress: deleting the veth pair below
// removes both ends and, with them, every qdisc/filter attached to
// either -- the same "the interface going away is the detach" contract
// internal/cnibgp's own teardown already relies on for its real tenant
// veth (attachUsidEgress's own doc comment has no DetachEgress
// counterpart at all).
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
