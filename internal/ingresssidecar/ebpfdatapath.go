// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

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

// ensureEgressDatapath makes usid_egress's own VRF resolution
// (ifindex_vrf_table -> vrf_table -> Linux VRF table id, usid.c's own
// doc comment on usid_egress) resolve correctly for vpc's VRF interface,
// then attaches usid_egress to that interface's own TC *egress* hook
// (attach.AttachLocalEgress) -- the actual enforcement point that was
// entirely missing before this file existed: EnsureRoute's
// egress_route_table entries had nothing anywhere in this pod's netns
// ever attached to read them.
//
// One VRF interface per VPC (vrf.Add's own doc comment) gives this file
// exactly the ifindex<->VRF 1:1 mapping usid_egress's ifindex_vrf_table
// lookup assumes -- the same shape internal/cnibgp's own
// registerEBPFDatapath relies on for a genuine tenant veth/tap attachment,
// just substituting "one VRF device per VPC sharing this gateway pod" for
// "one veth per CNI attachment". Attaching on this pod's own shared eth0
// instead, tempting since that is where cilium ultimately hands the
// packet off, was considered and rejected: eth0 is shared by every VPC
// this sidecar serves, and ifindex_vrf_table can only carry one (block,
// argument) per ifindex -- a single eth0 registration could resolve at
// most one of this pod's VPCs correctly.
//
// Idempotent: Register/AttachLocalEgress are both plain overwrite/replace
// operations, safe to call on every SetDesired that ensures a VRF (a
// repeat call for an already-provisioned VPC, e.g. after this sidecar's
// own restart, is a no-op in effect).
func ensureEgressDatapath(tableID uint32) error {
	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}

	link, err := vrfLinkForTable(tableID)
	if err != nil {
		return err
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

	if err := ifindexTable.Register(uint32(link.Attrs().Index), ingressSidecarBlock, argument); err != nil {
		return fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}

	program, err := ebpf.LoadPinnedProgram(filepath.Join(ebpfPinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	if err := attach.AttachLocalEgress(program, link.Attrs().Name); err != nil {
		return fmt.Errorf("attach usid_egress to VRF interface %q: %w", link.Attrs().Name, err)
	}
	return nil
}

// removeEgressDatapath undoes ensureEgressDatapath's own registrations for
// the VPC whose VRF table is tableID -- called before RemoveVRF deletes
// the VRF interface itself (backend.go's RemoveVRF), while its ifindex can
// still be resolved. Best-effort and idempotent, matching every other
// teardown step in this package (Unregister/DetachLocalEgress are both
// already "absent is not an error"): every step is attempted even if an
// earlier one failed, and every failure is joined and returned together,
// rather than a first error aborting the rest of cleanup.
func removeEgressDatapath(tableID uint32) error {
	argument, err := argumentForTableID(tableID)
	if err != nil {
		return err
	}

	var errs []error

	if link, lerr := vrfLinkForTable(tableID); lerr != nil {
		errs = append(errs, fmt.Errorf("find VRF interface for table %d: %w", tableID, lerr))
	} else {
		if err := attach.DetachLocalEgress(link.Attrs().Name); err != nil {
			errs = append(errs, fmt.Errorf("detach usid_egress: %w", err))
		}
		if ifindexTable, closer, oerr := ifindexvrfmap.OpenPinned(ebpfPinDir); oerr != nil {
			errs = append(errs, fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", oerr))
		} else {
			if err := ifindexTable.Unregister(uint32(link.Attrs().Index)); err != nil {
				errs = append(errs, fmt.Errorf("unregister eBPF ifindex_vrf_table entry: %w", err))
			}
			_ = closer.Close()
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
