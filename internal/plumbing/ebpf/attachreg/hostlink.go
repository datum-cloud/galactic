// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// ErrVRFNotRegistered is returned by RegisterHostLink when the VRF has no
// uSID entry on this node: no workload of its VPC has registered it.
var ErrVRFNotRegistered = errors.New("eBPF registration: VRF has no uSID entry on this node")

// ErrNoEnforcement is returned by RegisterHostLink on a node that enforces or
// audits traffic policy but failed the kernel's traffic policy preflight.
var ErrNoEnforcement = errors.New("traffic policy is on but this node cannot enforce it")

// RegisterHostLink registers a host link that is enslaved to an existing
// canonical VRF, such as a Galactic Edge attachment's, with the uSID
// datapath under that VRF's own uSID entry: it allocates no Argument. It
// writes the link's traffic policy row, with addr as its only address, and
// its ifindex_vrf_table and ifindex_egress_kind_table rows, then attaches
// usid_egress to its tc ingress and tp_deliver to its tc egress. Where the
// VRF has more than one entry, the lowest Argument is used, so every call
// picks the same one.
//
// The policy row carries a new policy token unless the link already has
// one, so a repeated registration keeps the snapshots galactic-router bound
// to it. Until galactic-router binds them, the link denies everything while
// the node enforces. On such a node, RegisterHostLink refuses a kernel that
// failed the preflight (ErrNoEnforcement) and reads every enforcement program
// back from the link before returning, so a caller that brings the link up
// only after it returns never carries an unchecked packet.
func RegisterHostLink(pinDir string, vrfTableID uint32, ifindex uint32, ifname string, addr netip.Addr) error {
	return RegisterHostLinkKind(pinDir, vrfTableID, ifindex, ifname, addr, tpmap.KindTenant)
}

// RegisterHostLinkKind is RegisterHostLink with the link's traffic policy
// kind. tpmap.KindTenant writes a tenant row as RegisterHostLink describes.
// tpmap.KindInfra writes an infra row, which the datapath never evaluates,
// replacing any tenant row the ifindex had; addr is then unused, and the
// kernel's traffic policy preflight is not required. Any other kind is an
// error.
func RegisterHostLinkKind(pinDir string, vrfTableID uint32, ifindex uint32, ifname string, addr netip.Addr,
	kind uint32) error {
	if kind != tpmap.KindTenant && kind != tpmap.KindInfra {
		return fmt.Errorf("register host link %q: unknown traffic policy kind %d", ifname, kind)
	}
	key, err := hostLinkVRFKey(pinDir, vrfTableID)
	if err != nil {
		return err
	}
	var active bool
	if kind == tpmap.KindInfra {
		err = putHostLinkInfra(pinDir, ifindex)
	} else {
		active, err = putHostLinkPolicy(pinDir, ifindex, addr)
	}
	if err != nil {
		return err
	}

	table, tableCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = tableCloser.Close() }()
	if err := table.Register(ifindex, key.Block, key.Argument); err != nil {
		return fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}
	if err := registerEgressKind(pinDir, ifindex, usidmap.EgressKindVeth); err != nil {
		return err
	}
	if err := attachUsidEgress(pinDir, ifname); err != nil {
		return fmt.Errorf("attach eBPF usid_egress to host interface %q: %w", ifname, err)
	}
	// tp_deliver checks what the kernel itself transmits to the link: the
	// traffic policy, and an edge link's forwarding gate.
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.TpDeliverPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned tp_deliver: %w", err)
	}
	defer func() { _ = program.Close() }()
	if err := attach.AttachDeliver(program, ifname); err != nil {
		return fmt.Errorf("attach eBPF tp_deliver to host interface %q: %w", ifname, err)
	}
	if active {
		return verifyEnforcement(ifname)
	}
	return nil
}

// hostLinkVRFKey returns the vrf_table key a host link in Linux VRF table
// vrfTableID registers under: the table's entry with the lowest Argument. It
// returns ErrVRFNotRegistered when the table has none.
func hostLinkVRFKey(pinDir string, vrfTableID uint32) (usidmap.VRFKey, error) {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return usidmap.VRFKey{}, fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()
	entries, err := registry.VRF.List()
	if err != nil {
		return usidmap.VRFKey{}, fmt.Errorf("list eBPF vrf_table: %w", err)
	}
	var found bool
	var key usidmap.VRFKey
	argument := uint16(math.MaxUint16)
	for _, e := range entries {
		if e.VRFTableID == vrfTableID && e.Argument < argument {
			key, argument, found = e.VRFKey, e.Argument, true
		}
	}
	if !found {
		return usidmap.VRFKey{}, fmt.Errorf("%w: table %d", ErrVRFNotRegistered, vrfTableID)
	}
	return key, nil
}

// putHostLinkInfra writes ifindex's infra traffic policy row, removing a
// tenant row the ifindex had first. A node without the policy maps has none
// to write.
func putHostLinkInfra(pinDir string, ifindex uint32) error {
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open pinned traffic policy maps: %w", err)
	}
	defer maps.Close()
	var row prog.UsidTpIfaceValue
	if err := maps.Interfaces.Lookup(ifindex, &row); err == nil && row.Kind == tpmap.KindInfra {
		return nil
	} else if err == nil {
		if err := maps.RemoveInterface(ifindex); err != nil {
			return err
		}
	}
	return maps.PutInfra(ifindex)
}

// HostLinkRegistered reports whether ifindex, named ifname, carries
// everything RegisterHostLinkKind writes for it under Linux VRF table
// vrfTableID with traffic policy kind: its ifindex_vrf_table row naming the
// table's vrf_table key, its ifindex_egress_kind_table row, a traffic policy
// row of kind, the egress chain on its tc ingress and tp_deliver on its tc
// egress. A table with no vrf_table entry reports false.
func HostLinkRegistered(pinDir string, vrfTableID uint32, ifindex uint32, ifname string, kind uint32) (bool, error) {
	key, err := hostLinkVRFKey(pinDir, vrfTableID)
	if errors.Is(err, ErrVRFNotRegistered) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	table, closer, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	row, ok, err := table.Get(ifindex)
	_ = closer.Close()
	if err != nil || !ok || row.Block != key.Block || row.Argument != key.Argument {
		return false, err
	}
	kinds, kindCloser, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF ifindex_egress_kind_table: %w", err)
	}
	_, ok, err = kinds.Get(ifindex)
	_ = kindCloser.Close()
	if err != nil || !ok {
		return false, err
	}
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned traffic policy maps: %w", err)
	}
	var tp prog.UsidTpIfaceValue
	err = maps.Interfaces.Lookup(ifindex, &tp)
	maps.Close()
	if errors.Is(err, ebpf.ErrKeyNotExist) || (err == nil && tp.Kind != kind) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read tp_iface_table[%d]: %w", ifindex, err)
	}
	if ok, err := attach.HasDeliver(ifname); err != nil || !ok {
		return false, err
	}
	return attach.HasEgressChain(ifname)
}

// HostLinkPresent reports whether ifindex, named ifname, carries any row or
// program RegisterHostLinkKind writes.
func HostLinkPresent(pinDir string, ifindex uint32, ifname string) (bool, error) {
	if ok, err := attach.HasAnyEgress(ifname); err != nil || ok {
		return ok, err
	}
	if table, closer, err := ifindexvrfmap.OpenPinned(pinDir); err == nil {
		_, ok, err := table.Get(ifindex)
		_ = closer.Close()
		if err != nil || ok {
			return ok, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir); err == nil {
		_, ok, err := kinds.Get(ifindex)
		_ = closer.Close()
		if err != nil || ok {
			return ok, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	maps, err := tpmap.OpenPinned(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer maps.Close()
	var tp prog.UsidTpIfaceValue
	err = maps.Interfaces.Lookup(ifindex, &tp)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	return err == nil, err
}

// DetachHostLink removes the egress programs RegisterHostLinkKind attached
// to ifname and then every row UnregisterHostLink removes for ifindex. Call
// it while the caller can still prove the ifindex is its own. A link that no
// longer exists, and absent rows, are not errors.
func DetachHostLink(pinDir string, ifindex uint32, ifname string) error {
	if err := attach.DetachEgress(ifname); err != nil {
		return fmt.Errorf("detach the egress datapath from %q: %w", ifname, err)
	}
	return UnregisterHostLink(pinDir, ifindex)
}

// putHostLinkPolicy writes ifindex's traffic policy row and addr as its
// address, and reports whether the node enforces or audits.
func putHostLinkPolicy(pinDir string, ifindex uint32, addr netip.Addr) (bool, error) {
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		return true, fmt.Errorf("open pinned traffic policy maps: %w", err)
	}
	defer maps.Close()
	state, err := maps.GetState()
	if err != nil {
		return true, err
	}
	active := state.Mode != tpmap.ModeOff
	if active && !state.Capable {
		return true, fmt.Errorf("%w: the kernel failed the traffic policy preflight", ErrNoEnforcement)
	}
	var row prog.UsidTpIfaceValue
	token := uint64(0)
	if err := maps.Interfaces.Lookup(ifindex, &row); err == nil && row.Kind == tpmap.KindTenant {
		token = row.PolicyToken
	}
	if token == 0 {
		if token, err = tpmap.NewPolicyToken(); err != nil {
			return active, err
		}
	}
	if err := maps.PutInterface(ifindex, token, tpmap.KindTenant); err != nil {
		return active, err
	}
	return active, maps.PutInterfaceAddr(ifindex, addr)
}

// verifyEnforcement reads usid_egress and tp_deliver back from ifname's tc
// hooks.
func verifyEnforcement(ifname string) error {
	ok, err := attach.HasDeliver(ifname)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("tp_deliver is not attached to %s", ifname)
	}
	if ok, err = attach.HasEgressChain(ifname); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the egress programs are not attached to %s", ifname)
	}
	return nil
}

// UnregisterHostLink removes every per-ifindex row RegisterHostLink wrote for
// ifindex, and the link's traffic policy rows. Call it before deleting the
// link, while the caller can still prove the ifindex is its own: a later link
// may reuse the number. Absent maps and rows are not errors.
func UnregisterHostLink(pinDir string, ifindex uint32) error {
	var errs []error
	// A map that is not pinned holds no row; any other failure to open one
	// may leave a row behind, so it is reported.
	opened := func(err error) bool {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
		return err == nil
	}
	if table, closer, err := ifindexvrfmap.OpenPinned(pinDir); opened(err) {
		errs = append(errs, table.Unregister(ifindex))
		_ = closer.Close()
	}
	if kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir); opened(err) {
		errs = append(errs, kinds.Unregister(ifindex))
		_ = closer.Close()
	}
	errs = append(errs, tpmap.RemovePinnedInterface(pinDir, ifindex))
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("unregister eBPF rows of ifindex %d: %w", ifindex, err)
	}
	return nil
}

// SyncHostLinkRoutes makes the pass-through entries egressroutemap.PassThroughEdge
// owns in Linux VRF table vrfTableID, in the egress_route_table pinned under
// pinDir, exactly want. A caller passes the address of every edge host link in
// the VRF and every prefix of a route one of them holds, open gate or not.
// Absent from the table, a workload of the VRF on this node would match the
// VRF's ::/0 shard route for them, since galactic-router installs no route for
// its own node's advertisements, and its packets would leave as public egress.
// As pass-through entries they reach the kernel, which routes an open prefix
// to the host link, where tp_deliver applies the link's gates, and drops a
// closed one, which has no host route, at the VRF's unreachable default.
//
// A wanted prefix that already has a pass-through entry of another owner is
// left as it is: it already reaches the kernel, and its owner removes it. Only
// this owner's entries are removed. An encapsulating entry for a wanted prefix,
// which only a holder on another node can have left, is replaced, and
// galactic-router's withdrawal of that remote route (srv6.RouteEgressDel)
// keeps this owner's entry.
func SyncHostLinkRoutes(pinDir string, vrfTableID uint32, want []netip.Prefix) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return syncHostLinkRoutesIn(table, vrfTableID, want)
}

func syncHostLinkRoutesIn(table *egressroutemap.EgressRouteTable, vrfTableID uint32, want []netip.Prefix) error {
	entries, err := table.Entries(vrfTableID)
	if err != nil {
		return err
	}
	wanted := map[netip.Prefix]bool{}
	var errs []error
	for _, p := range want {
		p = p.Masked()
		wanted[p] = true
		if e, ok := entries[p]; ok && e.PassThrough && e.Owner != egressroutemap.PassThroughEdge {
			continue
		}
		if err := table.RegisterPassThroughAs(vrfTableID, prefixIPNet(p), egressroutemap.PassThroughEdge); err != nil {
			errs = append(errs, err)
		}
	}
	for p, e := range entries {
		if wanted[p] || !e.PassThrough || e.Owner != egressroutemap.PassThroughEdge {
			continue
		}
		if _, err := table.UnregisterPassThroughAs(vrfTableID, prefixIPNet(p), egressroutemap.PassThroughEdge); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func prefixIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
