// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vipxlatmap implements the read/write API for the eBPF uSID
// datapath's vip_xlat_table map (usid.c's struct vip_xlat_key/
// vip_xlat_value) -- the DSR/Maglev redesign's VIP-boundary substitution
// (design plan §0.1, §2), originally built for the tap-backend case but
// now driven by ServiceVIPBindingReconciler
// (internal/controller/servicevipbinding_controller.go) for EgressKindVeth
// too: a decapsulated ingress packet is delivered into the owning
// tenant's own VRF routing table, which has no route to a veth binding's
// address on internal/plumbing/vip's root-namespace dummy interface --
// found live in containerlab (see ServiceVIPBindingReconciler's own doc
// comment) -- and this package's ingress row, run unconditionally by
// usid_ingress whenever a matching entry exists, rewrites the destination
// to the backend's real, already-routed address before that VRF lookup
// happens, closing exactly that gap. Mirrors
// internal/plumbing/ebpf/usidmap's own Register/Unregister/Get/List/
// Reconcile shape for vrf_table.
//
// # Two independent rows per binding
//
// usid.c's struct vip_xlat_key doc comment describes vip_xlat_table's
// direction convention precisely: the *ingress*-direction lookup (in
// usid_ingress, on a client's inbound request) keys on the packet's own
// destination port -- the VIP port a client dialed -- and rewrites the
// packet's destination to the backend's real address:port; the
// *egress*-direction lookup (in usid_egress, on the backend's own reply)
// keys on the packet's own source port -- the backend's real port -- and
// rewrites the packet's source back to the VIP's address:port. These are
// two independent map entries, not a single symmetric pair sharing one key:
// RegisterIngress and RegisterEgress each write exactly one row, with
// reversed key/value roles (RegisterIngress keys on the VIP port and values
// the backend address:port; RegisterEgress keys on the backend port and
// values the VIP address:port).
//
// # No on-disk generation field, unlike vrf_table
//
// usidmap.VRFTable's crash-safety Generation convention (see usidmap's own
// doc comment, "The plugin-binary-vs-run-container race") relies on a
// generation field stored directly in vrf_table's own kernel value struct
// (prog.UsidVrfValue.Generation), so it survives a control-daemon restart.
// struct vip_xlat_value (usid.c) has no equivalent field -- it is a bare
// `{addr[16], port}` substitution target with no spare bytes for one, and
// this package does not modify usid.c to add one (that file is a shared,
// already-verified eBPF program; changing its value layout is out of this
// package's scope). Generation/Reconcile below are therefore backed by an
// in-memory, per-process map instead of a kernel-stored field: Reconcile
// still protects against the intra-process race (a Register call landing
// between a caller's live-snapshot and its own Reconcile call, within the
// same running reconciler process -- the scenario GC-style sweeps care
// about day to day), but a process restart resets the tracked generations
// to unknown (surfaced as Generation 0 on every pre-existing entry), so
// immediately after a restart Reconcile can only safely trust the caller's
// live set, not an entry's staleness history. This is an accepted, smaller
// guarantee than VRFTable's, forced by struct vip_xlat_value's fixed
// layout -- see this package's own tests for the exact behavior.
package vipxlatmap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// Supported transport protocols -- the only two vip_xlat_table's rewrite
// path is ever consulted for (usid_ingress/usid_egress both gate the
// vip_xlat_table lookup behind `nexthdr == USID_IPPROTO_TCP ||
// USID_IPPROTO_UDP`, usid.c). Register rejects any other proto value
// outright rather than silently writing a kernel entry the datapath can
// never reach.
const (
	ProtoTCP = uint8(unix.IPPROTO_TCP)
	ProtoUDP = uint8(unix.IPPROTO_UDP)
)

// Key identifies one vip_xlat_table row exactly as the kernel key is
// composed (usid.c's struct vip_xlat_key): Block/Argument identify the
// tenant VRF (same composition as vrf_table's own key), Proto is the
// transport protocol, and Port is direction-dependent -- see this
// package's doc comment. Port is host order here; RegisterIngress/
// RegisterEgress/Get/List/Reconcile all convert to/from the kernel's
// wire-order representation internally (see hostToNetwork16).
type Key struct {
	Block    uint64
	Argument uint16
	Proto    uint8
	Port     uint16
}

// Entry is one fully decoded vip_xlat_table row, decoupled from
// prog.UsidVipXlatKey/Value's cilium/ebpf/BTF-generated layout so callers
// outside this package don't need to import prog or cilium/ebpf directly.
type Entry struct {
	Key

	// Addr is the rewrite target's address (backend for an ingress-direction
	// row, VIP for an egress-direction row).
	Addr net.IP

	// RewritePort is the rewrite target's port (host order), paired with
	// Addr.
	RewritePort uint16

	// Generation is this table wrapper's own in-memory registration
	// sequence number (see the package doc comment) -- 0 for any entry this
	// process did not itself Register (e.g. one pinned by a previous
	// process incarnation, discovered only via List/Get).
	Generation uint64
}

// VipXlatTable is the read/write API for vip_xlat_table.
type VipXlatTable struct {
	table usidmap.Table
	clock func() uint64

	mu          sync.Mutex
	generations map[prog.UsidVipXlatKey]uint64
}

// NewVipXlatTable wraps table as a VipXlatTable. Production callers pass a
// usidmap.KernelTable wrapping a loaded vip_xlat_table map (see
// OpenPinnedVipXlatTable); tests pass a fake usidmap.Table.
func NewVipXlatTable(table usidmap.Table) *VipXlatTable {
	return &VipXlatTable{
		table:       table,
		clock:       monotonicNow,
		generations: make(map[prog.UsidVipXlatKey]uint64),
	}
}

// Generation returns a snapshot of this table's own in-memory monotonic
// clock -- see the package doc comment for how this differs from
// usidmap.VRFTable.Generation.
func (t *VipXlatTable) Generation() uint64 {
	return t.clock()
}

// validateProto returns an error unless proto is ProtoTCP or ProtoUDP.
func validateProto(proto uint8) error {
	if proto != ProtoTCP && proto != ProtoUDP {
		return fmt.Errorf(
			"vipxlatmap: vip_xlat_table: proto %d is not tcp (%d) or udp (%d) -- "+
				"usid_ingress/usid_egress never consult vip_xlat_table for any other protocol",
			proto, ProtoTCP, ProtoUDP)
	}
	return nil
}

// validatePort returns an error if port is the reserved-invalid value 0.
func validatePort(port uint16) error {
	if port == 0 {
		return errors.New("vipxlatmap: vip_xlat_table: port 0 is never a valid TCP/UDP port")
	}
	return nil
}

// addrTo16 returns addr's raw 16 bytes in wire order, or an error if addr is
// not a genuine IPv6 address. Both usid_ingress's inner-packet path and
// usid_egress are IPv6-only by design (usid_egress's own doc comment: "IPv6
// only (component 2/0.1 are both IPv6-only by design)"), so an IPv4
// (or IPv4-mapped) address is rejected here rather than silently truncated
// or zero-padded into something the datapath would misinterpret.
func addrTo16(addr net.IP) ([16]byte, error) {
	if addr == nil {
		return [16]byte{}, errors.New("vipxlatmap: vip_xlat_table: address is nil")
	}
	a, ok := netip.AddrFromSlice(addr)
	if !ok {
		return [16]byte{}, fmt.Errorf("vipxlatmap: vip_xlat_table: %v is not a valid IP address", addr)
	}
	a = a.Unmap()
	if !a.Is6() {
		return [16]byte{}, fmt.Errorf(
			"vipxlatmap: vip_xlat_table: %s is not a 16-byte IPv6 address (the tap-VIP substitution is IPv6-only)", a)
	}
	return a.As16(), nil
}

// directionIngress/directionEgress mirror usid.c's
// USID_VIP_XLAT_DIR_INGRESS/USID_VIP_XLAT_DIR_EGRESS -- the byte value the
// kernel key's Direction field must carry so usid_ingress's and
// usid_egress's own, direction-fixed key constructions ever find the row
// each is looking for. Needed because (block, argument, proto, port) alone
// is not always unique: a binding that keeps the same port number on both
// the VIP and the backend (an unremarkable, common case, not a rare one --
// found live in containerlab, ns60's binding uses port 80 both ways) would
// otherwise collapse the ingress and egress rows into the same map entry,
// silently losing whichever was registered first. This package's own
// exported API stays direction-implicit (RegisterIngress/RegisterEgress/
// UnregisterIngress/UnregisterEgress/GetIngress/GetEgress each hard-code
// the direction their own name implies) -- only the kernel key construction
// below needs the actual byte value.
const (
	directionIngress = uint8(0)
	directionEgress  = uint8(1)
)

// register is the shared primitive RegisterIngress/RegisterEgress build
// their (key, value) pair around. keyPort is the port this row's kernel key
// is composed with (direction-dependent -- see the package doc comment);
// valAddr/valPort are the rewrite target this row substitutes in.
func (t *VipXlatTable) register(
	direction uint8, block uint64, argument uint16, proto uint8, keyPort uint16, valAddr net.IP, valPort uint16,
) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: %w", err)
	}
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: %w", err)
	}
	if err := validateProto(proto); err != nil {
		return err
	}
	if err := validatePort(keyPort); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: key port: %w", err)
	}
	if err := validatePort(valPort); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: rewrite port: %w", err)
	}
	rawAddr, err := addrTo16(valAddr)
	if err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: rewrite address: %w", err)
	}

	key := prog.UsidVipXlatKey{
		Block:     block,
		Argument:  argument,
		Proto:     proto,
		Direction: direction,
		Port:      hostToNetwork16(keyPort),
	}
	value := prog.UsidVipXlatValue{
		Addr: rawAddr,
		Port: hostToNetwork16(valPort),
	}
	if err := t.table.Put(key, value); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register block=%#x argument=%#x proto=%d port=%d: %w",
			block, argument, proto, keyPort, err)
	}

	t.mu.Lock()
	t.generations[key] = t.clock()
	t.mu.Unlock()
	return nil
}

// RegisterIngress writes vip_xlat_table's ingress-direction row for one
// ServiceVIPBinding: keyed on (block, argument, proto, vipPort) -- the
// packet's own destination port on a client's inbound request, per
// usid_ingress's lookup -- and rewriting to backendAddr:backendPort.
//
// vipAddr is accepted for call-site symmetry with RegisterEgress and with
// ServiceVIPBindingSpec's own field set (so a caller can pass the binding's
// VIPAddress/Port/BackendAddress/BackendPort straight through in the order
// they appear on the CRD) and is validated for family consistency with
// backendAddr, but it is not itself part of the kernel key or value:
// usid.c's struct vip_xlat_key carries no address field at all (only
// Proto+Port), and the ingress row's value is backendAddr:backendPort, not
// vipAddr.
func (t *VipXlatTable) RegisterIngress(
	block uint64, argument uint16, proto uint8,
	vipAddr net.IP, vipPort uint16,
	backendAddr net.IP, backendPort uint16,
) error {
	if _, err := addrTo16(vipAddr); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register ingress: vip address: %w", err)
	}
	return t.register(directionIngress, block, argument, proto, vipPort, backendAddr, backendPort)
}

// RegisterEgress writes vip_xlat_table's egress-direction row for one
// ServiceVIPBinding: keyed on (block, argument, proto, backendPort) -- the
// packet's own source port on the backend's own reply, per usid_egress's
// lookup -- and rewriting to vipAddr:vipPort. See RegisterIngress's doc
// comment for why backendAddr is accepted but not itself part of the
// kernel key.
func (t *VipXlatTable) RegisterEgress(
	block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16,
	vipAddr net.IP, vipPort uint16,
) error {
	if _, err := addrTo16(backendAddr); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register egress: backend address: %w", err)
	}
	return t.register(directionEgress, block, argument, proto, backendPort, vipAddr, vipPort)
}

// unregister removes the vip_xlat_table entry keyed by (direction, block,
// argument, proto, port), if present. Not an error if already absent,
// mirroring usidmap.VRFTable.Unregister's identical idempotency contract.
func (t *VipXlatTable) unregister(direction uint8, block uint64, argument uint16, proto uint8, port uint16) error {
	key := prog.UsidVipXlatKey{
		Block:     block,
		Argument:  argument,
		Proto:     proto,
		Direction: direction,
		Port:      hostToNetwork16(port),
	}
	if err := t.table.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("vipxlatmap: vip_xlat_table: unregister block=%#x argument=%#x proto=%d port=%d: %w",
			block, argument, proto, port, err)
	}
	t.mu.Lock()
	delete(t.generations, key)
	t.mu.Unlock()
	return nil
}

// UnregisterIngress removes the ingress-direction row RegisterIngress
// would have written for (block, argument, proto, vipPort).
func (t *VipXlatTable) UnregisterIngress(block uint64, argument uint16, proto uint8, vipPort uint16) error {
	return t.unregister(directionIngress, block, argument, proto, vipPort)
}

// UnregisterEgress removes the egress-direction row RegisterEgress would
// have written for (block, argument, proto, backendPort).
func (t *VipXlatTable) UnregisterEgress(block uint64, argument uint16, proto uint8, backendPort uint16) error {
	return t.unregister(directionEgress, block, argument, proto, backendPort)
}

// decodeEntry converts a raw kernel key/value pair into an Entry, attaching
// this table's own in-memory Generation bookkeeping for key (0 if unknown --
// see the package doc comment).
func (t *VipXlatTable) decodeEntry(key prog.UsidVipXlatKey, value prog.UsidVipXlatValue) Entry {
	t.mu.Lock()
	gen := t.generations[key]
	t.mu.Unlock()

	addr := make(net.IP, 16)
	copy(addr, value.Addr[:])

	return Entry{
		Key: Key{
			Block:    key.Block,
			Argument: key.Argument,
			Proto:    key.Proto,
			Port:     hostToNetwork16(key.Port), // self-inverse: wire -> host
		},
		Addr:        addr,
		RewritePort: hostToNetwork16(value.Port), // self-inverse: wire -> host
		Generation:  gen,
	}
}

// GetIngress reads the ingress-direction vip_xlat_table entry for (block,
// argument, proto, vipPort) -- the row RegisterIngress would have written --
// reporting whether it exists.
func (t *VipXlatTable) GetIngress(block uint64, argument uint16, proto uint8, vipPort uint16) (Entry, bool, error) {
	return t.get(directionIngress, block, argument, proto, vipPort)
}

// GetEgress reads the egress-direction vip_xlat_table entry for (block,
// argument, proto, backendPort) -- the row RegisterEgress would have
// written -- reporting whether it exists.
func (t *VipXlatTable) GetEgress(block uint64, argument uint16, proto uint8, backendPort uint16) (Entry, bool, error) {
	return t.get(directionEgress, block, argument, proto, backendPort)
}

// get is GetIngress/GetEgress's shared primitive.
func (t *VipXlatTable) get(
	direction uint8, block uint64, argument uint16, proto uint8, port uint16,
) (Entry, bool, error) {
	key := prog.UsidVipXlatKey{
		Block:     block,
		Argument:  argument,
		Proto:     proto,
		Direction: direction,
		Port:      hostToNetwork16(port),
	}
	var value prog.UsidVipXlatValue
	if err := t.table.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Entry{}, false, nil
		}
		return Entry{}, false, fmt.Errorf("vipxlatmap: vip_xlat_table: get block=%#x argument=%#x proto=%d port=%d: %w",
			block, argument, proto, port, err)
	}
	return t.decodeEntry(key, value), true, nil
}

// List returns every entry currently in vip_xlat_table, in unspecified
// order. There is no way to tell an ingress-direction row apart from an
// egress-direction row purely from a raw entry -- both are just
// (block, argument, proto, port) -> (addr, port) rows to the kernel; a
// caller that needs to know which direction a given entry belongs to must
// bring that context itself (e.g. from the ServiceVIPBinding it expects to
// correspond to it).
func (t *VipXlatTable) List() ([]Entry, error) {
	var (
		entries []Entry
		key     prog.UsidVipXlatKey
		value   prog.UsidVipXlatValue
	)
	it := t.table.Iterate()
	for it.Next(&key, &value) {
		entries = append(entries, t.decodeEntry(key, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("vipxlatmap: vip_xlat_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings vip_xlat_table into agreement with live -- the caller's
// current set of Keys that should exist -- removing every entry whose Key
// is absent from live, except an entry whose Generation is >= cutoff.
//
// cutoff must be a value returned by this table's own Generation, captured
// by the caller immediately before it builds live, mirroring
// usidmap.VRFTable.Reconcile's identical contract. See the package doc
// comment for how this method's crash-safety differs from VRFTable's: an
// entry this process did not itself Register (Generation 0, e.g. one left
// by a previous process incarnation) is never treated as "too new to
// judge" by this rule alone -- only entries this process has itself
// Registered at or after the snapshot are protected. A fresh process
// should let its own reconciler re-Register every live binding before ever
// calling Reconcile, rather than relying on this method alone to preserve
// state across a restart.
func (t *VipXlatTable) Reconcile(live map[Key]struct{}, cutoff uint64) (removed []Entry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("vipxlatmap: vip_xlat_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.Key]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		// Key carries no Direction (List's own doc comment: a raw entry
		// alone can't tell an ingress row from an egress row) -- try both;
		// unregister is a no-op for whichever direction was never actually
		// registered at this exact (block, argument, proto, port), so this
		// never deletes anything that didn't already match e.
		delErr := errors.Join(
			t.unregister(directionIngress, e.Block, e.Argument, e.Proto, e.Port),
			t.unregister(directionEgress, e.Block, e.Argument, e.Proto, e.Port),
		)
		if delErr != nil {
			errs = append(errs, fmt.Errorf("vipxlatmap: vip_xlat_table: reconcile: delete stale entry %+v: %w", e.Key, delErr))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}

// hostToNetwork16 converts a host-order uint16 to the network/big-endian
// byte order struct vip_xlat_key.Port and struct vip_xlat_value.Port
// require on the wire: bpf2go generates prog.UsidVipXlatKey/Value's Port
// fields as a plain uint16 with no automatic byte-swap (mirroring
// internal/plumbing/ebpf/prog/usid_test.go's own bswap16 helper, which
// performs the identical swap for the same reason -- populating the same
// map from a test). uint16 byte-swap is its own inverse, so this same
// function also converts a wire-order value read back out of the kernel to
// host order (see decodeEntry above).
func hostToNetwork16(v uint16) uint16 { return v<<8 | v>>8 }
