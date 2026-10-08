// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vipxlatmap implements the read/write API for the eBPF uSID
// datapath's vip_xlat_table map, which substitutes addresses at the VIP
// boundary.
//
// A decapsulated ingress packet is delivered into the owning tenant's VRF
// routing table, which has no route to a binding's address on the root
// namespace's dummy interface. The ingress row, applied whenever a matching
// entry exists, rewrites the destination to the backend's real, already-routed
// address before that lookup happens. The API mirrors usidmap's
// Register/Unregister/Get/List/Reconcile shape for vrf_table.
//
// # Two independent rows per binding
//
// The ingress lookup, on a client's inbound request, keys on the packet's
// destination port, the VIP port the client dialed, and rewrites the
// destination to the backend's address and port. The egress lookup, on the
// backend's reply, keys on the packet's source port, the backend's real port,
// and rewrites the source back to the VIP's address and port.
//
// These are two independent entries, not one symmetric pair. RegisterIngress
// and RegisterEgress each write exactly one row, with the key and value roles
// reversed.
//
// Each key carries an address as well as a port: the VIP for an ingress row,
// the backend for an egress row. Two bindings in one VRF that share a port
// therefore get their own rows, and a workload that is not a backend never
// matches an egress row. Two bindings can still claim the same row, the same
// VIP and port or the same backend and port. Deciding which one owns it is the
// caller's job, since this table has no record of who wrote a row.
//
// # Generation is per-process here, unlike vrf_table
//
// usidmap.VRFTable stores its crash-safety generation in the kernel value
// struct, so it survives a control-daemon restart. struct vip_xlat_value is a
// bare address and port with no spare bytes for one, and adding a field to the
// shared datapath program is out of this package's scope.
//
// Generation and Reconcile are therefore backed by an in-memory, per-process
// map. Reconcile still protects against the intra-process race, a Register
// landing between a caller's snapshot and its Reconcile, which is what a
// GC-style sweep needs day to day. A restart resets the tracked generations, so
// every pre-existing entry reports generation 0 and Reconcile can only trust
// the caller's live set. That is a smaller guarantee than VRFTable's, forced by
// the value layout.
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

// The transport protocols vip_xlat_table's rewrite path is consulted for. Both
// datapath programs gate the lookup on TCP or UDP, so Register rejects any
// other value rather than write an entry the datapath can never reach.
const (
	ProtoTCP = uint8(unix.IPPROTO_TCP)
	ProtoUDP = uint8(unix.IPPROTO_UDP)
)

// Key identifies one vip_xlat_table row as the kernel composes it. Block and
// Argument identify the tenant VRF and Proto is the transport protocol. Addr and
// Port are direction-dependent: the VIP's for an ingress row, the backend's for
// an egress row. Port is in host order here and converted internally.
//
// Slot is the backend slot an ingress row is keyed on, the value
// srv6.BackendSlot derives from the row's backend and galactic-gateway writes
// into the uSID it encapsulates toward that backend. It lets several backends of
// one VIP share a node and VRF, each with its own ingress row. Egress rows
// always carry Slot 0.
type Key struct {
	Block    uint64
	Argument uint16
	Slot     uint16
	Proto    uint8
	Addr     netip.Addr
	Port     uint16
}

// Entry is one decoded vip_xlat_table row, kept separate from the generated
// kernel layout so callers outside this package need not import it.
type Entry struct {
	Key

	// Direction is the lookup this row serves, which the kernel key carries
	// but Key does not.
	Direction Direction

	// RewriteAddr is the rewrite target's address (backend for an
	// ingress-direction row, VIP for an egress-direction row).
	RewriteAddr net.IP

	// RewritePort is the rewrite target's port (host order), paired with
	// RewriteAddr.
	RewritePort uint16

	// Generation is this wrapper's in-memory registration sequence number, 0
	// for any entry this process did not itself Register, such as one pinned by
	// a previous incarnation and discovered through List or Get.
	Generation uint64
}

// VipXlatTable is the read/write API for vip_xlat_table.
type VipXlatTable struct {
	table usidmap.Table
	clock func() uint64

	// writeMu serializes every write this process makes to the map, so a
	// removal that reads a row to decide ownership deletes the row it read
	// rather than one another binding registered in between. It does not
	// cover another process writing the same pinned map, such as the
	// galactic-router vip xlat CLI.
	writeMu sync.Mutex

	mu          sync.Mutex
	generations map[prog.UsidVipXlatKey]uint64
}

// NewVipXlatTable wraps table as a VipXlatTable. Production callers pass a
// kernel table over the loaded map; tests pass a fake.
func NewVipXlatTable(table usidmap.Table) *VipXlatTable {
	return &VipXlatTable{
		table:       table,
		clock:       monotonicNow,
		generations: make(map[prog.UsidVipXlatKey]uint64),
	}
}

// Generation returns a snapshot of this table's in-memory monotonic clock. See
// the package doc comment for how it differs from usidmap.VRFTable's.
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
// not a genuine IPv6 address. Both datapath paths are IPv6-only by design, so
// an IPv4 or IPv4-mapped address is rejected rather than silently truncated or
// zero-padded into something the datapath would misread.
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

// directionIngress and directionEgress mirror the datapath's direction
// constants, the byte the kernel key must carry so each program's
// direction-fixed key construction finds the row it is looking for.
//
// A direction field is needed because (block, argument, proto, port) is not
// always unique: a binding that keeps the same port number on both the VIP and
// the backend, an ordinary case, would otherwise collapse the two rows into one
// entry and silently lose whichever was registered first. The exported API
// stays direction-implicit, so only the key construction needs these values.
const (
	directionIngress = uint8(0)
	directionEgress  = uint8(1)
)

// Direction reports which lookup a decoded row serves: DirectionIngress for the
// row RegisterIngress writes, DirectionEgress for the row RegisterEgress writes.
type Direction uint8

// The two directions an Entry can report, matching the kernel key's byte.
const (
	DirectionIngress = Direction(directionIngress)
	DirectionEgress  = Direction(directionEgress)
)

// String returns "ingress", "egress", or the raw byte for any other value.
func (d Direction) String() string {
	switch d {
	case DirectionIngress:
		return "ingress"
	case DirectionEgress:
		return "egress"
	default:
		return fmt.Sprintf("direction(%d)", uint8(d))
	}
}

// register is the shared primitive RegisterIngress and RegisterEgress build
// their key and value around. keyAddr and keyPort are what the kernel key is
// composed with, which is direction-dependent; valAddr and valPort are the
// rewrite target the row substitutes in.
func (t *VipXlatTable) register(
	direction uint8, block uint64, argument, slot uint16, proto uint8,
	keyAddr net.IP, keyPort uint16, valAddr net.IP, valPort uint16,
) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

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
	key, err := kernelKey(direction, block, argument, slot, proto, keyAddr, keyPort)
	if err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: key address: %w", err)
	}
	rawAddr, err := addrTo16(valAddr)
	if err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register: rewrite address: %w", err)
	}

	value := prog.UsidVipXlatValue{
		Addr: rawAddr,
		Port: hostToNetwork16(valPort),
	}
	if err := t.table.Put(key, value); err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: register block=%#x argument=%#x slot=%#x proto=%d addr=%s port=%d: %w",
			block, argument, slot, proto, keyAddr, keyPort, err)
	}

	t.mu.Lock()
	t.generations[key] = t.clock()
	t.mu.Unlock()
	return nil
}

// RegisterIngress writes the ingress-direction row for one binding, keyed on
// (block, argument, slot, proto, vipAddr, vipPort), the packet's outer
// destination slot and inner destination on an inbound request, and rewriting
// to backendAddr and backendPort. slot is srv6.BackendSlot of the backend.
func (t *VipXlatTable) RegisterIngress(
	block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16,
	backendAddr net.IP, backendPort uint16,
) error {
	return t.register(directionIngress, block, argument, slot, proto, vipAddr, vipPort, backendAddr, backendPort)
}

// RegisterEgress writes the egress-direction row for one binding, keyed on
// (block, argument, proto, backendAddr, backendPort), the packet's source on
// the backend's reply, and rewriting to vipAddr and vipPort.
func (t *VipXlatTable) RegisterEgress(
	block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16,
	vipAddr net.IP, vipPort uint16,
) error {
	return t.register(directionEgress, block, argument, 0, proto, backendAddr, backendPort, vipAddr, vipPort)
}

// kernelKey composes the kernel key for (direction, block, argument, slot,
// proto, addr, port), returning an error if addr is not an IPv6 address.
func kernelKey(
	direction uint8, block uint64, argument, slot uint16, proto uint8, addr net.IP, port uint16,
) (prog.UsidVipXlatKey, error) {
	raw, err := addrTo16(addr)
	if err != nil {
		return prog.UsidVipXlatKey{}, err
	}
	return prog.UsidVipXlatKey{
		Block:     block,
		Argument:  argument,
		Slot:      slot,
		Proto:     proto,
		Direction: direction,
		Port:      hostToNetwork16(port),
		Addr:      raw,
	}, nil
}

// unregister removes the entry keyed by (direction, block, argument, slot,
// proto, addr, port) if present. An entry that is already absent is not an
// error. The caller holds writeMu.
func (t *VipXlatTable) unregister(
	direction uint8, block uint64, argument, slot uint16, proto uint8, addr net.IP, port uint16,
) error {
	key, err := kernelKey(direction, block, argument, slot, proto, addr, port)
	if err != nil {
		return fmt.Errorf("vipxlatmap: vip_xlat_table: unregister: %w", err)
	}
	if err := t.table.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf(
			"vipxlatmap: vip_xlat_table: unregister block=%#x argument=%#x slot=%#x proto=%d addr=%s port=%d: %w",
			block, argument, slot, proto, addr, port, err)
	}
	t.mu.Lock()
	delete(t.generations, key)
	t.mu.Unlock()
	return nil
}

// UnregisterIngress removes the ingress-direction row RegisterIngress
// would have written for (block, argument, slot, proto, vipAddr, vipPort).
func (t *VipXlatTable) UnregisterIngress(
	block uint64, argument, slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.unregister(directionIngress, block, argument, slot, proto, vipAddr, vipPort)
}

// UnregisterEgress removes the egress-direction row RegisterEgress would
// have written for (block, argument, proto, backendAddr, backendPort).
func (t *VipXlatTable) UnregisterEgress(
	block uint64, argument uint16, proto uint8, backendAddr net.IP, backendPort uint16,
) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.unregister(directionEgress, block, argument, 0, proto, backendAddr, backendPort)
}

// binding identifies the two rows one binding writes, validated and in the
// raw form the map stores. slot is the ingress row's backend slot.
type binding struct {
	slot        uint16
	proto       uint8
	vip         [16]byte
	vipPort     uint16
	backend     [16]byte
	backendPort uint16
}

// newBinding validates a binding's protocol and addresses.
func newBinding(
	slot uint16, proto uint8, vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) (binding, error) {
	if err := validateProto(proto); err != nil {
		return binding{}, err
	}
	rawVIP, err := addrTo16(vipAddr)
	if err != nil {
		return binding{}, fmt.Errorf("vipxlatmap: vip_xlat_table: unregister binding: vip address: %w", err)
	}
	rawBackend, err := addrTo16(backendAddr)
	if err != nil {
		return binding{}, fmt.Errorf("vipxlatmap: vip_xlat_table: unregister binding: backend address: %w", err)
	}
	return binding{
		slot: slot, proto: proto, vip: rawVIP, vipPort: vipPort, backend: rawBackend, backendPort: backendPort,
	}, nil
}

// isIngressRow reports whether e is the ingress row b writes: keyed on b's
// slot, VIP and port, and rewriting to b's backend and port.
func (b binding) isIngressRow(e Entry) bool {
	return e.Direction == DirectionIngress && e.Slot == b.slot && e.Proto == b.proto &&
		e.Addr == netip.AddrFrom16(b.vip) && e.Port == b.vipPort &&
		[16]byte(e.RewriteAddr) == b.backend && e.RewritePort == b.backendPort
}

// isEgressRow reports whether e is the egress row b writes: keyed on b's
// backend and port, and rewriting to b's VIP and port.
func (b binding) isEgressRow(e Entry) bool {
	return e.Direction == DirectionEgress && e.Slot == 0 && e.Proto == b.proto &&
		e.Addr == netip.AddrFrom16(b.backend) && e.Port == b.backendPort &&
		[16]byte(e.RewriteAddr) == b.vip && e.RewritePort == b.vipPort
}

// removeAt removes b's rows at (block, argument), reading each one first and
// deleting it only if it still rewrites to b's values. Another binding that
// claims the same key, the same VIP and port or the same backend and port,
// and has since written its own values there keeps its row.
//
// A binding with exactly b's values writes exactly b's rows, so this cannot
// tell the two apart. Callers that know of such a binding must not call it.
//
// The caller holds writeMu.
func (t *VipXlatTable) removeAt(block uint64, argument uint16, b binding) ([]Entry, error) {
	var removed []Entry

	ingress, found, err := t.get(directionIngress, block, argument, b.slot, b.proto, net.IP(b.vip[:]), b.vipPort)
	if err != nil {
		return nil, err
	}
	if found && b.isIngressRow(ingress) {
		if err := t.unregister(directionIngress, block, argument, b.slot, b.proto, net.IP(b.vip[:]), b.vipPort); err != nil {
			return nil, err
		}
		removed = append(removed, ingress)
	}

	egress, found, err := t.get(directionEgress, block, argument, 0, b.proto, net.IP(b.backend[:]), b.backendPort)
	if err != nil {
		return removed, err
	}
	if found && b.isEgressRow(egress) {
		backend := net.IP(b.backend[:])
		if err := t.unregister(directionEgress, block, argument, 0, b.proto, backend, b.backendPort); err != nil {
			return removed, err
		}
		removed = append(removed, egress)
	}
	return removed, nil
}

// UnregisterBinding removes the rows one binding wrote, wherever they sit,
// without the caller supplying the block or argument. It returns the rows it
// removed.
//
// It exists for teardown after the binding's VRF has left the node, when the
// (block, argument) pair can no longer be derived from the node's BGP objects.
// Every row that is exactly one of the binding's two rows, by key and by value,
// marks a location, and removeAt removes the binding's rows there.
func (t *VipXlatTable) UnregisterBinding(
	slot uint16, proto uint8, vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) ([]Entry, error) {
	b, err := newBinding(slot, proto, vipAddr, vipPort, backendAddr, backendPort)
	if err != nil {
		return nil, err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("vipxlatmap: vip_xlat_table: unregister binding: %w", err)
	}

	type location struct {
		block    uint64
		argument uint16
	}
	seen := make(map[location]struct{})
	var (
		removed []Entry
		errs    []error
	)
	for _, e := range entries {
		if !b.isIngressRow(e) && !b.isEgressRow(e) {
			continue
		}
		loc := location{e.Block, e.Argument}
		if _, ok := seen[loc]; ok {
			continue
		}
		seen[loc] = struct{}{}
		rows, err := t.removeAt(e.Block, e.Argument, b)
		removed = append(removed, rows...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}

// UnregisterBindingAt removes the rows one binding wrote at a known (block,
// argument), with the same value checks as UnregisterBinding. It returns the
// rows it removed.
func (t *VipXlatTable) UnregisterBindingAt(
	block uint64, argument, slot uint16,
	proto uint8, vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) ([]Entry, error) {
	b, err := newBinding(slot, proto, vipAddr, vipPort, backendAddr, backendPort)
	if err != nil {
		return nil, err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.removeAt(block, argument, b)
}

// decodeEntry converts a raw kernel key and value into an Entry, attaching this
// table's in-memory generation for that key, or 0 when unknown.
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
			Slot:     key.Slot,
			Proto:    key.Proto,
			Addr:     netip.AddrFrom16(key.Addr),
			Port:     hostToNetwork16(key.Port), // self-inverse: wire -> host
		},
		Direction:   Direction(key.Direction),
		RewriteAddr: addr,
		RewritePort: hostToNetwork16(value.Port), // self-inverse: wire -> host
		Generation:  gen,
	}
}

// GetIngress reads the ingress-direction entry for (block, argument, slot,
// proto, vipAddr, vipPort), the row RegisterIngress writes, and reports whether
// it exists.
func (t *VipXlatTable) GetIngress(
	block uint64, argument, slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
) (Entry, bool, error) {
	return t.get(directionIngress, block, argument, slot, proto, vipAddr, vipPort)
}

// GetEgress reads the egress-direction entry for (block, argument, proto,
// backendAddr, backendPort), the row RegisterEgress writes, and reports whether
// it exists.
func (t *VipXlatTable) GetEgress(
	block uint64, argument uint16, proto uint8, backendAddr net.IP, backendPort uint16,
) (Entry, bool, error) {
	return t.get(directionEgress, block, argument, 0, proto, backendAddr, backendPort)
}

// get is GetIngress/GetEgress's shared primitive.
func (t *VipXlatTable) get(
	direction uint8, block uint64, argument, slot uint16, proto uint8, addr net.IP, port uint16,
) (Entry, bool, error) {
	key, err := kernelKey(direction, block, argument, slot, proto, addr, port)
	if err != nil {
		return Entry{}, false, fmt.Errorf("vipxlatmap: vip_xlat_table: get: %w", err)
	}
	var value prog.UsidVipXlatValue
	if err := t.table.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Entry{}, false, nil
		}
		return Entry{}, false, fmt.Errorf(
			"vipxlatmap: vip_xlat_table: get block=%#x argument=%#x slot=%#x proto=%d addr=%s port=%d: %w",
			block, argument, slot, proto, addr, port, err)
	}
	return t.decodeEntry(key, value), true, nil
}

// List returns every entry in vip_xlat_table, in unspecified order, each with
// the direction its key carries.
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

// Reconcile brings vip_xlat_table into agreement with live, the caller's
// current set of keys, removing every entry whose key is absent from live
// unless its generation is at or above cutoff. It returns the entries removed.
//
// cutoff must come from this table's Generation, captured immediately before
// the caller builds live.
//
// Only entries this process itself registered at or after the snapshot are
// protected. An entry left by a previous incarnation reports generation 0 and
// is not treated as too new to judge, so a fresh process should let its
// reconciler re-register every live binding before calling this.
func (t *VipXlatTable) Reconcile(live map[Key]struct{}, cutoff uint64) (removed []Entry, err error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

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
		// Key carries no direction, so try both. unregister is a no-op for
		// whichever direction was never registered at this exact key, so this
		// never deletes anything that did not already match e.
		addr := net.IP(e.Addr.AsSlice())
		delErr := errors.Join(
			t.unregister(directionIngress, e.Block, e.Argument, e.Slot, e.Proto, addr, e.Port),
			t.unregister(directionEgress, e.Block, e.Argument, e.Slot, e.Proto, addr, e.Port),
		)
		if delErr != nil {
			errs = append(errs, fmt.Errorf("vipxlatmap: vip_xlat_table: reconcile: delete stale entry %+v: %w", e.Key, delErr))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}

// hostToNetwork16 converts a host-order uint16 to the big-endian byte order the
// kernel key and value ports use on the wire, since the generated structs
// declare them as plain uint16 with no automatic swap. A uint16 byte swap is
// its own inverse, so this also converts a value read back out to host order.
func hostToNetwork16(v uint16) uint16 { return v<<8 | v>>8 }
