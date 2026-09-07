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
// Argument identify the tenant VRF, Proto is the transport protocol, and Port
// is direction-dependent: the VIP port for an ingress row, the backend port for
// an egress row. Port is in host order here and converted internally.
type Key struct {
	Block    uint64
	Argument uint16
	Proto    uint8
	Port     uint16
}

// Entry is one decoded vip_xlat_table row, kept separate from the generated
// kernel layout so callers outside this package need not import it.
type Entry struct {
	Key

	// Addr is the rewrite target's address (backend for an ingress-direction
	// row, VIP for an egress-direction row).
	Addr net.IP

	// RewritePort is the rewrite target's port (host order), paired with
	// Addr.
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

// register is the shared primitive RegisterIngress and RegisterEgress build
// their key and value around. keyPort is the port the kernel key is composed
// with, which is direction-dependent; valAddr and valPort are the rewrite
// target the row substitutes in.
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

// RegisterIngress writes the ingress-direction row for one binding, keyed on
// (block, argument, proto, vipPort), the packet's destination port on an
// inbound request, and rewriting to backendAddr and backendPort.
//
// vipAddr is accepted for symmetry with RegisterEgress and with the CRD's field
// order, and is validated for family consistency with backendAddr, but is not
// part of the kernel key or value: the key carries no address field, and the
// ingress row's value is the backend.
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

// RegisterEgress writes the egress-direction row for one binding, keyed on
// (block, argument, proto, backendPort), the packet's source port on the
// backend's reply, and rewriting to vipAddr and vipPort. backendAddr is
// accepted but not part of the kernel key, as in RegisterIngress.
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

// unregister removes the entry keyed by (direction, block, argument, proto,
// port) if present. An entry that is already absent is not an error.
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
			Proto:    key.Proto,
			Port:     hostToNetwork16(key.Port), // self-inverse: wire -> host
		},
		Addr:        addr,
		RewritePort: hostToNetwork16(value.Port), // self-inverse: wire -> host
		Generation:  gen,
	}
}

// GetIngress reads the ingress-direction entry for (block, argument, proto,
// vipPort), the row RegisterIngress writes, and reports whether it exists.
func (t *VipXlatTable) GetIngress(block uint64, argument uint16, proto uint8, vipPort uint16) (Entry, bool, error) {
	return t.get(directionIngress, block, argument, proto, vipPort)
}

// GetEgress reads the egress-direction entry for (block, argument, proto,
// backendPort), the row RegisterEgress writes, and reports whether it exists.
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

// List returns every entry in vip_xlat_table, in unspecified order. A raw entry
// does not reveal its direction, since both are just (block, argument, proto,
// port) to (addr, port) rows, so a caller needing that must bring the context
// itself.
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

// hostToNetwork16 converts a host-order uint16 to the big-endian byte order the
// kernel key and value ports use on the wire, since the generated structs
// declare them as plain uint16 with no automatic swap. A uint16 byte swap is
// its own inverse, so this also converts a value read back out to host order.
func hostToNetwork16(v uint16) uint16 { return v<<8 | v>>8 }
