// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6map

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/nptv6"
)

// NPTv6Key identifies one nptv6_table row: the uSID Block that matched in
// locator_table plus the 12-bit Argument. The same composition usidmap.VRFKey
// uses, kept as its own type so a caller need not import that package just to
// build a key.
type NPTv6Key struct {
	Block    uint64
	Argument uint16
}

// NPTv6Entry is one decoded nptv6_table row, kept separate from the generated
// kernel layout, as usidmap.VRFEntry is.
type NPTv6Entry struct {
	NPTv6Key

	// Mapping is the RFC 6296 prefix pair this entry applies -- see
	// internal/plumbing/nptv6's doc comment for the translation itself.
	Mapping nptv6.Mapping

	// Adjustment is the precomputed RFC 6296 checksum-neutral adjustment, stored
	// in the kernel value so the datapath never recomputes it per packet.
	Adjustment uint16

	// Generation is this process's in-memory record of when Register last wrote
	// this entry. See the package doc comment for why it is not persisted in
	// the kernel value the way vrf_table's is.
	Generation uint64
}

// NPTv6Table is the read/write API for nptv6_table.
type NPTv6Table struct {
	table usidmap.Table
	clock func() uint64

	mu         sync.Mutex
	generation map[NPTv6Key]uint64
}

// NewNPTv6Table wraps table as an NPTv6Table. Production callers pass a kernel
// table over the loaded map, or use OpenPinned in a process that did not load
// the datapath; tests pass a fake.
func NewNPTv6Table(table usidmap.Table) *NPTv6Table {
	return &NPTv6Table{table: table, clock: monotonicNow, generation: make(map[NPTv6Key]uint64)}
}

// OpenPinned opens nptv6_table from its pinned path under pinDir and returns an
// NPTv6Table wrapping it, for a process that did not itself load the datapath
// but needs to read and write this one map. The returned map must be closed
// when the caller is done, which does not affect its pinned lifetime.
func OpenPinned(pinDir string) (*NPTv6Table, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapNptv6Table), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("nptv6map: open pinned map %q: %w", prog.UsidMapNptv6Table, err)
	}
	return NewNPTv6Table(usidmap.KernelTable{Map: m}), m, nil
}

// Generation returns a snapshot of this table's monotonic clock -- see
// doc.go for why this is process-local rather than kernel-persisted.
func (t *NPTv6Table) Generation() uint64 {
	return t.clock()
}

// Register writes, or overwrites, the nptv6_table entry for (block, argument).
// It computes the adjustment from m and converts m's prefixes into the fixed
// 16-byte zero-padded arrays the kernel value expects, which parsed CIDRs
// already are beyond their own prefix length.
//
// There is no read-modify-write step, unlike vrf_table's Register: this table
// carries no per-entry counters to preserve, so every call is a plain
// overwrite.
func (t *NPTv6Table) Register(block uint64, argument uint16, m nptv6.Mapping) error {
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: register block=%#x argument=%#x: %w", block, argument, err)
	}
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: register block=%#x argument=%#x: %w", block, argument, err)
	}

	adjustment, err := m.Adjustment()
	if err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: register block=%#x argument=%#x: compute adjustment: %w",
			block, argument, err)
	}
	value, err := toValue(m, adjustment)
	if err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: register block=%#x argument=%#x: %w", block, argument, err)
	}

	if err := t.table.Put(uint64(key), value); err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: register block=%#x argument=%#x: %w", block, argument, err)
	}

	nk := NPTv6Key{Block: block, Argument: argument}
	t.mu.Lock()
	t.generation[nk] = t.clock()
	t.mu.Unlock()
	return nil
}

// Unregister removes the nptv6_table entry for (block, argument) if present. An
// already-absent entry is not an error.
func (t *NPTv6Table) Unregister(block uint64, argument uint16) error {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("nptv6map: nptv6_table: unregister block=%#x argument=%#x: %w", block, argument, err)
	}
	if err := t.table.Delete(uint64(key)); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("nptv6map: nptv6_table: unregister block=%#x argument=%#x: %w", block, argument, err)
		}
	}
	t.mu.Lock()
	delete(t.generation, NPTv6Key{Block: block, Argument: argument})
	t.mu.Unlock()
	return nil
}

// Get reads the nptv6_table entry for (block, argument), reporting whether
// it exists.
func (t *NPTv6Table) Get(block uint64, argument uint16) (NPTv6Entry, bool, error) {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return NPTv6Entry{}, false, fmt.Errorf("nptv6map: nptv6_table: get block=%#x argument=%#x: %w",
			block, argument, err)
	}

	var value prog.UsidNptv6Value
	if err := t.table.Lookup(uint64(key), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return NPTv6Entry{}, false, nil
		}
		return NPTv6Entry{}, false, fmt.Errorf("nptv6map: nptv6_table: get block=%#x argument=%#x: %w",
			block, argument, err)
	}
	return t.decode(block, argument, value), true, nil
}

// List returns every entry currently in nptv6_table, in unspecified order.
func (t *NPTv6Table) List() ([]NPTv6Entry, error) {
	var (
		entries []NPTv6Entry
		rawKey  uint64
		value   prog.UsidNptv6Value
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		block := rawKey >> uformat.ArgumentBits
		argument := uint16(rawKey & (1<<uformat.ArgumentBits - 1))
		entries = append(entries, t.decode(block, argument, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("nptv6map: nptv6_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings nptv6_table into agreement with live, the caller's current
// set of keys that should have an entry, removing every entry whose key is
// absent except one whose generation is at or above cutoff. The same semantics
// as vrf_table's; see the package doc comment for why this table's single
// sequential writer makes the race that guards against far narrower here.
func (t *NPTv6Table) Reconcile(live map[NPTv6Key]struct{}, cutoff uint64) (removed []NPTv6Entry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("nptv6map: nptv6_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.NPTv6Key]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.Block, e.Argument); err != nil {
			errs = append(errs, fmt.Errorf("nptv6map: nptv6_table: reconcile: delete stale entry %+v: %w",
				e.NPTv6Key, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}

// decode converts a raw kernel value and its key into an NPTv6Entry, filling in
// the generation from this process's own bookkeeping, or zero when this process
// never registered the entry.
func (t *NPTv6Table) decode(block uint64, argument uint16, value prog.UsidNptv6Value) NPTv6Entry {
	nk := NPTv6Key{Block: block, Argument: argument}

	ula := make(net.IP, net.IPv6len)
	copy(ula, value.UlaPrefix[:])
	pub := make(net.IP, net.IPv6len)
	copy(pub, value.PublicPrefix[:])
	mask := net.CIDRMask(int(value.PrefixLen), 128)

	t.mu.Lock()
	gen := t.generation[nk]
	t.mu.Unlock()

	return NPTv6Entry{
		NPTv6Key: nk,
		Mapping: nptv6.Mapping{
			ULAPrefix:    &net.IPNet{IP: ula, Mask: mask},
			PublicPrefix: &net.IPNet{IP: pub, Mask: mask},
		},
		Adjustment: value.Adjustment,
		Generation: gen,
	}
}

// toValue converts m and its precomputed adjustment into the fixed 16-byte
// zero-padded arrays the kernel value expects. A parsed CIDR's address is
// already 16 bytes and zero-padded beyond its prefix length, so this needs only
// a conversion and no further masking.
func toValue(m nptv6.Mapping, adjustment uint16) (prog.UsidNptv6Value, error) {
	ulaIP := m.ULAPrefix.IP.To16()
	if ulaIP == nil {
		return prog.UsidNptv6Value{}, fmt.Errorf("ULAPrefix %v is not a valid IPv6 CIDR", m.ULAPrefix)
	}
	pubIP := m.PublicPrefix.IP.To16()
	if pubIP == nil {
		return prog.UsidNptv6Value{}, fmt.Errorf("PublicPrefix %v is not a valid IPv6 CIDR", m.PublicPrefix)
	}
	ones, _ := m.ULAPrefix.Mask.Size()

	var value prog.UsidNptv6Value
	copy(value.UlaPrefix[:], ulaIP)
	copy(value.PublicPrefix[:], pubIP)
	value.PrefixLen = uint8(ones)
	value.Adjustment = adjustment
	return value, nil
}
