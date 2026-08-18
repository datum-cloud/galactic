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
// locator_table, plus the 12-bit Argument -- the identical composition
// usidmap.VRFKey uses, kept as its own type here (rather than reusing
// usidmap.VRFKey directly) purely so this package's own exported API never
// forces a caller to import usidmap just to build a key.
type NPTv6Key struct {
	Block    uint64
	Argument uint16
}

// NPTv6Entry is one fully decoded nptv6_table row, decoupled from
// prog.UsidNptv6Value's cilium/ebpf/BTF-generated field layout -- mirrors
// usidmap.VRFEntry's own reasoning.
type NPTv6Entry struct {
	NPTv6Key

	// Mapping is the RFC 6296 prefix pair this entry applies -- see
	// internal/plumbing/nptv6's doc comment for the translation itself.
	Mapping nptv6.Mapping

	// Adjustment is the precomputed RFC 6296 §3.6 checksum-neutral
	// adjustment (nptv6.Mapping.Adjustment), stored in the kernel value so
	// the datapath never recomputes it per packet.
	Adjustment uint16

	// Generation is this process's own in-memory bookkeeping of when this
	// entry was last (re-)registered by Register -- see doc.go's "no
	// Generation/monotonic-clock kernel field" section for why this is not
	// persisted in the kernel value the way usidmap.VRFEntry's own
	// Generation is.
	Generation uint64
}

// NPTv6Table is the read/write API for nptv6_table.
type NPTv6Table struct {
	table usidmap.Table
	clock func() uint64

	mu         sync.Mutex
	generation map[NPTv6Key]uint64
}

// NewNPTv6Table wraps table as an NPTv6Table. Production callers pass a
// usidmap.KernelTable wrapping a loaded *prog.UsidObjects's Nptv6Table map
// (or OpenPinned, below, for a process that did not itself load the
// datapath); tests pass a fake usidmap.Table.
func NewNPTv6Table(table usidmap.Table) *NPTv6Table {
	return &NPTv6Table{table: table, clock: monotonicNow, generation: make(map[NPTv6Key]uint64)}
}

// OpenPinned opens nptv6_table from its pinned path under pinDir
// (internal/plumbing/ebpf/attach.Load pins each map at
// <pinDir>/<map name>) and returns an NPTv6Table wrapping it, mirroring
// usidmap.OpenPinnedRegistry -- for a process (internal/gc's periodic
// sweep, via internal/installer.Run) that did not itself load the
// datapath but needs to read/write this one map. The returned io.Closer
// (the opened *ebpf.Map itself) must be closed once the caller is done; it
// does not affect the map's pinned lifetime.
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

// Register writes (or overwrites) the nptv6_table entry for (block,
// argument): computes m.Adjustment() internally and converts m's two
// prefixes into the fixed 16-byte zero-padded arrays prog.UsidNptv6Value
// expects, mirroring exactly how internal/plumbing/nptv6.prefixChecksum/
// Translate already read prefix bytes (net.IPNet.IP, as produced by
// net.ParseCIDR, is already zero-padded beyond its own prefix length). There
// is no read-modify-write step here (unlike usidmap.VRFTable.Register):
// nptv6_table carries no per-entry counters to preserve across a
// re-registration, so every call is a plain overwrite.
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

// Unregister removes the nptv6_table entry for (block, argument), if
// present. Not an error to unregister an already-absent entry, matching
// usidmap.VRFTable.Unregister's own idempotent contract.
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

// Reconcile brings nptv6_table into agreement with live -- the caller's
// current set of (Block, Argument) pairs that should have an entry --
// removing every entry whose key is absent from live, except an entry whose
// Generation is >= cutoff. Mirrors usidmap.VRFTable.Reconcile's exact
// semantics; see doc.go for why this table's own writer (a single,
// sequential periodic sweep) makes the race that mechanism guards against
// far narrower here than for vrf_table, and why Generation is nonetheless
// still tracked and honored the same way.
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

// decode converts a raw kernel value plus its (block, argument) key into an
// NPTv6Entry, filling in Generation from this process's own in-memory
// bookkeeping (zero if this entry was never registered by this process
// instance -- see doc.go).
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

// toValue converts m (plus its precomputed adjustment) into the fixed
// 16-byte zero-padded arrays prog.UsidNptv6Value expects. m.ULAPrefix/
// m.PublicPrefix.IP are already 16-byte, zero-padded-beyond-prefix-length
// slices by construction of net.ParseCIDR (the same assumption
// nptv6.prefixChecksum documents), so this only needs a To16 conversion, no
// further masking.
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
