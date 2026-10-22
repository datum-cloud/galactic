// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tpmap writes the uSID datapath's interface traffic policy maps:
// the enforcement mode, the managed-interface table, the NAT locators that
// classify a route or an outer source as a NAT shard's, and the per-interface,
// per-direction snapshots tp_decide evaluates.
//
// A snapshot is published by creating a new inner map, filling it, and
// inserting it with one update of tp_binding_table. The kernel waits for
// every program that could hold the replaced snapshot to finish before that
// update returns (maybe_wait_bpf_programs in kernel/bpf/syscall.c), so once
// Publish returns, counter rows only the old snapshot referenced can be
// reused. See docs/enhancements/networking/interface-traffic-policy.
//
// Maps opened from a pin directory also pin each snapshot they publish under
// its tp_snapshots subdirectory. Reading a snapshot back needs a handle to its
// inner map, and the kernel hands one out by map ID only to CAP_SYS_ADMIN; a
// pin can be opened by any process with access to the bpffs, so
// galactic-router can adopt the snapshots bound before it restarted.
package tpmap

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// Enforcement modes, tp_state.mode.
const (
	ModeOff     uint32 = 0
	ModeAudit   uint32 = 1
	ModeEnforce uint32 = 2
)

// Directions, the workload's.
const (
	DirIngress uint32 = 0
	DirEgress  uint32 = 1
)

// Interface kinds, tp_iface_table.kind.
const (
	KindTenant uint32 = 1
	KindInfra  uint32 = 2
)

// Fallback reasons, the fixed metric enum, in the datapath's order.
const (
	ReasonNoMatch             uint8 = 0
	ReasonPolicyUnavailable   uint8 = 1
	ReasonParseError          uint8 = 2
	ReasonClassificationError uint8 = 3
	reasonCount                     = 4
)

// ReasonNames are the metric label values of the fallback reasons.
var ReasonNames = [reasonCount]string{"no_match", "policy_unavailable", "parse_error", "classification_error"}

// RuleCounterRows is tp_rule_counters' size.
const RuleCounterRows = 16384

// slotSize is the size of one snapshot slot, an entry or the header.
var slotSize = uint32(binary.Size(prog.UsidTpEntry{})) //nolint:gosec // a fixed struct size

// SnapshotSpec is the spec of one tp_binding_table inner map, which must match
// the compiled template exactly: the kernel refuses an inner map of any other
// shape.
var SnapshotSpec = ebpf.MapSpec{
	Name:       "tp_snapshot",
	Type:       ebpf.Array,
	KeySize:    4,
	ValueSize:  slotSize,
	MaxEntries: galacticv1alpha1.MaxCompiledEntries + 1,
}

// snapshotPinDir is the subdirectory of the pin directory that holds one pin
// per bound snapshot.
const snapshotPinDir = "tp_snapshots"

// ErrSnapshotUnreadable reports a bound snapshot that has no matching pin and
// whose inner map this process may not open by ID, such as one bound by a
// datapath writer that did not pin it.
var ErrSnapshotUnreadable = errors.New("bound snapshot is unreadable")

// Maps are the traffic policy maps of a loaded or pinned uSID datapath.
type Maps struct {
	State            *ebpf.Map
	Interfaces       *ebpf.Map
	InterfaceAddrs   *ebpf.Map
	Bindings         *ebpf.Map
	NATLocators      *ebpf.Map
	RuleCounters     *ebpf.Map
	FallbackCounters *ebpf.Map
	// Unattributed and AccountingErrorCounts are the node-level counters.
	Unattributed          *ebpf.Map
	AccountingErrorCounts *ebpf.Map

	// pinDir is where the maps are pinned; empty for maps that are not, whose
	// snapshots are not pinned either.
	pinDir string
}

// FromObjects returns the traffic policy maps of objs.
func FromObjects(objs *prog.UsidObjects) *Maps {
	return &Maps{
		State:                 objs.TpState,
		Interfaces:            objs.TpIfaceTable,
		InterfaceAddrs:        objs.TpIfaceAddrTable,
		Bindings:              objs.TpBindingTable,
		NATLocators:           objs.TpNatLocatorTable,
		RuleCounters:          objs.TpRuleCounters,
		FallbackCounters:      objs.TpFallbackCounters,
		Unattributed:          objs.TpUnattributedCounters,
		AccountingErrorCounts: objs.TpAccountingErrors,
	}
}

// FromPinnedObjects returns the traffic policy maps of objs, which the caller
// pinned under pinDir, so the maps manage snapshot pins as OpenPinned's do.
func FromPinnedObjects(objs *prog.UsidObjects, pinDir string) *Maps {
	m := FromObjects(objs)
	m.pinDir = pinDir
	return m
}

// State is tp_state: the node's enforcement mode and what the datapath needs
// to apply it.
type State struct {
	Mode uint32
	// NATLocatorsSynced reports that tp_nat_locator_table holds every shard
	// locator; until then an encapsulated packet's path is unknown.
	NATLocatorsSynced bool
	// Mark is the skb mark usid_ingress sets on a packet tp_deliver must not
	// decide again. Zero disables it.
	Mark uint32
	// Capable reports that the kernel passed the traffic policy preflight.
	Capable bool
}

// SetState writes tp_state.
func (m *Maps) SetState(st State) error {
	v := prog.UsidTpStateValue{Mode: st.Mode, Mark: st.Mark}
	if st.NATLocatorsSynced {
		v.NatLocatorsSynced = 1
	}
	if st.Capable {
		v.Capable = 1
	}
	if err := m.State.Put(uint32(0), v); err != nil {
		return fmt.Errorf("write tp_state: %w", err)
	}
	return nil
}

// GetState reads tp_state.
func (m *Maps) GetState() (State, error) {
	var v prog.UsidTpStateValue
	if err := m.State.Lookup(uint32(0), &v); err != nil {
		return State{}, fmt.Errorf("read tp_state: %w", err)
	}
	return State{Mode: v.Mode, NATLocatorsSynced: v.NatLocatorsSynced != 0, Mark: v.Mark, Capable: v.Capable != 0}, nil
}

// OpenPinned opens the traffic policy maps pinned under pinDir, as a CNI
// plugin does; Close releases them.
func OpenPinned(pinDir string) (*Maps, error) {
	m := &Maps{pinDir: pinDir}
	for _, p := range []struct {
		name string
		dst  **ebpf.Map
	}{
		{prog.UsidMapTpState, &m.State},
		{prog.UsidMapTpIfaceTable, &m.Interfaces},
		{prog.UsidMapTpIfaceAddrTable, &m.InterfaceAddrs},
		{prog.UsidMapTpBindingTable, &m.Bindings},
		{prog.UsidMapTpNatLocatorTable, &m.NATLocators},
		{prog.UsidMapTpRuleCounters, &m.RuleCounters},
		{prog.UsidMapTpFallbackCounters, &m.FallbackCounters},
		{prog.UsidMapTpUnattributedCounters, &m.Unattributed},
		{prog.UsidMapTpAccountingErrors, &m.AccountingErrorCounts},
	} {
		mp, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, p.name), nil)
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("open pinned %s: %w", p.name, err)
		}
		*p.dst = mp
	}
	return m, nil
}

// Close releases maps opened by OpenPinned.
func (m *Maps) Close() {
	for _, mp := range []*ebpf.Map{m.State, m.Interfaces, m.InterfaceAddrs, m.Bindings, m.NATLocators,
		m.RuleCounters, m.FallbackCounters, m.Unattributed, m.AccountingErrorCounts} {
		if mp != nil {
			_ = mp.Close()
		}
	}
}

// NewPolicyToken is a random policy token for a new interface lifetime.
func NewPolicyToken() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("read random policy token: %w", err)
	}
	return binary.NativeEndian.Uint64(b[:]) | 1, nil // never zero
}

// RemoveInterface removes everything ifindex's lifetime owns in the policy
// maps: both bindings, its interface row, its addresses and its fallback
// rows. Rows already gone are not an error.
func (m *Maps) RemoveInterface(ifindex uint32) error {
	var errs []error
	for _, dir := range []uint32{DirIngress, DirEgress} {
		if err := m.Invalidate(ifindex, dir); err != nil {
			errs = append(errs, err)
		}
	}
	var iface prog.UsidTpIfaceValue
	if err := m.Interfaces.Lookup(ifindex, &iface); err == nil {
		for _, dir := range []uint32{DirIngress, DirEgress} {
			for reason := range uint8(reasonCount) {
				err := m.FallbackCounters.Delete(FallbackKey(ifindex, iface.PolicyToken, dir, reason))
				if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					errs = append(errs, fmt.Errorf("delete fallback counters: %w", err))
				}
			}
		}
		if err := m.Interfaces.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete tp_iface_table[%d]: %w", ifindex, err))
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("read tp_iface_table[%d]: %w", ifindex, err))
	}
	var (
		key   prog.UsidTpIfaceAddrKey
		value uint8
		stale []prog.UsidTpIfaceAddrKey
	)
	it := m.InterfaceAddrs.Iterate()
	for it.Next(&key, &value) {
		if key.Ifindex == ifindex {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate tp_iface_addr_table: %w", err))
	}
	for _, k := range stale {
		if err := m.InterfaceAddrs.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete interface address: %w", err))
		}
	}
	return errors.Join(errs...)
}

// PutInterface marks ifindex as an interface Galactic manages, with its
// lifetime's policy token. Its zeroed fallback counter rows are created
// first, so its first packet is attributed. A row that already exists for
// this lifetime keeps its counts.
func (m *Maps) PutInterface(ifindex uint32, token uint64, kind uint32) error {
	zero := make([]prog.UsidTpCounter, ebpf.MustPossibleCPU())
	for _, dir := range []uint32{DirIngress, DirEgress} {
		for reason := range uint8(reasonCount) {
			err := m.FallbackCounters.Update(FallbackKey(ifindex, token, dir, reason), zero, ebpf.UpdateNoExist)
			if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
				return fmt.Errorf("create fallback counters for ifindex %d: %w", ifindex, err)
			}
		}
	}
	if err := m.Interfaces.Put(ifindex, prog.UsidTpIfaceValue{PolicyToken: token, Kind: kind}); err != nil {
		return fmt.Errorf("write tp_iface_table[%d]: %w", ifindex, err)
	}
	return nil
}

// PutInterfaceAddr records one of ifindex's assigned addresses, which the
// link-operation checks accept as an ARP or neighbor discovery source.
func (m *Maps) PutInterfaceAddr(ifindex uint32, addr netip.Addr) error {
	k := prog.UsidTpIfaceAddrKey{Ifindex: ifindex, Family: 6}
	if addr.Is4() {
		k.Family = 4
		a4 := addr.As4()
		copy(k.Addr[:], a4[:])
	} else {
		k.Addr = addr.As16()
	}
	if err := m.InterfaceAddrs.Put(k, uint8(1)); err != nil {
		return fmt.Errorf("write tp_iface_addr_table: %w", err)
	}
	return nil
}

// FallbackKey is the tp_fallback_counters key of one interface lifetime,
// direction and reason.
func FallbackKey(ifindex uint32, token uint64, dir uint32, reason uint8) prog.UsidTpFallbackKey {
	return prog.UsidTpFallbackKey{Ifindex: ifindex, Direction: uint8(dir), Reason: reason, PolicyToken: token}
}

// AddNATLocator records sid's locator, its top 64 bits, as a NAT shard's.
// Shard locators are disjoint from every router locator, so an entry is never
// removed while the agent runs: a stale one can classify nothing wrongly.
func (m *Maps) AddNATLocator(sid netip.Addr) error {
	b := sid.As16()
	if err := m.NATLocators.Put(binary.NativeEndian.Uint64(b[:8]), uint8(1)); err != nil {
		return fmt.Errorf("write tp_nat_locator_table: %w", err)
	}
	return nil
}

// Snapshot is one interface direction's compiled policy as the datapath
// holds it.
type Snapshot struct {
	Token uint64
	// CounterBase is added to every entry's Rule to find its counter row.
	CounterBase uint32
	// Generation and PolicyUID identify the policy the entries were compiled
	// from; the datapath ignores them.
	Generation int64
	PolicyUID  [16]byte
	Entries    []trafficpolicy.Entry
	// Raw is each entry as the datapath holds it, filled by ReadSnapshot
	// only, so a reader can check the entries are what a policy compiles to.
	Raw []prog.UsidTpEntry
}

// Publish installs entries as ifindex's snapshot in dir, its rules counting
// into rows counterBase onward. The rows must already be zeroed (see
// ZeroCounters). When Publish returns, no packet can still be evaluating the
// snapshot it replaced.
func (m *Maps) Publish(ifindex, dir uint32, token uint64, counterBase uint32, entries []trafficpolicy.Entry) error {
	return m.PublishSnapshot(ifindex, dir, Snapshot{Token: token, CounterBase: counterBase, Entries: entries})
}

// PublishSnapshot is Publish with the policy identity recorded in the header.
func (m *Maps) PublishSnapshot(ifindex, dir uint32, snap Snapshot) error {
	entries := snap.Entries
	if len(entries) > galacticv1alpha1.MaxCompiledEntries {
		return fmt.Errorf("%d entries, more than the limit of %d", len(entries), galacticv1alpha1.MaxCompiledEntries)
	}
	for _, e := range entries {
		if uint64(snap.CounterBase)+uint64(e.Rule) >= RuleCounterRows {
			return fmt.Errorf("rule %d's counter row %d is outside tp_rule_counters", e.Rule,
				uint64(snap.CounterBase)+uint64(e.Rule))
		}
	}
	inner, err := ebpf.NewMap(&SnapshotSpec)
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}
	defer inner.Close() //nolint:errcheck // the outer map holds its own reference once inserted

	count := uint32(len(entries)) //nolint:gosec // bounded above
	header := prog.UsidTpHeader{
		PolicyToken: snap.Token, CounterBase: snap.CounterBase, Count: count,
		Generation: uint64(snap.Generation), PolicyUid: snap.PolicyUID, //nolint:gosec // a generation is never negative
	}
	if err := inner.Put(uint32(0), header); err != nil {
		return fmt.Errorf("write snapshot header: %w", err)
	}
	for i, e := range entries {
		if err := inner.Put(uint32(i+1), EncodeEntry(e)); err != nil { //nolint:gosec // bounded above
			return fmt.Errorf("write snapshot entry %d: %w", i, err)
		}
	}
	key := prog.UsidTpBindingKey{Ifindex: ifindex, Direction: dir}
	tmp, err := m.pinTemp(key, inner)
	if err != nil {
		return err
	}
	if err := m.Bindings.Put(key, inner); err != nil {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
		return fmt.Errorf("bind snapshot to ifindex %d direction %d: %w", ifindex, dir, err)
	}
	if tmp != "" {
		// The snapshot is bound either way. A missing or stale pin only makes
		// it unreadable, which ReadSnapshot reports, so it is not an error here.
		if err := os.Rename(tmp, m.snapshotPin(key)); err != nil {
			_ = os.Remove(tmp)
			_ = os.Remove(m.snapshotPin(key))
		}
	}
	return nil
}

// pinTemp pins inner under a temporary name in the snapshot pin directory,
// returning "" for maps without a pin directory. Renaming it over the key's
// pin once bound replaces the previous snapshot's pin in one step.
func (m *Maps) pinTemp(key prog.UsidTpBindingKey, inner *ebpf.Map) (string, error) {
	if m.pinDir == "" {
		return "", nil
	}
	dir := filepath.Join(m.pinDir, snapshotPinDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create snapshot pin directory: %w", err)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random pin name: %w", err)
	}
	// bpffs refuses any name containing a dot.
	tmp := filepath.Join(dir, fmt.Sprintf("tmp-%d-%d-%x", key.Ifindex, key.Direction, b))
	if err := inner.Pin(tmp); err != nil {
		return "", fmt.Errorf("pin snapshot of ifindex %d direction %d: %w", key.Ifindex, key.Direction, err)
	}
	return tmp, nil
}

// snapshotPin is the path of key's snapshot pin.
func (m *Maps) snapshotPin(key prog.UsidTpBindingKey) string {
	return filepath.Join(m.pinDir, snapshotPinDir, fmt.Sprintf("%d-%d", key.Ifindex, key.Direction))
}

// openSnapshot opens the inner map bound with id: from key's pin when it is
// that map, otherwise by ID, which the kernel allows only with CAP_SYS_ADMIN
// and reports as ErrSnapshotUnreadable without it.
func (m *Maps) openSnapshot(key prog.UsidTpBindingKey, id ebpf.MapID) (*ebpf.Map, error) {
	pinErr := errors.New("snapshot pins are not managed")
	if m.pinDir != "" {
		var pinned *ebpf.Map
		if pinned, pinErr = m.loadPin(m.snapshotPin(key), id); pinErr == nil {
			return pinned, nil
		}
	}
	inner, err := ebpf.NewMapFromID(id)
	if errors.Is(err, os.ErrPermission) {
		// pinErr is formatted, not wrapped: a missing pin must not read as
		// os.ErrNotExist, which callers take for an unbound snapshot.
		return nil, fmt.Errorf("%w: ifindex %d direction %d: open pin: %s; open by ID: %w", ErrSnapshotUnreadable,
			key.Ifindex, key.Direction, pinErr.Error(), err)
	}
	return inner, err
}

// errPinMismatch reports a pin that holds a map other than the bound one.
var errPinMismatch = errors.New("pin holds a map other than the bound snapshot")

// loadPin opens the map pinned at path if its ID is id.
func (m *Maps) loadPin(path string, id ebpf.MapID) (*ebpf.Map, error) {
	pinned, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, err
	}
	info, err := pinned.Info()
	if err != nil {
		_ = pinned.Close()
		return nil, fmt.Errorf("read pinned map info: %w", err)
	}
	if pinnedID, ok := info.ID(); !ok || pinnedID != id {
		_ = pinned.Close()
		return nil, errPinMismatch
	}
	return pinned, nil
}

// SweepPins removes every snapshot pin that holds no bound snapshot: a
// temporary pin a publish left behind, and a key's pin whose binding is gone
// or holds another map, as when an interface's DEL unbinds it while a publish
// for it is still renaming its pin. Only the snapshot publisher may call it,
// and never during one of its own publishes, whose temporary pin it would
// remove. A pin whose binding cannot be read, or that cannot be opened, is
// kept.
func (m *Maps) SweepPins() error {
	if m.pinDir == "" {
		return nil
	}
	dir := filepath.Join(m.pinDir, snapshotPinDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list snapshot pins: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if m.pinBound(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove snapshot pin %s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// pinBound reports whether the snapshot pin name is its key's bound snapshot.
func (m *Maps) pinBound(name string) bool {
	var key prog.UsidTpBindingKey
	if _, err := fmt.Sscanf(name, "%d-%d", &key.Ifindex, &key.Direction); err != nil ||
		name != fmt.Sprintf("%d-%d", key.Ifindex, key.Direction) {
		return false // a temporary pin, or nothing this package wrote
	}
	var id uint32
	err := m.Bindings.Lookup(key, &id)
	if errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	pinned, err := m.loadPin(filepath.Join(m.pinDir, snapshotPinDir, name), ebpf.MapID(id))
	if err != nil {
		// Only a pin of another map is stale. One that failed to open, such
		// as for want of a file descriptor, may be the bound snapshot's.
		return !errors.Is(err, errPinMismatch) && !errors.Is(err, os.ErrNotExist)
	}
	_ = pinned.Close()
	return true
}

// ReadSnapshot reads ifindex's snapshot in dir, reporting false when none is
// bound. Entries carry only each entry's Rule, which names its counter row,
// and its flags; Raw holds every entry in full. A bound snapshot this process
// cannot open returns an error wrapping ErrSnapshotUnreadable.
func (m *Maps) ReadSnapshot(ifindex, dir uint32) (Snapshot, bool, error) {
	key := prog.UsidTpBindingKey{Ifindex: ifindex, Direction: dir}
	// A map-of-maps lookup read into a uint32 is the inner map's ID; reading
	// it into an *ebpf.Map would open it by ID.
	var id uint32
	err := m.Bindings.Lookup(key, &id)
	if errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("look up binding of ifindex %d direction %d: %w", ifindex, dir, err)
	}
	inner, err := m.openSnapshot(key, ebpf.MapID(id))
	if errors.Is(err, os.ErrNotExist) {
		// Unbound since it was looked up. Only an open by ID tells: without
		// CAP_SYS_ADMIN the kernel refuses before it finds the map gone, so
		// that case returns ErrSnapshotUnreadable instead.
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	defer inner.Close() //nolint:errcheck // read-only handle
	var header prog.UsidTpHeader
	if err := inner.Lookup(uint32(0), &header); err != nil {
		return Snapshot{}, false, fmt.Errorf("read snapshot header: %w", err)
	}
	snap := Snapshot{
		Token: header.PolicyToken, CounterBase: header.CounterBase,
		Generation: int64(header.Generation), PolicyUID: header.PolicyUid, //nolint:gosec // written from an int64
	}
	if header.Count > galacticv1alpha1.MaxCompiledEntries {
		return Snapshot{}, false, fmt.Errorf("snapshot of ifindex %d direction %d claims %d entries, more than the limit "+
			"of %d", ifindex, dir, header.Count, galacticv1alpha1.MaxCompiledEntries)
	}
	for i := uint32(1); i <= header.Count; i++ {
		var e prog.UsidTpEntry
		if err := inner.Lookup(i, &e); err != nil {
			return Snapshot{}, false, fmt.Errorf("read snapshot entry %d: %w", i, err)
		}
		snap.Entries = append(snap.Entries, trafficpolicy.Entry{Rule: e.Rule, Flags: trafficpolicy.EntryFlag(e.Flags)})
		snap.Raw = append(snap.Raw, e)
	}
	return snap, true, nil
}

// BoundKeys lists every bound interface direction.
func (m *Maps) BoundKeys() ([]prog.UsidTpBindingKey, error) {
	var (
		key prog.UsidTpBindingKey
		id  uint32 // the inner map's ID, read without opening it
		out []prog.UsidTpBindingKey
	)
	it := m.Bindings.Iterate()
	for it.Next(&key, &id) {
		out = append(out, key)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate tp_binding_table: %w", err)
	}
	return out, nil
}

// RuleCounter is the sum over CPUs of one rule counter row.
func (m *Maps) RuleCounter(row uint32) (packets, bytes uint64, err error) {
	return sumPerCPU(m.RuleCounters, row)
}

// FallbackCounter is the sum over CPUs of one interface lifetime's fallback
// row.
func (m *Maps) FallbackCounter(ifindex uint32, token uint64, dir uint32, reason uint8) (
	packets, bytes uint64, err error,
) {
	return sumPerCPU(m.FallbackCounters, FallbackKey(ifindex, token, dir, reason))
}

// UnattributedCounter is the sum over CPUs of the node-level fallback count
// for dir and reason.
func (m *Maps) UnattributedCounter(dir uint32, reason uint8) (packets, bytes uint64, err error) {
	return sumPerCPU(m.Unattributed, dir*reasonCount+uint32(reason))
}

// AccountingErrors is the sum over CPUs of the missing-rule-counter count for
// dir and verdict.
func (m *Maps) AccountingErrors(dir uint32, allow bool) (uint64, error) {
	k := dir * 2
	if allow {
		k++
	}
	var per []uint64
	if err := m.AccountingErrorCounts.Lookup(k, &per); err != nil {
		return 0, fmt.Errorf("read tp_accounting_errors[%d]: %w", k, err)
	}
	var n uint64
	for _, v := range per {
		n += v
	}
	return n, nil
}

func sumPerCPU(m *ebpf.Map, key any) (packets, bytes uint64, err error) {
	var per []prog.UsidTpCounter
	if err := m.Lookup(key, &per); err != nil {
		return 0, 0, err
	}
	for _, c := range per {
		packets += c.Packets
		bytes += c.Bytes
	}
	return packets, bytes, nil
}

// Invalidate removes ifindex's snapshot in dir, and its pin, so it denies as
// policy_unavailable. It needs no allocation, so it works when publishing a
// replacement cannot.
func (m *Maps) Invalidate(ifindex, dir uint32) error {
	key := prog.UsidTpBindingKey{Ifindex: ifindex, Direction: dir}
	err := m.Bindings.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unbind ifindex %d direction %d: %w", ifindex, dir, err)
	}
	if m.pinDir == "" {
		return nil
	}
	// Checked first so a caller whose bpffs mount is read-only, and that never
	// pins, is not refused for a pin that does not exist.
	pin := m.snapshotPin(key)
	if _, err := os.Lstat(pin); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unpin snapshot of ifindex %d direction %d: %w", ifindex, dir, err)
	}
	return nil
}

// ZeroCounters resets rule counter rows [base, base+n), so a new counter
// interval starts at zero.
func (m *Maps) ZeroCounters(base, n uint32) error {
	zero := make([]prog.UsidTpCounter, ebpf.MustPossibleCPU())
	for i := base; i < base+n; i++ {
		if err := m.RuleCounters.Put(i, zero); err != nil {
			return fmt.Errorf("zero rule counter %d: %w", i, err)
		}
	}
	return nil
}

// EncodeEntry is e in the datapath's layout.
func EncodeEntry(e trafficpolicy.Entry) prog.UsidTpEntry {
	out := prog.UsidTpEntry{
		Flags:    uint16(e.Flags),
		Rule:     e.Rule,
		Path:     uint8(e.Path),
		Family:   uint8(e.Family),
		Proto:    e.Proto,
		IcmpType: e.ICMPType,
		IcmpCode: e.ICMPCode,
		SportLo:  e.SourcePorts.Start,
		SportHi:  e.SourcePorts.End,
		DportLo:  e.DestPorts.Start,
		DportHi:  e.DestPorts.End,
	}
	if e.Source.IsValid() {
		out.Src, out.SrcMask = prefixWords(e.Source)
	}
	if e.Destination.IsValid() {
		out.Dst, out.DstMask = prefixWords(e.Destination)
	}
	return out
}

// prefixWords is p's address and mask as the two native-endian words the
// datapath loads them as, an IPv4 address in the first 4 bytes.
func prefixWords(p netip.Prefix) (addr, mask [2]uint64) {
	var a, m [16]byte
	if p.Addr().Is4() {
		a4 := p.Addr().As4()
		copy(a[:], a4[:])
	} else {
		a = p.Addr().As16()
	}
	for i := range p.Bits() {
		m[i/8] |= 0x80 >> (i % 8)
	}
	for i := range a {
		a[i] &= m[i]
	}
	return [2]uint64{binary.NativeEndian.Uint64(a[:8]), binary.NativeEndian.Uint64(a[8:])},
		[2]uint64{binary.NativeEndian.Uint64(m[:8]), binary.NativeEndian.Uint64(m[8:])}
}

// Active reports whether the node pinned under pinDir enforces or audits
// traffic policy. A node whose policy maps are not pinned, such as one still
// running an older datapath, is not. Any other failure to read the mode is
// returned, and callers fail closed on it.
func Active(pinDir string) (bool, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapTpState), nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("open pinned tp_state: %w", err)
	}
	defer m.Close() //nolint:errcheck // read-only handle
	var v prog.UsidTpStateValue
	if err := m.Lookup(uint32(0), &v); err != nil {
		return true, fmt.Errorf("read tp_state: %w", err)
	}
	return v.Mode != ModeOff, nil
}

// RemovePinnedInterface is RemoveInterface on the maps pinned under pinDir. A
// node without them has nothing to remove.
func RemovePinnedInterface(pinDir string, ifindex uint32) error {
	m, err := OpenPinned(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer m.Close()
	return m.RemoveInterface(ifindex)
}

// PutPinnedInfra marks ifindex, under pinDir, as a platform interface the
// datapath delivers through but never evaluates, such as an ingress sidecar's
// veth peer. Traffic it passes on to a tenant interface is checked there. A
// node without the policy maps has nothing to record.
func PutPinnedInfra(pinDir string, ifindex uint32) error {
	m, err := OpenPinned(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer m.Close()
	if err := m.Interfaces.Put(ifindex, prog.UsidTpIfaceValue{Kind: KindInfra}); err != nil {
		return fmt.Errorf("write tp_iface_table[%d]: %w", ifindex, err)
	}
	return nil
}
