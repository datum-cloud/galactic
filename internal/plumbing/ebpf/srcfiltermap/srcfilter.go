// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfiltermap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// MaxSlots is the number of distinct uplinks an allow entry's interface mask
// can name. Valid slots are 0 through MaxSlots-1.
const MaxSlots = prog.SrcFilterMaxSlots

// configKey is the only key of the single-entry src_filter_config_table.
const configKey uint32 = 0

// deniedPrefixBits is the width of the source prefix src_filter_denied records.
const deniedPrefixBits = 64

// Mode selects how the datapath acts on a source the filter rejects.
type Mode uint32

const (
	// ModeOff skips the filter entirely.
	ModeOff = Mode(prog.SrcFilterModeOff)
	// ModeAudit counts and records rejected sources but still delivers them.
	ModeAudit = Mode(prog.SrcFilterModeAudit)
	// ModeEnforce drops rejected sources.
	ModeEnforce = Mode(prog.SrcFilterModeEnforce)
)

// String returns the mode's configuration name.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAudit:
		return "audit"
	case ModeEnforce:
		return "enforce"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(m))
	}
}

// ParseMode returns the Mode named by s, case-insensitively, or an error if s
// names none.
func ParseMode(s string) (Mode, error) {
	for _, m := range []Mode{ModeOff, ModeAudit, ModeEnforce} {
		if strings.EqualFold(strings.TrimSpace(s), m.String()) {
			return m, nil
		}
	}
	return ModeOff, fmt.Errorf("srcfiltermap: unknown mode %q (want off, audit or enforce)", s)
}

func (m Mode) valid() bool { return m <= ModeEnforce }

// Config is the filter's global state.
type Config struct {
	Mode Mode
	// Populated reports that the allow-list reflects a complete sync. While
	// false, the datapath passes every packet whatever the mode.
	Populated bool
	// Generation is an opaque control-plane counter the datapath never reads.
	Generation uint32
}

// Entry is one allowed source prefix.
type Entry struct {
	// Prefix is an IPv6 prefix; Put stores it masked.
	Prefix netip.Prefix
	// IfaceMask has bit N set for every uplink assigned slot N.
	IfaceMask uint32
	// AnyIface accepts the prefix on every interface, ignoring IfaceMask.
	AnyIface bool
}

// Stats is the sum of the datapath's per-CPU decision counters.
type Stats struct {
	Checked           uint64
	Allowed           uint64
	DenyPrefix        uint64
	DenyIface         uint64
	BypassUnpopulated uint64
}

// DenyReason says why a source was rejected.
type DenyReason uint32

const (
	// DenyReasonPrefix means the source matched no allowed prefix.
	DenyReasonPrefix = DenyReason(prog.SrcFilterStatDenyPrefix)
	// DenyReasonIface means the source's prefix is not allowed on the arrival
	// interface.
	DenyReasonIface = DenyReason(prog.SrcFilterStatDenyIface)
)

// String returns a stable, metrics-friendly name for the reason.
func (r DenyReason) String() string {
	if name, ok := prog.SrcFilterStatNames[uint32(r)]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", uint32(r))
}

// DeniedSource is one src_filter_denied record: a source /64 the filter has
// rejected, in audit or enforce mode.
type DeniedSource struct {
	Prefix      netip.Prefix
	Count       uint64
	LastIfindex uint32
	LastSeenNs  uint64
	LastReason  DenyReason
}

// SyncResult counts what SyncAllow changed.
type SyncResult struct {
	Added     int
	Updated   int
	Removed   int
	Unchanged int
}

// Tables are the five maps a Filter reads and writes.
type Tables struct {
	Allow       usidmap.Table
	UplinkSlots usidmap.Table
	Config      usidmap.Table
	Stats       usidmap.Table
	Denied      usidmap.Table
}

// Filter is the read/write API over the source filter maps. It holds no state
// of its own, so it is safe for concurrent use whenever its tables are.
type Filter struct {
	t Tables
}

// New returns a Filter over tables. Production callers use OpenPinned; tests
// pass fakes.
func New(tables Tables) *Filter {
	return &Filter{t: tables}
}

// IfaceMask returns the interface mask naming every slot in slots, or an error
// if any slot is MaxSlots or above.
func IfaceMask(slots ...uint8) (uint32, error) {
	var mask uint32
	for _, s := range slots {
		if int(s) >= MaxSlots {
			return 0, fmt.Errorf("srcfiltermap: uplink slot %d out of range [0,%d)", s, MaxSlots)
		}
		mask |= 1 << s
	}
	return mask, nil
}

func allowKey(p netip.Prefix) (prog.UsidSrcAllowKey, netip.Prefix, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() {
		return prog.UsidSrcAllowKey{}, netip.Prefix{}, fmt.Errorf("srcfiltermap: %s is not an IPv6 prefix", p)
	}
	p = p.Masked()
	return prog.UsidSrcAllowKey{Prefixlen: uint32(p.Bits()), Addr: p.Addr().As16()}, p, nil
}

func (e Entry) value() prog.UsidSrcAllowValue {
	v := prog.UsidSrcAllowValue{IfaceMask: e.IfaceMask}
	if e.AnyIface {
		v.Flags |= prog.SrcFilterFlagAnyIface
	}
	return v
}

// PutAllow creates or overwrites the allow entry for e.Prefix. It returns an
// error if e.Prefix is not an IPv6 prefix or the write fails.
func (f *Filter) PutAllow(e Entry) error {
	key, p, err := allowKey(e.Prefix)
	if err != nil {
		return err
	}
	if err := f.t.Allow.Put(key, e.value()); err != nil {
		return fmt.Errorf("srcfiltermap: src_allow_table: put %s: %w", p, err)
	}
	return nil
}

// DeleteAllow removes the allow entry for p. An absent entry is not an error.
func (f *Filter) DeleteAllow(p netip.Prefix) error {
	key, p, err := allowKey(p)
	if err != nil {
		return err
	}
	if err := f.t.Allow.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("srcfiltermap: src_allow_table: delete %s: %w", p, err)
	}
	return nil
}

// ListAllow returns every allow entry, sorted by prefix.
func (f *Filter) ListAllow() ([]Entry, error) {
	var (
		key     prog.UsidSrcAllowKey
		val     prog.UsidSrcAllowValue
		entries []Entry
	)
	it := f.t.Allow.Iterate()
	for it.Next(&key, &val) {
		p := netip.PrefixFrom(netip.AddrFrom16(key.Addr), int(key.Prefixlen))
		entries = append(entries, Entry{
			Prefix:    p,
			IfaceMask: val.IfaceMask,
			AnyIface:  val.Flags&prog.SrcFilterFlagAnyIface != 0,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("srcfiltermap: src_allow_table: iterate: %w", err)
	}
	slices.SortFunc(entries, func(a, b Entry) int { return a.Prefix.Compare(b.Prefix) })
	return entries, nil
}

// SyncAllow makes the allow-list exactly desired: it writes new and changed
// entries first and only then removes entries desired no longer names, so a
// prefix present in both the old and new sets is never briefly missing.
// Entries whose prefixes mask to the same value are an error, as is any
// invalid prefix; either leaves the map untouched.
func (f *Filter) SyncAllow(desired []Entry) (SyncResult, error) {
	want := make(map[netip.Prefix]Entry, len(desired))
	for _, e := range desired {
		_, p, err := allowKey(e.Prefix)
		if err != nil {
			return SyncResult{}, err
		}
		if _, dup := want[p]; dup {
			return SyncResult{}, fmt.Errorf("srcfiltermap: duplicate allow entry for %s", p)
		}
		e.Prefix = p
		want[p] = e
	}

	current, err := f.ListAllow()
	if err != nil {
		return SyncResult{}, err
	}
	have := make(map[netip.Prefix]Entry, len(current))
	for _, e := range current {
		have[e.Prefix] = e
	}

	var res SyncResult
	var errs []error
	for _, p := range sortedPrefixes(want) {
		e := want[p]
		old, ok := have[p]
		switch {
		case ok && old == e:
			res.Unchanged++
			continue
		case ok:
			res.Updated++
		default:
			res.Added++
		}
		if err := f.PutAllow(e); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	for _, p := range sortedPrefixes(have) {
		if _, ok := want[p]; ok {
			continue
		}
		if err := f.DeleteAllow(p); err != nil {
			errs = append(errs, err)
			continue
		}
		res.Removed++
	}
	return res, errors.Join(errs...)
}

func sortedPrefixes(m map[netip.Prefix]Entry) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}

// SetUplinkSlot assigns ifindex to slot, the bit an allow entry's interface
// mask uses to name it. It returns an error if slot is MaxSlots or above.
func (f *Filter) SetUplinkSlot(ifindex uint32, slot uint8) error {
	if int(slot) >= MaxSlots {
		return fmt.Errorf("srcfiltermap: uplink_slot_table: slot %d for ifindex %d out of range [0,%d)",
			slot, ifindex, MaxSlots)
	}
	if err := f.t.UplinkSlots.Put(ifindex, uint32(slot)); err != nil {
		return fmt.Errorf("srcfiltermap: uplink_slot_table: put ifindex %d: %w", ifindex, err)
	}
	return nil
}

// DeleteUplinkSlot removes ifindex's slot. An absent entry is not an error.
func (f *Filter) DeleteUplinkSlot(ifindex uint32) error {
	if err := f.t.UplinkSlots.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("srcfiltermap: uplink_slot_table: delete ifindex %d: %w", ifindex, err)
	}
	return nil
}

// UplinkSlots returns every ifindex-to-slot assignment.
func (f *Filter) UplinkSlots() (map[uint32]uint8, error) {
	var ifindex, slot uint32
	out := make(map[uint32]uint8)
	it := f.t.UplinkSlots.Iterate()
	for it.Next(&ifindex, &slot) {
		out[ifindex] = uint8(slot)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("srcfiltermap: uplink_slot_table: iterate: %w", err)
	}
	return out, nil
}

// SyncUplinkSlots makes the slot assignments exactly desired, writing before
// deleting. Two interfaces sharing a slot is an error and leaves the map
// untouched.
func (f *Filter) SyncUplinkSlots(desired map[uint32]uint8) error {
	owner := make(map[uint8]uint32, len(desired))
	for ifindex, slot := range desired {
		if int(slot) >= MaxSlots {
			return fmt.Errorf("srcfiltermap: uplink slot %d for ifindex %d out of range [0,%d)", slot, ifindex, MaxSlots)
		}
		if other, dup := owner[slot]; dup {
			return fmt.Errorf("srcfiltermap: uplink slot %d assigned to both ifindex %d and %d",
				slot, min(other, ifindex), max(other, ifindex))
		}
		owner[slot] = ifindex
	}

	current, err := f.UplinkSlots()
	if err != nil {
		return err
	}
	var errs []error
	for ifindex, slot := range desired {
		if cur, ok := current[ifindex]; ok && cur == slot {
			continue
		}
		if err := f.SetUplinkSlot(ifindex, slot); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	for ifindex := range current {
		if _, ok := desired[ifindex]; ok {
			continue
		}
		if err := f.DeleteUplinkSlot(ifindex); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Config returns the filter's global state. A never-written config reads as
// ModeOff and unpopulated.
func (f *Filter) Config() (Config, error) {
	var v prog.UsidSrcFilterConfig
	if err := f.t.Config.Lookup(configKey, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("srcfiltermap: src_filter_config_table: lookup: %w", err)
	}
	return Config{Mode: Mode(v.Mode), Populated: v.Populated != 0, Generation: v.Generation}, nil
}

// SetConfig writes the filter's global state. It returns an error for an
// unknown mode.
func (f *Filter) SetConfig(c Config) error {
	if !c.Mode.valid() {
		return fmt.Errorf("srcfiltermap: src_filter_config_table: invalid mode %s", c.Mode)
	}
	v := prog.UsidSrcFilterConfig{Mode: uint32(c.Mode), Generation: c.Generation}
	if c.Populated {
		v.Populated = 1
	}
	if err := f.t.Config.Put(configKey, v); err != nil {
		return fmt.Errorf("srcfiltermap: src_filter_config_table: put: %w", err)
	}
	return nil
}

// Stats returns the datapath's decision counters summed across CPUs.
func (f *Filter) Stats() (Stats, error) {
	read := func(slot uint32) (uint64, error) {
		var perCPU []uint64
		if err := f.t.Stats.Lookup(slot, &perCPU); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return 0, nil
			}
			return 0, fmt.Errorf("srcfiltermap: src_filter_stats: lookup %s: %w",
				prog.SrcFilterStatNames[slot], err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total, nil
	}

	var (
		s    Stats
		errs []error
	)
	for slot, dst := range map[uint32]*uint64{
		prog.SrcFilterStatChecked:           &s.Checked,
		prog.SrcFilterStatAllowed:           &s.Allowed,
		prog.SrcFilterStatDenyPrefix:        &s.DenyPrefix,
		prog.SrcFilterStatDenyIface:         &s.DenyIface,
		prog.SrcFilterStatBypassUnpopulated: &s.BypassUnpopulated,
	} {
		v, err := read(slot)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*dst = v
	}
	return s, errors.Join(errs...)
}

// DeniedSources returns every recorded denied source /64, most denials first.
func (f *Filter) DeniedSources() ([]DeniedSource, error) {
	var (
		key prog.UsidSrcDeniedKey
		val prog.UsidSrcDeniedValue
		out []DeniedSource
	)
	it := f.t.Denied.Iterate()
	for it.Next(&key, &val) {
		var a [16]byte
		copy(a[:], key.Prefix[:])
		out = append(out, DeniedSource{
			Prefix:      netip.PrefixFrom(netip.AddrFrom16(a), deniedPrefixBits),
			Count:       val.Count,
			LastIfindex: val.LastIfindex,
			LastSeenNs:  val.LastNs,
			LastReason:  DenyReason(val.LastReason),
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("srcfiltermap: src_filter_denied: iterate: %w", err)
	}
	slices.SortFunc(out, func(a, b DeniedSource) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return a.Prefix.Compare(b.Prefix)
	})
	return out, nil
}
