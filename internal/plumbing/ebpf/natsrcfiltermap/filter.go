// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natsrcfiltermap

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// configKey is nat_src_filter_config's single fixed key.
const configKey uint32 = 0

// Configuration names of each Mode.
const (
	modeNameOff     = "off"
	modeNameAudit   = "audit"
	modeNameEnforce = "enforce"
)

// Mode is the source filter's operating mode.
type Mode uint32

const (
	// ModeOff leaves the dispatcher's behaviour unchanged.
	ModeOff = Mode(natprog.SrcFilterModeOff)
	// ModeAudit counts every decision and forwards everything.
	ModeAudit = Mode(natprog.SrcFilterModeAudit)
	// ModeEnforce drops every packet whose source fails a check.
	ModeEnforce = Mode(natprog.SrcFilterModeEnforce)
)

// String returns the mode's configuration name.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return modeNameOff
	case ModeAudit:
		return modeNameAudit
	case ModeEnforce:
		return modeNameEnforce
	default:
		return fmt.Sprintf("unknown(%d)", uint32(m))
	}
}

// ParseMode parses off, audit or enforce, case-insensitively. An empty string
// is off. Any other value is an error.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", modeNameOff:
		return ModeOff, nil
	case modeNameAudit:
		return ModeAudit, nil
	case modeNameEnforce:
		return ModeEnforce, nil
	default:
		return ModeOff, fmt.Errorf("unknown SRv6 source filter mode %q (want off, audit or enforce)", s)
	}
}

// Binding is the set of uplinks an allowed prefix may arrive on.
type Binding struct {
	// Slots holds one bit per uplink slot, bit N being slot N.
	Slots uint32

	// AnyInterface accepts the prefix on every uplink, ignoring Slots.
	AnyInterface bool
}

// SlotMask returns the interface mask naming each slot in slots. It returns an
// error for a slot above natprog.SrcFilterMaxSlot.
func SlotMask(slots ...uint8) (uint32, error) {
	var mask uint32
	for _, s := range slots {
		if s > natprog.SrcFilterMaxSlot {
			return 0, fmt.Errorf("uplink slot %d out of range [0,%d]", s, natprog.SrcFilterMaxSlot)
		}
		mask |= 1 << s
	}
	return mask, nil
}

// AllowEntry is one allow-list entry.
type AllowEntry struct {
	Prefix  netip.Prefix
	Binding Binding
}

// Config is nat_src_filter_config's decoded state.
type Config struct {
	Mode       Mode
	Populated  bool
	Generation uint64
}

// Stats is the per-CPU summed value of every decision counter.
type Stats struct {
	Checked           uint64
	Allowed           uint64
	DenyPrefix        uint64
	DenyInterface     uint64
	DenyStructure     uint64
	BypassUnpopulated uint64
}

// DeniedSource is one entry of the denied-source record: the sending
// locator, the top 64 bits of the source, and its most recent denial.
type DeniedSource struct {
	Locator     netip.Prefix
	Packets     uint64
	LastSeen    time.Duration
	LastReason  string
	LastIfindex uint32
}

// Tables names the maps a Filter operates on.
type Tables struct {
	Allow       Table
	UplinkSlots Table
	Config      Table
	Stats       PerCPUReader
	Denied      Table
}

// Filter is the typed API over the source filter's maps. Its methods are safe
// for concurrent use.
type Filter struct {
	mu sync.Mutex
	t  Tables
}

// NewFilter returns a Filter over tables.
func NewFilter(tables Tables) *Filter {
	return &Filter{t: tables}
}

// NewKernelFilter returns a Filter over a loaded object set's maps.
func NewKernelFilter(objs *natprog.NatObjects) *Filter {
	return NewFilter(Tables{
		Allow:       KernelTable{Map: objs.NatSrcAllow},
		UplinkSlots: KernelTable{Map: objs.NatUplinkSlot},
		Config:      KernelTable{Map: objs.NatSrcFilterConfig},
		Stats:       objs.NatSrcFilterStats,
		Denied:      KernelTable{Map: objs.NatSrcDenied},
	})
}

// allowKey validates prefix and encodes it as an LPM key. The prefix must be a
// native IPv6 prefix; host bits below its length are masked off.
func allowKey(prefix netip.Prefix) (natprog.NatSrcAllowKey, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return natprog.NatSrcAllowKey{}, fmt.Errorf("allow prefix %s is not a native IPv6 prefix", prefix)
	}
	masked := prefix.Masked()
	return natprog.NatSrcAllowKey{
		Prefixlen: uint32(masked.Bits()),
		Addr:      masked.Addr().As16(),
	}, nil
}

// PutAllow creates or replaces the allow-list entry for prefix. It returns an
// error if prefix is not a native IPv6 prefix, or if binding names no uplink
// and does not accept any.
func (f *Filter) PutAllow(prefix netip.Prefix, binding Binding) error {
	key, err := allowKey(prefix)
	if err != nil {
		return fmt.Errorf("natsrcfiltermap: put allow: %w", err)
	}
	if binding.Slots == 0 && !binding.AnyInterface {
		return fmt.Errorf("natsrcfiltermap: put allow %s: binding names no uplink", prefix)
	}
	value := natprog.NatSrcAllowValue{IfaceMask: binding.Slots}
	if binding.AnyInterface {
		value.Flags |= natprog.SrcAllowFlagAnyInterface
	}
	if err := f.t.Allow.Put(key, value); err != nil {
		return fmt.Errorf("natsrcfiltermap: put allow %s: %w", prefix, err)
	}
	return nil
}

// DeleteAllow removes the allow-list entry for prefix. Deleting an absent
// entry is not an error.
func (f *Filter) DeleteAllow(prefix netip.Prefix) error {
	key, err := allowKey(prefix)
	if err != nil {
		return fmt.Errorf("natsrcfiltermap: delete allow: %w", err)
	}
	if err := f.t.Allow.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("natsrcfiltermap: delete allow %s: %w", prefix, err)
	}
	return nil
}

// ListAllow returns every allow-list entry, sorted by prefix.
func (f *Filter) ListAllow() ([]AllowEntry, error) {
	var (
		key     natprog.NatSrcAllowKey
		value   natprog.NatSrcAllowValue
		entries []AllowEntry
	)
	it := f.t.Allow.Iterate()
	for it.Next(&key, &value) {
		entries = append(entries, AllowEntry{
			Prefix: netip.PrefixFrom(netip.AddrFrom16(key.Addr), int(key.Prefixlen)),
			Binding: Binding{
				Slots:        value.IfaceMask,
				AnyInterface: value.Flags&natprog.SrcAllowFlagAnyInterface != 0,
			},
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natsrcfiltermap: list allow: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Prefix.String() < entries[j].Prefix.String()
	})
	return entries, nil
}

// SyncUplinkSlots makes nat_uplink_slot hold exactly slots, keyed by ifindex:
// every entry is written and any ifindex not in slots is removed. It returns an
// error for a zero ifindex or a slot above natprog.SrcFilterMaxSlot, before
// writing anything.
func (f *Filter) SyncUplinkSlots(slots map[uint32]uint8) error {
	for ifindex, slot := range slots {
		if ifindex == 0 {
			return errors.New("natsrcfiltermap: sync uplink slots: ifindex 0 is not an interface")
		}
		if slot > natprog.SrcFilterMaxSlot {
			return fmt.Errorf("natsrcfiltermap: sync uplink slots: ifindex %d slot %d out of range [0,%d]",
				ifindex, slot, natprog.SrcFilterMaxSlot)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	current, err := f.uplinkSlots()
	if err != nil {
		return fmt.Errorf("natsrcfiltermap: sync uplink slots: %w", err)
	}
	for ifindex, slot := range slots {
		if err := f.t.UplinkSlots.Put(ifindex, uint32(slot)); err != nil {
			return fmt.Errorf("natsrcfiltermap: sync uplink slots: put ifindex %d: %w", ifindex, err)
		}
	}
	for ifindex := range current {
		if _, keep := slots[ifindex]; keep {
			continue
		}
		if err := f.t.UplinkSlots.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("natsrcfiltermap: sync uplink slots: delete ifindex %d: %w", ifindex, err)
		}
	}
	return nil
}

// UplinkSlots returns every ifindex-to-slot entry.
func (f *Filter) UplinkSlots() (map[uint32]uint8, error) {
	slots, err := f.uplinkSlots()
	if err != nil {
		return nil, fmt.Errorf("natsrcfiltermap: uplink slots: %w", err)
	}
	return slots, nil
}

func (f *Filter) uplinkSlots() (map[uint32]uint8, error) {
	var ifindex, slot uint32
	out := make(map[uint32]uint8)
	it := f.t.UplinkSlots.Iterate()
	for it.Next(&ifindex, &slot) {
		out[ifindex] = uint8(slot)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Config returns the filter's current mode and sync state. An unwritten
// config reads as off and unpopulated.
func (f *Filter) Config() (Config, error) {
	raw, err := f.readConfig()
	if err != nil {
		return Config{}, fmt.Errorf("natsrcfiltermap: config: %w", err)
	}
	return Config{
		Mode:       Mode(raw.Mode),
		Populated:  raw.Populated != 0,
		Generation: raw.Generation,
	}, nil
}

func (f *Filter) readConfig() (natprog.NatSrcFilterConfig, error) {
	var raw natprog.NatSrcFilterConfig
	if err := f.t.Config.Lookup(configKey, &raw); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return natprog.NatSrcFilterConfig{}, err
	}
	return raw, nil
}

// updateConfig applies mutate to the current config and writes it back. The
// datapath only reads this map, so a read-modify-write under f.mu is the only
// writer.
func (f *Filter) updateConfig(mutate func(*natprog.NatSrcFilterConfig)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := f.readConfig()
	if err != nil {
		return err
	}
	mutate(&raw)
	return f.t.Config.Put(configKey, raw)
}

// SetMode sets the filter's mode, leaving its sync state as it is. It returns
// an error for a mode other than ModeOff, ModeAudit or ModeEnforce.
func (f *Filter) SetMode(mode Mode) error {
	if mode != ModeOff && mode != ModeAudit && mode != ModeEnforce {
		return fmt.Errorf("natsrcfiltermap: set mode: unknown mode %d", uint32(mode))
	}
	if err := f.updateConfig(func(c *natprog.NatSrcFilterConfig) { c.Mode = uint32(mode) }); err != nil {
		return fmt.Errorf("natsrcfiltermap: set mode: %w", err)
	}
	return nil
}

// MarkPopulated records that a full allow-list sync has landed, arming the
// prefix and interface checks, and stores generation as that sync's
// identifier.
func (f *Filter) MarkPopulated(generation uint64) error {
	err := f.updateConfig(func(c *natprog.NatSrcFilterConfig) {
		c.Populated = 1
		c.Generation = generation
	})
	if err != nil {
		return fmt.Errorf("natsrcfiltermap: mark populated: %w", err)
	}
	return nil
}

// MarkUnpopulated disarms the prefix and interface checks, returning the filter
// to its structural checks alone.
func (f *Filter) MarkUnpopulated() error {
	if err := f.updateConfig(func(c *natprog.NatSrcFilterConfig) { c.Populated = 0 }); err != nil {
		return fmt.Errorf("natsrcfiltermap: mark unpopulated: %w", err)
	}
	return nil
}

// Stats returns every decision counter, summed across CPUs.
func (f *Filter) Stats() (Stats, error) {
	var totals [natprog.SrcStatCount]uint64
	for i := range natprog.SrcStatCount {
		var perCPU []uint64
		if err := f.t.Stats.Lookup(i, &perCPU); err != nil {
			return Stats{}, fmt.Errorf("natsrcfiltermap: stats: lookup[%d]: %w", i, err)
		}
		for _, v := range perCPU {
			totals[i] += v
		}
	}
	return Stats{
		Checked:           totals[natprog.SrcStatChecked],
		Allowed:           totals[natprog.SrcStatAllowed],
		DenyPrefix:        totals[natprog.SrcStatDenyPrefix],
		DenyInterface:     totals[natprog.SrcStatDenyInterface],
		DenyStructure:     totals[natprog.SrcStatDenyStructure],
		BypassUnpopulated: totals[natprog.SrcStatBypassUnpopulated],
	}, nil
}

// Denied returns the denied-source record, most recent first. LastSeen is the
// kernel's monotonic clock at the denial, not wall time.
func (f *Filter) Denied() ([]DeniedSource, error) {
	var (
		key   natprog.NatSrcDeniedKey
		value natprog.NatSrcDeniedValue
		out   []DeniedSource
	)
	it := f.t.Denied.Iterate()
	for it.Next(&key, &value) {
		var addr [16]byte
		copy(addr[:8], key.Locator[:])
		reason := natprog.SrcStatNames[value.LastReason]
		if reason == "" {
			reason = fmt.Sprintf("unknown_%d", value.LastReason)
		}
		out = append(out, DeniedSource{
			Locator:     netip.PrefixFrom(netip.AddrFrom16(addr), 64),
			Packets:     value.Packets,
			LastSeen:    time.Duration(value.LastSeenNs),
			LastReason:  reason,
			LastIfindex: value.LastIfindex,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natsrcfiltermap: denied: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out, nil
}
