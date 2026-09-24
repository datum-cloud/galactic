// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfiltermap

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		in        string
		want      Mode
		wantError bool
	}{
		{"off", ModeOff, false},
		{"Audit", ModeAudit, false},
		{" enforce ", ModeEnforce, false},
		{"", ModeOff, true},
		{"drop", ModeOff, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseMode(tt.in)
			if (err != nil) != tt.wantError {
				t.Fatalf("ParseMode(%q) error = %v, wantError = %v", tt.in, err, tt.wantError)
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestIfaceMask(t *testing.T) {
	tests := []struct {
		name      string
		slots     []uint8
		want      uint32
		wantError bool
	}{
		{"None", nil, 0, false},
		{"Single", []uint8{3}, 1 << 3, false},
		{"Several", []uint8{0, 5, 31}, 1 | 1<<5 | 1<<31, false},
		{"OutOfRange", []uint8{32}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IfaceMask(tt.slots...)
			if (err != nil) != tt.wantError {
				t.Fatalf("IfaceMask(%v) error = %v, wantError = %v", tt.slots, err, tt.wantError)
			}
			if got != tt.want {
				t.Errorf("IfaceMask(%v) = %#x, want %#x", tt.slots, got, tt.want)
			}
		})
	}
}

func TestPutAllow(t *testing.T) {
	f, tables := NewFake()

	if err := f.PutAllow(Entry{Prefix: netip.MustParsePrefix("fd00:aa:1::5/48"), IfaceMask: 1 << 2}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}
	if err := f.PutAllow(Entry{Prefix: netip.MustParsePrefix("fd00:bb::/32"), AnyIface: true}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}

	var v prog.UsidSrcAllowValue
	key := prog.UsidSrcAllowKey{Prefixlen: 48, Addr: netip.MustParseAddr("fd00:aa:1::").As16()}
	if err := tables.Allow.Lookup(key, &v); err != nil {
		t.Fatalf("stored key not masked: %v", err)
	}
	if v.IfaceMask != 1<<2 || v.Flags != 0 {
		t.Errorf("stored value = %+v, want mask 0x4 and no flags", v)
	}
	key = prog.UsidSrcAllowKey{Prefixlen: 32, Addr: netip.MustParseAddr("fd00:bb::").As16()}
	if err := tables.Allow.Lookup(key, &v); err != nil {
		t.Fatalf("lookup any-iface entry: %v", err)
	}
	if v.Flags != prog.SrcFilterFlagAnyIface {
		t.Errorf("stored flags = %#x, want SrcFilterFlagAnyIface", v.Flags)
	}

	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	want := []Entry{
		{Prefix: netip.MustParsePrefix("fd00:aa:1::/48"), IfaceMask: 1 << 2},
		{Prefix: netip.MustParsePrefix("fd00:bb::/32"), AnyIface: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListAllow = %+v, want %+v", got, want)
	}
}

func TestPutAllowRejectsNonIPv6(t *testing.T) {
	f, _ := NewFake()
	for _, p := range []netip.Prefix{
		{},
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::ffff:10.0.0.0/104"),
	} {
		if err := f.PutAllow(Entry{Prefix: p, AnyIface: true}); err == nil {
			t.Errorf("PutAllow(%s) succeeded, want error", p)
		}
	}
}

func TestDeleteAllowAbsentIsNotError(t *testing.T) {
	f, _ := NewFake()
	if err := f.DeleteAllow(netip.MustParsePrefix("fd00::/16")); err != nil {
		t.Errorf("DeleteAllow on absent entry: %v", err)
	}
}

func TestSyncAllow(t *testing.T) {
	f, tables := NewFake()
	keep := Entry{Prefix: netip.MustParsePrefix("fd00:1::/32"), IfaceMask: 1}
	change := Entry{Prefix: netip.MustParsePrefix("fd00:2::/32"), IfaceMask: 1}
	stale := Entry{Prefix: netip.MustParsePrefix("fd00:3::/32"), IfaceMask: 1}
	for _, e := range []Entry{keep, change, stale} {
		if err := f.PutAllow(e); err != nil {
			t.Fatalf("seed %s: %v", e.Prefix, err)
		}
	}

	changed := Entry{Prefix: change.Prefix, IfaceMask: 1 | 1<<1}
	added := Entry{Prefix: netip.MustParsePrefix("fd00:4::/32"), AnyIface: true}
	res, err := f.SyncAllow([]Entry{keep, changed, added})
	if err != nil {
		t.Fatalf("SyncAllow: %v", err)
	}
	if want := (SyncResult{Added: 1, Updated: 1, Removed: 1, Unchanged: 1}); res != want {
		t.Errorf("SyncAllow result = %+v, want %+v", res, want)
	}
	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if want := []Entry{keep, changed, added}; !reflect.DeepEqual(got, want) {
		t.Errorf("after sync = %+v, want %+v", got, want)
	}
	if n := tables.Allow.(*FakeTable).Len(); n != 3 {
		t.Errorf("table holds %d entries, want 3", n)
	}
}

func TestSyncAllowRejectsInvalidInputUntouched(t *testing.T) {
	tests := []struct {
		name    string
		desired []Entry
	}{
		{"Duplicate", []Entry{
			{Prefix: netip.MustParsePrefix("fd00:1::1/32")},
			{Prefix: netip.MustParsePrefix("fd00:1::2/32")},
		}},
		{"IPv4", []Entry{{Prefix: netip.MustParsePrefix("10.0.0.0/8")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, tables := NewFake()
			seed := Entry{Prefix: netip.MustParsePrefix("fd00:9::/32"), AnyIface: true}
			if err := f.PutAllow(seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := f.SyncAllow(tt.desired); err == nil {
				t.Fatal("SyncAllow succeeded, want error")
			}
			if n := tables.Allow.(*FakeTable).Len(); n != 1 {
				t.Errorf("table holds %d entries, want the untouched seed only", n)
			}
		})
	}
}

func TestSyncAllowWriteFailureKeepsStaleEntries(t *testing.T) {
	f, tables := NewFake()
	stale := Entry{Prefix: netip.MustParsePrefix("fd00:3::/32"), AnyIface: true}
	if err := f.PutAllow(stale); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tables.Allow.(*FakeTable).PutErr = errors.New("map full")

	if _, err := f.SyncAllow([]Entry{{Prefix: netip.MustParsePrefix("fd00:4::/32"), AnyIface: true}}); err == nil {
		t.Fatal("SyncAllow succeeded, want the write error")
	}
	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if want := []Entry{stale}; !reflect.DeepEqual(got, want) {
		t.Errorf("after failed sync = %+v, want stale entry kept: %+v", got, want)
	}
}

func TestUplinkSlots(t *testing.T) {
	f, _ := NewFake()
	if err := f.SetUplinkSlot(7, 32); err == nil {
		t.Error("SetUplinkSlot with slot 32 succeeded, want error")
	}
	if err := f.SetUplinkSlot(7, 0); err != nil {
		t.Fatalf("SetUplinkSlot: %v", err)
	}
	if err := f.SetUplinkSlot(9, 1); err != nil {
		t.Fatalf("SetUplinkSlot: %v", err)
	}

	if err := f.SyncUplinkSlots(map[uint32]uint8{7: 0, 11: 2}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	got, err := f.UplinkSlots()
	if err != nil {
		t.Fatalf("UplinkSlots: %v", err)
	}
	if want := map[uint32]uint8{7: 0, 11: 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("UplinkSlots = %v, want %v", got, want)
	}

	if err := f.SyncUplinkSlots(map[uint32]uint8{7: 1, 11: 1}); err == nil {
		t.Error("SyncUplinkSlots with a shared slot succeeded, want error")
	}
	if err := f.DeleteUplinkSlot(7); err != nil {
		t.Errorf("DeleteUplinkSlot: %v", err)
	}
	if err := f.DeleteUplinkSlot(7); err != nil {
		t.Errorf("DeleteUplinkSlot on absent entry: %v", err)
	}
}

func TestConfig(t *testing.T) {
	f, _ := NewFake()

	got, err := f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got != (Config{}) {
		t.Errorf("unwritten Config = %+v, want off and unpopulated", got)
	}

	want := Config{Mode: ModeAudit, Populated: true, Generation: 4}
	if err := f.SetConfig(want); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if got, err = f.Config(); err != nil || got != want {
		t.Errorf("Config = %+v, %v, want %+v", got, err, want)
	}

	if err := f.SetConfig(Config{Mode: Mode(9)}); err == nil {
		t.Error("SetConfig with an unknown mode succeeded, want error")
	}
}

func TestStats(t *testing.T) {
	f, tables := NewFake()
	seed := map[uint32][]uint64{
		prog.SrcFilterStatChecked:           {3, 4},
		prog.SrcFilterStatAllowed:           {2, 1},
		prog.SrcFilterStatDenyPrefix:        {1, 0},
		prog.SrcFilterStatDenyIface:         {0, 2},
		prog.SrcFilterStatBypassUnpopulated: {0, 1},
	}
	for slot, v := range seed {
		if err := tables.Stats.Put(slot, v); err != nil {
			t.Fatalf("seed stats: %v", err)
		}
	}

	got, err := f.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	want := Stats{Checked: 7, Allowed: 3, DenyPrefix: 1, DenyIface: 2, BypassUnpopulated: 1}
	if got != want {
		t.Errorf("Stats = %+v, want %+v", got, want)
	}
}

func TestDeniedSources(t *testing.T) {
	f, tables := NewFake()
	put := func(src string, v prog.UsidSrcDeniedValue) {
		t.Helper()
		var key prog.UsidSrcDeniedKey
		a := netip.MustParseAddr(src).As16()
		copy(key.Prefix[:], a[:8])
		if err := tables.Denied.Put(key, v); err != nil {
			t.Fatalf("seed denied: %v", err)
		}
	}
	put("2001:db8:1:2::9", prog.UsidSrcDeniedValue{Count: 2, LastNs: 10, LastIfindex: 4,
		LastReason: prog.SrcFilterStatDenyPrefix})
	put("fd00:aa:1:2::1", prog.UsidSrcDeniedValue{Count: 5, LastNs: 20, LastIfindex: 5,
		LastReason: prog.SrcFilterStatDenyIface})

	got, err := f.DeniedSources()
	if err != nil {
		t.Fatalf("DeniedSources: %v", err)
	}
	want := []DeniedSource{
		{Prefix: netip.MustParsePrefix("fd00:aa:1:2::/64"), Count: 5, LastIfindex: 5, LastSeenNs: 20,
			LastReason: DenyReasonIface},
		{Prefix: netip.MustParsePrefix("2001:db8:1:2::/64"), Count: 2, LastIfindex: 4, LastSeenNs: 10,
			LastReason: DenyReasonPrefix},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DeniedSources = %+v, want %+v", got, want)
	}
	if got[0].LastReason.String() != "deny_iface" {
		t.Errorf("reason name = %q, want deny_iface", got[0].LastReason)
	}
}
