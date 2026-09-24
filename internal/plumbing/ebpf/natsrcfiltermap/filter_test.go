// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natsrcfiltermap

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      Mode
		wantError bool
	}{
		{"Empty", "", ModeOff, false},
		{"Off", modeNameOff, ModeOff, false},
		{"Audit", modeNameAudit, ModeAudit, false},
		{"EnforceMixedCase", " Enforce ", ModeEnforce, false},
		{"Unknown", "strict", ModeOff, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMode(tt.input)
			if (err != nil) != tt.wantError {
				t.Fatalf("ParseMode(%q) error = %v, wantError = %v", tt.input, err, tt.wantError)
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
			if !tt.wantError {
				if back, _ := ParseMode(got.String()); back != got {
					t.Errorf("ParseMode(%q.String()) = %v, want %v", got, back, got)
				}
			}
		})
	}
}

func TestSlotMask(t *testing.T) {
	tests := []struct {
		name      string
		slots     []uint8
		want      uint32
		wantError bool
	}{
		{"None", nil, 0, false},
		{"FirstAndLast", []uint8{0, 31}, 1 | 1<<31, false},
		{"OutOfRange", []uint8{32}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SlotMask(tt.slots...)
			if (err != nil) != tt.wantError {
				t.Fatalf("SlotMask(%v) error = %v, wantError = %v", tt.slots, err, tt.wantError)
			}
			if got != tt.want {
				t.Errorf("SlotMask(%v) = %#x, want %#x", tt.slots, got, tt.want)
			}
		})
	}
}

func TestPutAllowEncodesAndMasks(t *testing.T) {
	f, fakes := NewFakeFilter()

	if err := f.PutAllow(netip.MustParsePrefix("fc00:0:0:1:ffff::/64"), Binding{Slots: 0b101}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}
	if err := f.PutAllow(netip.MustParsePrefix("fc00:0:1::/48"), Binding{AnyInterface: true}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}

	var value natprog.NatSrcAllowValue
	key := natprog.NatSrcAllowKey{Prefixlen: 64, Addr: netip.MustParseAddr("fc00:0:0:1::").As16()}
	if err := fakes.Allow.Lookup(key, &value); err != nil {
		t.Fatalf("masked key not stored: %v", err)
	}
	if value.IfaceMask != 0b101 || value.Flags != 0 {
		t.Errorf("value = %+v, want mask 0b101 and no flags", value)
	}

	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	want := []AllowEntry{
		{Prefix: netip.MustParsePrefix("fc00:0:0:1::/64"), Binding: Binding{Slots: 0b101}},
		{Prefix: netip.MustParsePrefix("fc00:0:1::/48"), Binding: Binding{AnyInterface: true}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListAllow = %+v, want %+v", got, want)
	}
}

func TestPutAllowRejects(t *testing.T) {
	tests := []struct {
		name    string
		prefix  netip.Prefix
		binding Binding
	}{
		{"IPv4Prefix", netip.MustParsePrefix("192.0.2.0/24"), Binding{AnyInterface: true}},
		{"MappedPrefix", netip.MustParsePrefix("::ffff:192.0.2.0/120"), Binding{AnyInterface: true}},
		{"InvalidPrefix", netip.Prefix{}, Binding{AnyInterface: true}},
		{"NoUplink", netip.MustParsePrefix("fc00::/48"), Binding{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, fakes := NewFakeFilter()
			if err := f.PutAllow(tt.prefix, tt.binding); err == nil {
				t.Errorf("PutAllow(%s, %+v) succeeded, want error", tt.prefix, tt.binding)
			}
			if fakes.Allow.Len() != 0 {
				t.Errorf("rejected entry was written")
			}
		})
	}
}

func TestDeleteAllowToleratesAbsent(t *testing.T) {
	f, fakes := NewFakeFilter()
	prefix := netip.MustParsePrefix("fc00:0:0:1::/64")

	if err := f.DeleteAllow(prefix); err != nil {
		t.Fatalf("DeleteAllow(absent): %v", err)
	}
	if err := f.PutAllow(prefix, Binding{Slots: 1}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}
	if err := f.DeleteAllow(prefix); err != nil {
		t.Fatalf("DeleteAllow: %v", err)
	}
	if fakes.Allow.Len() != 0 {
		t.Errorf("entry survived DeleteAllow")
	}
}

func TestSyncUplinkSlots(t *testing.T) {
	f, _ := NewFakeFilter()

	if err := f.SyncUplinkSlots(map[uint32]uint8{2: 0, 3: 1, 7: 2}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	if err := f.SyncUplinkSlots(map[uint32]uint8{3: 0, 9: 1}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	got, err := f.UplinkSlots()
	if err != nil {
		t.Fatalf("UplinkSlots: %v", err)
	}
	want := map[uint32]uint8{3: 0, 9: 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UplinkSlots = %v, want %v", got, want)
	}
}

func TestSyncUplinkSlotsRejectsBeforeWriting(t *testing.T) {
	tests := []struct {
		name  string
		slots map[uint32]uint8
	}{
		{"ZeroIfindex", map[uint32]uint8{0: 0, 2: 1}},
		{"SlotOutOfRange", map[uint32]uint8{2: 32}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, fakes := NewFakeFilter()
			if err := f.SyncUplinkSlots(tt.slots); err == nil {
				t.Errorf("SyncUplinkSlots(%v) succeeded, want error", tt.slots)
			}
			if fakes.UplinkSlots.Len() != 0 {
				t.Errorf("rejected sync wrote entries")
			}
		})
	}
}

func TestConfigModeAndPopulated(t *testing.T) {
	f, _ := NewFakeFilter()

	cfg, err := f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg != (Config{}) {
		t.Errorf("unwritten Config = %+v, want zero (off, unpopulated)", cfg)
	}

	if err := f.MarkPopulated(7); err != nil {
		t.Fatalf("MarkPopulated: %v", err)
	}
	if err := f.SetMode(ModeEnforce); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	cfg, err = f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if want := (Config{Mode: ModeEnforce, Populated: true, Generation: 7}); cfg != want {
		t.Errorf("Config = %+v, want %+v", cfg, want)
	}

	if err := f.MarkUnpopulated(); err != nil {
		t.Fatalf("MarkUnpopulated: %v", err)
	}
	cfg, err = f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if want := (Config{Mode: ModeEnforce, Generation: 7}); cfg != want {
		t.Errorf("Config after MarkUnpopulated = %+v, want %+v", cfg, want)
	}

	if err := f.SetMode(Mode(9)); err == nil {
		t.Errorf("SetMode(9) succeeded, want error")
	}
}

func TestStatsSumsAcrossCPUs(t *testing.T) {
	f, fakes := NewFakeFilter()
	fakes.Stats.Set(natprog.SrcStatChecked, 4, 6)
	fakes.Stats.Set(natprog.SrcStatAllowed, 3, 1)
	fakes.Stats.Set(natprog.SrcStatDenyPrefix, 1, 0)
	fakes.Stats.Set(natprog.SrcStatDenyInterface, 0, 2)
	fakes.Stats.Set(natprog.SrcStatDenyStructure, 1, 1)
	fakes.Stats.Set(natprog.SrcStatBypassUnpopulated, 0, 0)

	got, err := f.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	want := Stats{Checked: 10, Allowed: 4, DenyPrefix: 1, DenyInterface: 2, DenyStructure: 2}
	if got != want {
		t.Errorf("Stats = %+v, want %+v", got, want)
	}
}

func TestDeniedDecodesMostRecentFirst(t *testing.T) {
	f, fakes := NewFakeFilter()

	older := natprog.NatSrcDeniedKey{}
	copy(older.Locator[:], netip.MustParseAddr("fc00:0:0:1::").AsSlice()[:8])
	newer := natprog.NatSrcDeniedKey{}
	copy(newer.Locator[:], netip.MustParseAddr("fc00:0:0:2::").AsSlice()[:8])

	_ = fakes.Denied.Put(older, natprog.NatSrcDeniedValue{
		Packets: 3, LastSeenNs: 100, LastReason: natprog.SrcStatDenyPrefix, LastIfindex: 2,
	})
	_ = fakes.Denied.Put(newer, natprog.NatSrcDeniedValue{
		Packets: 1, LastSeenNs: 200, LastReason: natprog.SrcStatDenyInterface, LastIfindex: 4,
	})

	got, err := f.Denied()
	if err != nil {
		t.Fatalf("Denied: %v", err)
	}
	want := []DeniedSource{
		{
			Locator: netip.MustParsePrefix("fc00:0:0:2::/64"), Packets: 1,
			LastSeen: 200 * time.Nanosecond, LastReason: "deny_interface", LastIfindex: 4,
		},
		{
			Locator: netip.MustParsePrefix("fc00:0:0:1::/64"), Packets: 3,
			LastSeen: 100 * time.Nanosecond, LastReason: "deny_prefix", LastIfindex: 2,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Denied = %+v, want %+v", got, want)
	}
}
