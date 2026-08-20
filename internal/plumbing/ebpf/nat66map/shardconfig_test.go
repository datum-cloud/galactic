// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"net/netip"
	"strings"
	"testing"
)

func TestShardConfigTable_SetAndGet(t *testing.T) {
	table := NewShardConfigTable(newFakeTable())

	cfg := ShardConfig{
		ShardSID:     netip.MustParseAddr("fc00:1:2::1"),
		ShardPubAddr: netip.MustParseAddr("2001:db8:9999::1"),
	}
	if err := table.Set(cfg); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, ok, err := table.Get()
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true after Set")
	}
	if got != cfg {
		t.Errorf("Get() = %+v, want %+v", got, cfg)
	}
}

func TestShardConfigTable_GetBeforeSet(t *testing.T) {
	table := NewShardConfigTable(newFakeTable())

	got, ok, err := table.Get()
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Errorf("Get() ok = true, want false before any Set; got %+v", got)
	}
}

func TestShardConfigTable_SetOverwrites(t *testing.T) {
	table := NewShardConfigTable(newFakeTable())

	first := ShardConfig{
		ShardSID:     netip.MustParseAddr("fc00:1:2::1"),
		ShardPubAddr: netip.MustParseAddr("2001:db8:9999::1"),
	}
	second := ShardConfig{
		ShardSID:     netip.MustParseAddr("fc00:3:4::1"),
		ShardPubAddr: netip.MustParseAddr("2001:db8:8888::1"),
	}

	if err := table.Set(first); err != nil {
		t.Fatalf("Set(first) error = %v", err)
	}
	if err := table.Set(second); err != nil {
		t.Fatalf("Set(second) error = %v", err)
	}

	got, ok, err := table.Get()
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true")
	}
	if got != second {
		t.Errorf("Get() = %+v, want %+v (second Set must overwrite the first)", got, second)
	}
}

func TestShardConfigTable_SetRejectsIPv4(t *testing.T) {
	table := NewShardConfigTable(newFakeTable())

	tests := []struct {
		name string
		cfg  ShardConfig
	}{
		{
			name: "ipv4 shard SID",
			cfg: ShardConfig{
				ShardSID:     netip.MustParseAddr("203.0.113.1"),
				ShardPubAddr: netip.MustParseAddr("2001:db8:9999::1"),
			},
		},
		{
			name: "ipv4 shard pub addr",
			cfg: ShardConfig{
				ShardSID:     netip.MustParseAddr("fc00:1:2::1"),
				ShardPubAddr: netip.MustParseAddr("203.0.113.1"),
			},
		},
		{
			name: "4-in-6 shard SID",
			cfg: ShardConfig{
				ShardSID:     netip.MustParseAddr("::ffff:203.0.113.1"),
				ShardPubAddr: netip.MustParseAddr("2001:db8:9999::1"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := table.Set(tc.cfg)
			if err == nil {
				t.Fatal("Set() error = nil, want an error for a non-native-IPv6 address")
			}
			if !strings.Contains(err.Error(), "not a native IPv6 address") {
				t.Errorf("Set() error = %q, want it to mention the IPv6-only requirement", err)
			}
		})
	}
}
