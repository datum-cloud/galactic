// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"slices"
	"testing"
)

func TestHostOnlyPortTable_RegisterAndGet(t *testing.T) {
	table := NewHostOnlyPortTable(newFakeTable())
	if err := table.Register(vethIfindex, []uint16{20000, 20001}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ports, ok, err := table.Get(vethIfindex)
	if err != nil || !ok {
		t.Fatalf("Get = ok %v, err %v; want the entry", ok, err)
	}
	if want := []uint16{20000, 20001}; !slices.Equal(ports, want) {
		t.Errorf("ports = %v, want %v", ports, want)
	}
}

// A list the datapath cannot hold, or would read wrongly, is rejected rather
// than truncated: a silently dropped port would be left open.
func TestHostOnlyPortTable_RejectsInvalidLists(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ports []uint16
	}{
		{name: "empty", ports: nil},
		{name: "too many", ports: []uint16{1, 2, 3, 4, 5}},
		{name: "zero", ports: []uint16{0}},
		{name: "repeated", ports: []uint16{20000, 20000}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			table := NewHostOnlyPortTable(newFakeTable())
			if err := table.Register(vethIfindex, tt.ports); err == nil {
				t.Errorf("Register(%v) = nil, want an error", tt.ports)
			}
			if _, ok, _ := table.Get(vethIfindex); ok {
				t.Error("a rejected Register left an entry behind")
			}
		})
	}
}

func TestHostOnlyPortTable_UnregisterIsIdempotent(t *testing.T) {
	table := NewHostOnlyPortTable(newFakeTable())
	if err := table.Unregister(vethIfindex); err != nil {
		t.Fatalf("Unregister of an absent entry = %v, want nil", err)
	}
	if err := table.Register(vethIfindex, []uint16{20000}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := table.Unregister(vethIfindex); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if _, ok, _ := table.Get(vethIfindex); ok {
		t.Error("entry still present after Unregister")
	}
}

// testAliasOwner is the container ID host-only aliases record in these tests.
const testAliasOwner = "c0ffee"

func TestHostOnlyAlias_RoundTrips(t *testing.T) {
	const owner = testAliasOwner
	for _, alias := range []string{
		HostOnlyAlias([]uint16{20000, 20001}, owner),
		HostOnlyAlias([]uint16{20000, 20001}, ""),
	} {
		ports, ok, err := ParseHostOnlyAlias(alias)
		if err != nil || !ok || !slices.Equal(ports, []uint16{20000, 20001}) {
			t.Errorf("ParseHostOnlyAlias(%q) = %v, %v, %v; want [20000 20001]", alias, ports, ok, err)
		}
	}
	if got := HostOnlyAlias(nil, owner); got != owner {
		t.Errorf("HostOnlyAlias(nil, %q) = %q, want the owner alone", owner, got)
	}
	if HostOnlyAlias(nil, "") != "" {
		t.Error("an unowned attachment with no host-only ports has an alias")
	}
	if _, ok, err := ParseHostOnlyAlias("someone-else"); ok || err != nil {
		t.Errorf("an unrelated alias parsed as host-only ports: ok %v, err %v", ok, err)
	}
	for _, bad := range []string{"galactic-host-only-tcp=", "galactic-host-only-tcp=0", "galactic-host-only-tcp=70000"} {
		if _, _, err := ParseHostOnlyAlias(bad); err == nil {
			t.Errorf("ParseHostOnlyAlias(%q) = nil error, want one", bad)
		}
	}
}

// AliasOwner reads the owner back from every alias a host link carries.
func TestAliasOwner(t *testing.T) {
	for _, tt := range []struct{ alias, want string }{
		{HostOnlyAlias([]uint16{22, 20000}, testAliasOwner), testAliasOwner},
		{HostOnlyAlias([]uint16{22}, ""), ""},
		{HostOnlyAlias(nil, testAliasOwner), testAliasOwner},
		{testAliasOwner, testAliasOwner},
		{"", ""},
	} {
		if got := AliasOwner(tt.alias); got != tt.want {
			t.Errorf("AliasOwner(%q) = %q, want %q", tt.alias, got, tt.want)
		}
	}
}

// A recreated table loses every entry; the aliases the links keep put the
// missing ones back without touching an entry that survived.
func TestHostOnlyPortTable_Restore(t *testing.T) {
	const survivor, other = vethIfindex + 1, vethIfindex + 2
	table := NewHostOnlyPortTable(newFakeTable())
	if err := table.Register(survivor, []uint16{7000}); err != nil {
		t.Fatal(err)
	}

	restored, err := table.Restore(map[uint32]string{
		vethIfindex: HostOnlyAlias([]uint16{20000}, testAliasOwner),
		survivor:    HostOnlyAlias([]uint16{20000}, ""),
		other:       "someone-else",
	})
	if err != nil || restored != 1 {
		t.Fatalf("Restore = %d, %v; want 1, nil", restored, err)
	}
	if ports, _, _ := table.Get(vethIfindex); !slices.Equal(ports, []uint16{20000}) {
		t.Errorf("restored entry = %v, want [20000]", ports)
	}
	if ports, _, _ := table.Get(survivor); !slices.Equal(ports, []uint16{7000}) {
		t.Errorf("surviving entry = %v, want it left at [7000]", ports)
	}
	if _, ok, _ := table.Get(other); ok {
		t.Error("an interface without a host-only alias got an entry")
	}
}
