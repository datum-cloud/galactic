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
