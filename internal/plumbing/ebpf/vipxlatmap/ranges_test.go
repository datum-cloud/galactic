// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"net"
	"testing"
)

func TestRangeBindingPreservesSiblingsAndRejectsOverlap(t *testing.T) {
	exact, ranges := newFakeTable(), newFakeTable()
	table := NewVipXlatTable(exact).WithRangeTable(ranges)
	vip, backend := net.ParseIP("2001:db8::1"), net.ParseIP("fd00::1")
	const block = uint64(0x20010db8ff01)
	const argument = uint16(10)
	const slot = uint16(1)
	for _, start := range []uint16{10000, 11000} {
		if err := table.RegisterIngressRange(block,
			argument,
			slot,
			ProtoUDP,
			vip,
			start,
			start+127,
			backend); err != nil {
			t.Fatal(err)
		}
		if err := table.RegisterEgressRange(block, argument, ProtoUDP, backend, start, start+127, vip); err != nil {
			t.Fatal(err)
		}
	}
	if ranges.len() != 2 || exact.len() != 0 {
		t.Fatalf("range expanded: %d range keys, %d singleton keys", ranges.len(), exact.len())
	}
	if err := table.RegisterEgressRange(block,
		argument,
		ProtoUDP,
		backend,
		10050,
		10200,
		net.ParseIP("2001:db8::2")); err == nil {
		t.Fatal("conflict accepted")
	}
	if err := table.UnregisterRangeBindingAt(block, argument, slot, ProtoUDP, vip, 10000, 10127, backend); err != nil {
		t.Fatal(err)
	}
	present, err := table.RangeBindingPresent(block, argument, slot, ProtoUDP, vip, 11000, 11127, backend)
	if err != nil || !present {
		t.Fatalf("sibling lost: %v %v", present, err)
	}
	present, err = table.RangeBindingPresent(block, argument, slot, ProtoUDP, vip, 10000, 10127, backend)
	if err != nil || present {
		t.Fatalf("deleted binding remains: %v %v", present, err)
	}
}

func TestRangeBindingConditionalDelete(t *testing.T) {
	table := NewVipXlatTable(newFakeTable()).WithRangeTable(newFakeTable())
	vip, backend := net.ParseIP("2001:db8::1"), net.ParseIP("fd00::1")
	const block = uint64(0x20010db8ff01)
	if err := table.RegisterIngressRange(block, 10, 1, ProtoUDP, vip, 10000, 10031, backend); err != nil {
		t.Fatal(err)
	}
	if err := table.RegisterEgressRange(block, 10, ProtoUDP, backend, 10000, 10031, vip); err != nil {
		t.Fatal(err)
	}
	if err := table.UnregisterRangeBindingAt(block, 10, 1, ProtoUDP, vip, 10000, 10127, backend); err != nil {
		t.Fatal(err)
	}
	present, err := table.RangeBindingPresent(block, 10, 1, ProtoUDP, vip, 10000, 10031, backend)
	if err != nil || !present {
		t.Fatalf("old delete removed replacement: %v %v", present, err)
	}
}

func TestRangeTranslationCapacityAndSingletonConflicts(t *testing.T) {
	table := NewVipXlatTable(newFakeTable()).WithRangeTable(newFakeTable())
	vip, backend := net.ParseIP("2001:db8::1"), net.ParseIP("fd00::1")
	const block = uint64(0x20010db8ff01)
	for i := range uint16(17) {
		err := table.RegisterEgressRange(block, 10, ProtoUDP, backend, 10000+i*100, 10063+i*100, vip)
		if (err == nil) != (i < 16) {
			t.Fatalf("descriptor %d: %v", i, err)
		}
	}
	if err := table.RegisterEgress(block, 10, ProtoUDP, backend, 10001, vip, 10001); err == nil {
		t.Fatal("singleton shadowing range accepted")
	}
	if err := table.RegisterEgress(block, 10, ProtoUDP, backend, 13000, vip, 13000); err != nil {
		t.Fatal(err)
	}
	if err := table.RegisterEgressRange(block, 10, ProtoUDP, backend, 12999, 13001, vip); err == nil {
		t.Fatal("range shadowing singleton accepted")
	}
	entries, err := table.ListRanges()
	if err != nil || len(entries) != 16 {
		t.Fatalf("capacity corruption: %d %v", len(entries), err)
	}
}

func TestWideTranslationRangeAndVRFIsolation(t *testing.T) {
	raw := newFakeTable()
	table := NewVipXlatTable(newFakeTable()).WithRangeTable(raw)
	vip, backend := net.ParseIP("2001:db8::1"), net.ParseIP("fd00::1")
	const block = uint64(0x20010db8ff01)
	for _, arg := range []uint16{10, 11} {
		if err := table.RegisterIngressRange(block, arg, 1, ProtoUDP, vip, 10000, 60000, backend); err != nil {
			t.Fatal(err)
		}
		if err := table.RegisterEgressRange(block, arg, ProtoUDP, backend, 10000, 60000, vip); err != nil {
			t.Fatal(err)
		}
	}
	if raw.len() != 4 {
		t.Fatalf("wide range expanded: %d keys", raw.len())
	}
	if err := table.UnregisterRangeBindingAt(block, 10, 1, ProtoUDP, vip, 10000, 60000, backend); err != nil {
		t.Fatal(err)
	}
	if present,
		err := table.RangeBindingPresent(block,
		11,
		1,
		ProtoUDP,
		vip,
		10000,
		60000,
		backend); err != nil || !present {
		t.Fatalf("other VRF removed: %v %v", present, err)
	}
}
