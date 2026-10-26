// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
package gateway

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

type fakeRangeMap struct {
	entries map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipRangeValue

	failOnNthPut int
	putCount     int
}

func newFakeRangeMap() *fakeRangeMap {
	return &fakeRangeMap{entries: make(map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipRangeValue)}
}

func (f *fakeRangeMap) Put(key, value any) error {
	f.putCount++
	if f.failOnNthPut != 0 && f.putCount == f.failOnNthPut {
		return fmt.Errorf("fakeRangeMap: injected failure on Put #%d", f.putCount)
	}
	f.entries[key.(edgeprog.EdgedsrVipKey)] = value.(edgeprog.EdgedsrVipRangeValue)
	return nil
}

func (f *fakeRangeMap) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgedsrVipKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*edgeprog.EdgedsrVipRangeValue) = v
	return nil
}

func (f *fakeRangeMap) Delete(key any) error {
	k := key.(edgeprog.EdgedsrVipKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeRangeMap) Iterate() edgemap.Iterator {
	keys := make([]edgeprog.EdgedsrVipKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeRangeIterator{table: f, keys: keys}
}

type fakeRangeIterator struct {
	table *fakeRangeMap
	keys  []edgeprog.EdgedsrVipKey
	i     int
}

func (it *fakeRangeIterator) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgedsrVipKey) = k
	*valueOut.(*edgeprog.EdgedsrVipRangeValue) = it.table.entries[k]
	return true
}

func (it *fakeRangeIterator) Err() error { return nil }

var _ edgemap.Table = (*fakeRangeMap)(nil)

func TestRangeFailurePreservesSiblingAndRetiresOldCoverage(t *testing.T) {
	ctx := context.Background()
	raw := newFakeRangeMap()
	groups := newFakeVIPTable()
	d := newTestKernelDatapath()
	d.ranges = edgemap.NewRangeTable(raw)
	d.rangeVIPTable = edgemap.NewVIPTable(groups, newFakeStatsTable(), newFakeAddrTable(), newFakeReturnStatsTable())
	a := testDesiredRule(t, "a", "2001:db8::1")
	a.Protocol = protocolUDP
	a.Port = 10000
	a.PortEnd = 10127
	b := a
	b.Key = "b"
	b.Port = 11000
	b.PortEnd = 11127
	if err := d.ApplyRule(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyRule(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Fail the new backend snapshot after removing old coverage.
	groups.failOnNthPut = groups.putCount + 1
	a.PortEnd = 10031
	if err := d.ApplyRule(ctx, a); err == nil {
		t.Fatal("injected backend failure ignored")
	}
	for _, v := range raw.entries {
		if v.Count != 1 || v.Ranges[0].Start != 11000 {
			t.Fatalf("failed update affected sibling: %+v", v)
		}
	}
	groups.failOnNthPut = 0
	// Fail classifier publication, then ensure no replacement remains live.
	raw.failOnNthPut = raw.putCount + 1
	if err := d.ApplyRule(ctx, a); err == nil {
		t.Fatal("injected classifier failure ignored")
	}
	for _, v := range raw.entries {
		if v.Count != 1 || v.Ranges[0].Start != 11000 {
			t.Fatalf("failed publish affected sibling: %+v", v)
		}
	}
	raw.failOnNthPut = 0
	if err := d.ApplyRule(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveRule(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	for _, v := range raw.entries {
		if v.Count != 1 || v.Ranges[0].Start != 11000 {
			t.Fatalf("delete affected sibling: %+v", v)
		}
	}
	if len(groups.entries) != 1 {
		t.Fatalf("orphan groups: %d", len(groups.entries))
	}
}
