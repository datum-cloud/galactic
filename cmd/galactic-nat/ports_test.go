// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// memTable is an in-memory natmap.Table keyed by any comparable key.
type memTable map[any]any

func (m memTable) Put(key, value any) error { m[key] = value; return nil }
func (m memTable) Lookup(key, valueOut any) error {
	v, ok := m[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}
func (m memTable) Delete(key any) error   { delete(m, key); return nil }
func (memTable) Iterate() natmap.Iterator { return &connRowsIterator{rows: &connRows{}, idx: -1} }

func TestNatCollectorReportsMasqueradePorts(t *testing.T) {
	const now uint32 = 100_000
	shardConfig := natmap.NewShardConfigTable(memTable{})
	if err := shardConfig.Set(natmap.ShardConfig{
		ShardSID:      netip.MustParseAddr("fc00:1:2::1"),
		ShardPubAddr6: netip.MustParseAddr("2001:db8:9966::1"),
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var rows connRows
	peerPort := uint16(443)
	for _, port := range []uint16{35000, 35001} {
		key, value := reverseRow(natprog.FamilyIPv6, 17, port, 443, now)
		key.Daddr = netip.MustParseAddr("2001:db8:9966::1").As16()
		key.Saddr = netip.MustParseAddr("2001:db8:1::1").As16()
		key.Sport = peerPort<<8 | peerPort>>8
		rows.add(key, value)
	}

	c := &natCollector{
		connTable:   natmap.NewConnTable(&rows),
		now:         fixedClock(now),
		shardConfig: shardConfig,
	}
	got := gatherAll(t, c)

	if v := got["galactic_nat_masquerade_port_range"][""]; v != float64(natprog.PATPortRange) {
		t.Errorf("port range = %v, want %d", v, natprog.PATPortRange)
	}
	inUse := got["galactic_nat_masquerade_ports_in_use"]
	maxDest := got["galactic_nat_masquerade_destination_ports_max"]
	// Labels sort as address/family/proto. The served IPv6 address is reported
	// for every protocol, zero included; the unserved IPv4 family not at all.
	want := map[string]float64{
		"2001:db8:9966::1/nat66/udp":  2,
		"2001:db8:9966::1/nat66/tcp":  0,
		"2001:db8:9966::1/nat66/icmp": 0,
	}
	if !reflect.DeepEqual(inUse, want) {
		t.Errorf("ports_in_use = %v, want %v", inUse, want)
	}
	if !reflect.DeepEqual(maxDest, want) {
		t.Errorf("destination_ports_max = %v, want %v", maxDest, want)
	}
}

// Without the session clock no row's liveness is known, so the per-address
// port series are left out rather than reported as zeros an idle shard would
// show. The range, which needs no clock, is still reported.
func TestNatCollectorPortsWithoutClock(t *testing.T) {
	shardConfig := natmap.NewShardConfigTable(memTable{})
	if err := shardConfig.Set(natmap.ShardConfig{
		ShardSID:      netip.MustParseAddr("fc00:1:2::1"),
		ShardPubAddr6: netip.MustParseAddr("2001:db8:9966::1"),
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	c := &natCollector{
		connTable:   natmap.NewConnTable(&connRows{}),
		now:         func() (uint32, error) { return 0, errors.New("no clock") },
		shardConfig: shardConfig,
	}
	got := gatherAll(t, c)
	if _, ok := got["galactic_nat_masquerade_ports_in_use"]; ok {
		t.Error("reported ports_in_use without a clock; zeros would read as an idle shard")
	}
	if _, ok := got["galactic_nat_masquerade_destination_ports_max"]; ok {
		t.Error("reported destination_ports_max without a clock")
	}
	if got["galactic_nat_masquerade_port_range"][""] != float64(natprog.PATPortRange) {
		t.Error("port range missing without a clock")
	}
}
