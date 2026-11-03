// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sidecarmap

import (
	"net"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// memTable is an in-memory usidmap.Table keyed by any comparable key.
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

func (m memTable) Delete(key any) error {
	if _, ok := m[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m, key)
	return nil
}

func (m memTable) Iterate() usidmap.Iterator {
	it := &memIterator{}
	for k, v := range m {
		it.keys = append(it.keys, k)
		it.values = append(it.values, v)
	}
	return it
}

// memIterator walks a snapshot of a memTable's entries.
type memIterator struct {
	keys, values []any
	idx          int
}

func (it *memIterator) Next(keyOut, valueOut any) bool {
	if it.idx >= len(it.keys) {
		return false
	}
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(it.keys[it.idx]))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.values[it.idx]))
	it.idx++
	return true
}

func (it *memIterator) Err() error { return nil }

// memPolicy is an in-memory tp_iface_table holding each row's kind, with
// tpmap.Maps' contract: RemoveInfra deletes only an infra row.
type memPolicy map[uint32]uint32

func (m memPolicy) InfraInterfaces() ([]uint32, error) {
	var rows []uint32
	for ifindex, kind := range m {
		if kind == tpmap.KindInfra {
			rows = append(rows, ifindex)
		}
	}
	return rows, nil
}

func (m memPolicy) RemoveInfra(ifindex uint32) error {
	if m[ifindex] == tpmap.KindInfra {
		delete(m, ifindex)
	}
	return nil
}

const (
	hostBlock    = uint64(0xfd00_0000_0001)
	hostArgument = uint16(7)
	hostIfindex  = uint32(12)
	hostTableID  = uint32(42)
	// hostInfra is a host-side infra row, such as an ingress gateway pod's
	// primary interface, which the installer owns.
	hostInfra = uint32(30)
)

// fixture is one node's maps holding a host attachment's rows and the rows of
// two sidecar VRFs, with Arguments 1 and 2, and their traffic policy rows.
type fixture struct {
	maps                     Maps
	vrfRaw, ifxRaw, routeRaw memTable
	policy                   memPolicy
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{
		vrfRaw: memTable{}, ifxRaw: memTable{}, routeRaw: memTable{},
		policy: memPolicy{hostIfindex: tpmap.KindTenant, hostInfra: tpmap.KindInfra},
	}
	f.maps = Maps{
		VRF:         usidmap.NewVRFTable(f.vrfRaw),
		Ifindex:     ifindexvrfmap.NewIfindexVRFTable(f.ifxRaw),
		EgressRoute: egressroutemap.NewEgressRouteTable(f.routeRaw),
		Policy:      f.policy,
	}

	if err := f.maps.VRF.Register(hostBlock, hostArgument, hostTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	if err := f.maps.Ifindex.Register(hostIfindex, hostBlock, hostArgument); err != nil {
		t.Fatal(err)
	}
	f.putRoute(hostTableID, "2001:db8:1::/64")

	for _, arg := range []uint16{1, 2} {
		tableID := vrf.SidecarTableIDBase + uint32(arg)
		if err := f.maps.VRF.Register(uformat.BlockIngressSidecar, arg, tableID, usidmap.EgressKindVeth); err != nil {
			t.Fatal(err)
		}
		if err := f.maps.Ifindex.Register(ifindexvrfmap.SidecarIfindex(arg), uformat.BlockIngressSidecar, arg); err != nil {
			t.Fatal(err)
		}
		f.putRoute(tableID, "2001:db8:2::5/128")
		f.putRoute(tableID, "10.0.0.5/32")
		f.policy[ifindexvrfmap.SidecarIfindex(arg)] = tpmap.KindInfra
	}
	return f
}

// putRoute writes an egress_route_table row directly. Register resolves the
// SID's next hop over netlink, which a unit test has nothing to resolve
// against, and Prune only ever reads keys.
func (f fixture) putRoute(tableID uint32, cidr string) {
	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ones, _ := prefix.Mask.Size()
	key := prog.UsidEgressRouteKey{TableId: tableID, Prefixlen: uint32(8*(4+1) + ones)}
	if v4 := prefix.IP.To4(); v4 != nil {
		key.Family = 1
		copy(key.Addr[:4], v4)
	} else {
		copy(key.Addr[:], prefix.IP.To16())
	}
	f.routeRaw[key] = prog.UsidEgressRouteValue{}
}

func (f fixture) routeTables(t *testing.T) map[uint32]int {
	t.Helper()
	byTable, err := f.maps.EgressRoute.Prefixes()
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint32]int{}
	for tableID, prefixes := range byTable {
		out[tableID] = len(prefixes)
	}
	return out
}

func TestPrune_EmptyKeepRemovesEverySidecarRowAndNoHostRow(t *testing.T) {
	f := newFixture(t)

	result, err := Prune(f.maps, nil)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if want := (Result{VRFRows: 2, IfindexRows: 2, EgressRouteRows: 4, PolicyRows: 2}); result != want {
		t.Errorf("result = %+v, want %+v", result, want)
	}

	vrfRows, err := f.maps.VRF.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(vrfRows) != 1 || vrfRows[0].Block != hostBlock {
		t.Errorf("vrf_table = %+v, want only the host row", vrfRows)
	}
	ifxRows, err := f.maps.Ifindex.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifxRows) != 1 || ifxRows[0].Ifindex != hostIfindex {
		t.Errorf("ifindex_vrf_table = %+v, want only the host row", ifxRows)
	}
	if got, want := f.routeTables(t), map[uint32]int{hostTableID: 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("egress_route_table rows per table = %v, want %v", got, want)
	}
	if want := (memPolicy{hostIfindex: tpmap.KindTenant, hostInfra: tpmap.KindInfra}); !reflect.DeepEqual(f.policy, want) {
		t.Errorf("tp_iface_table = %v, want only the host rows %v", f.policy, want)
	}
}

func TestPrune_KeepsTheNamedArguments(t *testing.T) {
	f := newFixture(t)

	result, err := Prune(f.maps, map[uint16]struct{}{2: {}})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if want := (Result{VRFRows: 1, IfindexRows: 1, EgressRouteRows: 2, PolicyRows: 1}); result != want {
		t.Errorf("result = %+v, want %+v", result, want)
	}

	if _, ok, _ := f.maps.VRF.Get(uformat.BlockIngressSidecar, 1); ok {
		t.Error("vrf_table still holds argument 1")
	}
	if _, ok, _ := f.maps.VRF.Get(uformat.BlockIngressSidecar, 2); !ok {
		t.Error("vrf_table lost argument 2, which keep names")
	}
	if _, ok, _ := f.maps.Ifindex.Get(ifindexvrfmap.SidecarIfindex(1)); ok {
		t.Error("ifindex_vrf_table still holds argument 1's interface")
	}
	if _, ok, _ := f.maps.Ifindex.Get(ifindexvrfmap.SidecarIfindex(2)); !ok {
		t.Error("ifindex_vrf_table lost argument 2's interface, which keep names")
	}
	want := map[uint32]int{hostTableID: 1, vrf.SidecarTableIDBase + 2: 2}
	if got := f.routeTables(t); !reflect.DeepEqual(got, want) {
		t.Errorf("egress_route_table rows per table = %v, want %v", got, want)
	}
	if _, ok := f.policy[ifindexvrfmap.SidecarIfindex(1)]; ok {
		t.Error("tp_iface_table still holds argument 1's interface")
	}
	if _, ok := f.policy[ifindexvrfmap.SidecarIfindex(2)]; !ok {
		t.Error("tp_iface_table lost argument 2's interface, which keep names")
	}
}

func TestPrune_KeepingEverythingRemovesNothing(t *testing.T) {
	f := newFixture(t)

	result, err := Prune(f.maps, map[uint16]struct{}{1: {}, 2: {}})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if result.Total() != 0 {
		t.Errorf("removed %+v, want nothing", result)
	}
}

func TestPrune_LeavesATenantPolicyRowInTheSidecarRange(t *testing.T) {
	f := newFixture(t)
	f.policy[ifindexvrfmap.SidecarIfindex(1)] = tpmap.KindTenant

	result, err := Prune(f.maps, nil)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if result.PolicyRows != 1 {
		t.Errorf("removed %d policy rows, want 1 (argument 2's infra row)", result.PolicyRows)
	}
	if f.policy[ifindexvrfmap.SidecarIfindex(1)] != tpmap.KindTenant {
		t.Error("tenant row in the sidecar range removed")
	}
}

func TestPrune_WithoutPolicyMaps(t *testing.T) {
	f := newFixture(t)
	f.maps.Policy = nil

	result, err := Prune(f.maps, nil)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if want := (Result{VRFRows: 2, IfindexRows: 2, EgressRouteRows: 4}); result != want {
		t.Errorf("result = %+v, want %+v", result, want)
	}
}

func TestPresent(t *testing.T) {
	cases := []struct {
		name   string
		change func(f fixture)
		want   bool
	}{
		{name: "every row", change: func(fixture) {}, want: true},
		{name: "no vrf_table row", change: func(f fixture) {
			_ = f.maps.VRF.Unregister(uformat.BlockIngressSidecar, 1)
		}},
		{name: "no ifindex_vrf_table row", change: func(f fixture) {
			_ = f.maps.Ifindex.Unregister(ifindexvrfmap.SidecarIfindex(1))
		}},
		{name: "no infra row", change: func(f fixture) {
			delete(f.policy, ifindexvrfmap.SidecarIfindex(1))
		}},
		{name: "tenant row instead of infra", change: func(f fixture) {
			f.policy[ifindexvrfmap.SidecarIfindex(1)] = tpmap.KindTenant
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(f)
			got, err := Present(f.maps, 1)
			if err != nil {
				t.Fatalf("Present: %v", err)
			}
			if got != tc.want {
				t.Errorf("Present = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPresent_WithoutPolicyMaps(t *testing.T) {
	f := newFixture(t)
	f.maps.Policy = nil
	delete(f.policy, ifindexvrfmap.SidecarIfindex(1))

	got, err := Present(f.maps, 1)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !got {
		t.Error("Present = false on a node without traffic policy maps, want true")
	}
}
