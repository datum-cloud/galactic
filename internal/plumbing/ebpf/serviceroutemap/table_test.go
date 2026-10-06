// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroutemap

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

type fakeTable struct {
	putKey, putValue any
	deleted          any
}

func (f *fakeTable) Put(key, value any) error {
	f.putKey, f.putValue = key, value
	return nil
}

func (*fakeTable) Lookup(any, any) error { return ebpf.ErrKeyNotExist }

func (f *fakeTable) Delete(key any) error {
	f.deleted = key
	return ebpf.ErrKeyNotExist
}

func (*fakeTable) Iterate() usidmap.Iterator {
	return emptyIterator{}
}

type emptyIterator struct{}

func (emptyIterator) Next(any, any) bool { return false }
func (emptyIterator) Err() error         { return nil }

func TestTables_RegisterIPv6Route(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	tables := New(routes, access)
	_, prefix, err := net.ParseCIDR("fd20:0:19::/96")
	if err != nil {
		t.Fatal(err)
	}
	if err := tables.RegisterRoute(42, prefix, 101, 43, 1, true); err != nil {
		t.Fatal(err)
	}
	key, ok := routes.putKey.(prog.UsidEgressRouteKey)
	if !ok {
		t.Fatalf("route key type = %T", routes.putKey)
	}
	if key.TableId != 42 || key.Family != familyIPv6 || key.Prefixlen != 136 {
		t.Fatalf("route key = %+v", key)
	}
	value, ok := routes.putValue.(serviceRouteValue)
	if !ok || value.TargetIfindex != 101 || value.TargetTableID != 43 ||
		value.TargetKind != 1 || value.RequirePolicy != 1 {
		t.Fatalf("route value = %+v", routes.putValue)
	}
}

func TestTables_RegisterAccessUsesNetworkPortOrder(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	tables := New(routes, access)
	address := net.ParseIP("fd20::53")
	if err := tables.RegisterAccess(42, address, ProtocolUDP, 53); err != nil {
		t.Fatal(err)
	}
	key, ok := access.putKey.(serviceAccessKey)
	if !ok {
		t.Fatalf("access key type = %T", access.putKey)
	}
	if key.TableID != 42 || key.Family != familyIPv6 || key.Protocol != ProtocolUDP || key.Port != 0x3500 {
		t.Fatalf("access key = %+v", key)
	}
	if !bytes.Equal(key.Address[:], address.To16()) {
		t.Fatalf("address = %x, want %x", key.Address, address.To16())
	}
}

func TestTables_UnregisterAbsentIsIdempotent(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	tables := New(routes, access)
	_, prefix, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := tables.UnregisterRoute(7, prefix); err != nil {
		t.Fatal(err)
	}
	if err := tables.UnregisterAccess(7, net.ParseIP("192.0.2.53"), ProtocolTCP, 853); err != nil {
		t.Fatal(err)
	}
	if routes.deleted == nil || access.deleted == nil {
		t.Fatal("expected both map keys to be deleted")
	}
}

func TestRouteKeyRejectsNilPrefix(t *testing.T) {
	_, err := routeKey(1, nil)
	if err == nil {
		t.Fatal("routeKey(nil) did not return an error")
	}
}
