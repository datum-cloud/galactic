// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

func TestLocalShardTable_Kernel(t *testing.T) {
	requireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := prog.LoadUsid()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(spec.Maps[prog.UsidMapEgressLocalShard].Copy())
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewLocalShardTable(m)
	t.Cleanup(func() { _ = tbl.Close() })

	sid := netip.MustParseAddr("2001:db8:ff01:9::")
	if _, ok, err := tbl.Get(7); err != nil || ok {
		t.Fatalf("Get(7) on an empty table = %t, %v; want no row", ok, err)
	}
	if err := tbl.Delete(7); err != nil {
		t.Fatalf("Delete of a missing row = %v, want nil", err)
	}
	if err := tbl.Put(7, LocalShard{ShardSID: netip.MustParseAddr("192.0.2.1"), PairIfindex: 3}); err == nil {
		t.Fatal("Put with an IPv4 shard SID succeeded, want an error")
	}
	want := LocalShard{ShardSID: sid, PairIfindex: 42}
	if err := tbl.Put(7, want); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := tbl.Get(7); err != nil || !ok || got != want {
		t.Fatalf("Get(7) = %+v, %t, %v; want %+v", got, ok, err, want)
	}
	all, err := tbl.All()
	if err != nil || len(all) != 1 || all[7] != want {
		t.Fatalf("All() = %v, %v; want only table 7", all, err)
	}
	if err := tbl.Delete(7); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tbl.Get(7); ok {
		t.Fatal("row still present after Delete")
	}
}

func TestOpenPinnedLocalShardTable_MissingPin(t *testing.T) {
	_, err := OpenPinnedLocalShardTable(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenPinnedLocalShardTable on an empty directory = %v, want os.ErrNotExist", err)
	}
}
