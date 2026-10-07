// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// A new version that changes one map's layout recreates that map alone. Every
// other map keeps its rows across the reload. This is the case where
// vip_xlat_table's key grew: recreating every map with it emptied the tables
// only CNI ADD writes, and every attachment on the node went dark until its
// workload re-attached.
func TestLoad_SchemaChangeRecreatesOnlyTheChangedMap(t *testing.T) {
	requireRoot(t)
	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-schema-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	objs, err := Load(pinDir)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	vrfKey := uint64(0x123)
	if err := objs.VrfTable.Put(vrfKey, prog.UsidVrfValue{VrfTableId: 42}); err != nil {
		t.Fatalf("seed vrf_table: %v", err)
	}
	if err := objs.LocatorTable.Put(uint64(0x456), prog.UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("seed locator_table: %v", err)
	}
	newKeySize := objs.VipXlatTable.KeySize()
	_ = objs.Close()

	// Stand in for the previous version's vip_xlat_table: same map, older,
	// smaller key.
	vipPin := filepath.Join(pinDir, prog.UsidMapVipXlatTable)
	if err := os.Remove(vipPin); err != nil {
		t.Fatalf("remove vip_xlat_table pin: %v", err)
	}
	old, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "vip_xlat_table", Type: ebpf.Hash, KeySize: newKeySize / 2, ValueSize: 8, MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("create old-layout vip_xlat_table: %v", err)
	}
	if err := old.Pin(vipPin); err != nil {
		t.Fatalf("pin old-layout vip_xlat_table: %v", err)
	}
	_ = old.Close()

	objs, err = Load(pinDir)
	if err != nil {
		t.Fatalf("Load over an old-layout vip_xlat_table: %v", err)
	}
	defer objs.Close() //nolint:errcheck // test-owned objects

	if got := objs.VipXlatTable.KeySize(); got != newKeySize {
		t.Errorf("vip_xlat_table key size = %d after reload, want the new layout's %d", got, newKeySize)
	}
	var vrf prog.UsidVrfValue
	if err := objs.VrfTable.Lookup(vrfKey, &vrf); err != nil {
		t.Errorf("vrf_table lost its row across the reload: %v", err)
	} else if vrf.VrfTableId != 42 {
		t.Errorf("vrf_table row = table %d, want 42", vrf.VrfTableId)
	}
	var loc prog.UsidLocatorValue
	if err := objs.LocatorTable.Lookup(uint64(0x456), &loc); err != nil {
		t.Errorf("locator_table lost its row across the reload: %v", err)
	}
}
