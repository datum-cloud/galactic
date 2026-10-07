// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDrainLegacyServiceAuthorization(t *testing.T) {
	requireRoot(t)
	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-rollout-test-%d", os.Getpid()))
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatalf("create pin directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	access := createPinnedTestMap(t, pinDir, "service_access_table", ebpf.Hash, 24, 1, 8)
	reverse := createPinnedTestMap(t, pinDir, "service_reverse_table", ebpf.Hash, 44, 8, 8)
	grant := createPinnedTestMap(t, pinDir, "service_remote_grant_table", ebpf.Hash, 40, 8, 8)
	state := createPinnedTestMap(t, pinDir, "service_policy_state_table", ebpf.Array, 4, 1, 1)

	markerKey := make([]byte, 24)
	markerKey[4] = 1
	realKey := append([]byte(nil), markerKey...)
	realKey[5] = 6
	realKey[6], realKey[7] = 1, 187
	for _, key := range [][]byte{markerKey, realKey} {
		if err := access.Put(key, []byte{1}); err != nil {
			t.Fatalf("seed access: %v", err)
		}
	}
	if err := reverse.Put(make([]byte, 44), make([]byte, 8)); err != nil {
		t.Fatalf("seed reverse: %v", err)
	}
	if err := grant.Put(make([]byte, 40), make([]byte, 8)); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := state.Put(uint32(0), []byte{1}); err != nil {
		t.Fatalf("enable policy: %v", err)
	}

	if err := drainLegacyServiceAuthorization(pinDir); err != nil {
		t.Fatalf("drainLegacyServiceAuthorization: %v", err)
	}
	var one [1]byte
	if err := access.Lookup(markerKey, &one); err != nil {
		t.Fatalf("fragment marker removed: %v", err)
	}
	if err := access.Lookup(realKey, &one); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("real access lookup = %v, want key absent", err)
	}
	if countMapEntries(reverse) != 0 || countMapEntries(grant) != 0 {
		t.Fatalf("reverse/grant entries remain after drain: %d/%d", countMapEntries(reverse), countMapEntries(grant))
	}
	if err := state.Lookup(uint32(0), &one); err != nil || one[0] != 0 {
		t.Fatalf("policy state after drain = %v, %v, want disabled", one, err)
	}
}

func createPinnedTestMap(t *testing.T, dir, name string, typ ebpf.MapType, keySize, valueSize, maxEntries uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: name, Type: typ, KeySize: keySize, ValueSize: valueSize, MaxEntries: maxEntries})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.Pin(filepath.Join(dir, name)); err != nil {
		t.Fatalf("pin %s: %v", name, err)
	}
	return m
}

func countMapEntries(m *ebpf.Map) int {
	count := 0
	iterator := m.Iterate()
	info, _ := m.Info()
	key, value := make([]byte, info.KeySize), make([]byte, info.ValueSize)
	for iterator.Next(&key, &value) {
		count++
	}
	return count
}
