// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package mappin

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to create and pin BPF maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// pinDir returns a fresh directory on the host's bpffs, removed on cleanup.
func pinDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-mappin-test-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("no writable bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func hashSpec(name string, keySize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: name, Type: ebpf.Hash, KeySize: keySize, ValueSize: 8, MaxEntries: 16}
}

// pin creates spec's map and pins it under dir by its name, holding value
// under key so a test can tell a kept map from a recreated one.
func pin(t *testing.T, dir string, spec *ebpf.MapSpec, key, value []byte) {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatalf("create map %s: %v", spec.Name, err)
	}
	defer m.Close() //nolint:errcheck // test-owned descriptor
	if err := m.Put(key, value); err != nil {
		t.Fatalf("seed map %s: %v", spec.Name, err)
	}
	if err := m.Pin(filepath.Join(dir, spec.Name)); err != nil {
		t.Fatalf("pin map %s: %v", spec.Name, err)
	}
}

// One map changing shape removes only that map's pin. The unchanged map keeps
// its pin and contents, a map the caller skips is left alone even though it
// changed, and a map with no pin yet is not an error.
func TestUnpinIncompatible_RemovesOnlyChangedMaps(t *testing.T) {
	requireRoot(t)
	dir := pinDir(t)

	value := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pin(t, dir, hashSpec("kept", 8), make([]byte, 8), value)
	pin(t, dir, hashSpec("grown", 16), make([]byte, 16), value)
	pin(t, dir, hashSpec("foreign", 16), make([]byte, 16), value)

	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"kept":    hashSpec("kept", 8),
		"grown":   hashSpec("grown", 32),
		"foreign": hashSpec("foreign", 32),
		"new":     hashSpec("new", 8),
	}}

	unpinned, err := UnpinIncompatible(spec, dir, func(name string) bool { return name == "foreign" })
	if err != nil {
		t.Fatalf("UnpinIncompatible: %v", err)
	}
	if !slices.Equal(unpinned, []string{"grown"}) {
		t.Errorf("unpinned = %v, want [grown]", unpinned)
	}

	if _, err := os.Stat(filepath.Join(dir, "grown")); !os.IsNotExist(err) {
		t.Errorf("grown's pin still exists (stat err %v), want it removed", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "foreign")); err != nil {
		t.Errorf("foreign's pin is gone (%v), want a skipped map left alone", err)
	}

	kept, err := ebpf.LoadPinnedMap(filepath.Join(dir, "kept"), nil)
	if err != nil {
		t.Fatalf("kept's pin is gone: %v", err)
	}
	defer kept.Close() //nolint:errcheck // test-owned descriptor
	got := make([]byte, 8)
	if err := kept.Lookup(make([]byte, 8), &got); err != nil {
		t.Fatalf("kept lost its row: %v", err)
	}
	if !slices.Equal(got, value) {
		t.Errorf("kept's row = %v, want %v", got, value)
	}
}

// With every pin matching, nothing is removed.
func TestUnpinIncompatible_CompatiblePinsUntouched(t *testing.T) {
	requireRoot(t)
	dir := pinDir(t)
	pin(t, dir, hashSpec("a", 8), make([]byte, 8), make([]byte, 8))

	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"a": hashSpec("a", 8)}}
	unpinned, err := UnpinIncompatible(spec, dir, nil)
	if err != nil {
		t.Fatalf("UnpinIncompatible: %v", err)
	}
	if len(unpinned) != 0 {
		t.Errorf("unpinned = %v, want none", unpinned)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); err != nil {
		t.Errorf("a's pin is gone: %v", err)
	}
}
