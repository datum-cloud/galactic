// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// TestLoad_RecreatesConnTableWithOldValueSize covers a shard upgraded across a
// change to the session value: the table its previous process pinned has the
// old value size, and Load must replace it rather than fail to start.
func TestLoad_RecreatesConnTableWithOldValueSize(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-nat-test-upgrade-%d", os.Getpid()))
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatalf("create pin dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	spec, err := natprog.LoadNat()
	if err != nil {
		t.Fatalf("load collection spec: %v", err)
	}
	cur := spec.Maps["nat_conn_table"]
	const oldValueSize = 56
	if cur.ValueSize == oldValueSize {
		t.Fatalf("nat_conn_table value size is still %d; this test needs an older layout to stand in", oldValueSize)
	}

	old, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: cur.Type, KeySize: cur.KeySize, ValueSize: oldValueSize, MaxEntries: cur.MaxEntries,
	})
	if err != nil {
		t.Fatalf("create old-layout map: %v", err)
	}
	if err := old.Pin(filepath.Join(pinDir, "nat_conn_table")); err != nil {
		t.Fatalf("pin old-layout map: %v", err)
	}
	_ = old.Close()

	objs, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load over an old-layout pinned table: %v", err)
	}
	defer func() { _ = objs.Close() }()

	if got := objs.NatConnTable.ValueSize(); got != cur.ValueSize {
		t.Errorf("nat_conn_table value size after Load = %d, want %d", got, cur.ValueSize)
	}
}
