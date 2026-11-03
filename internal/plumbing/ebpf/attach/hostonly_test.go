// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// After a rollback the pinned host_only_port_table can outlive the tp_deliver
// that read it. Only a map the program references counts.
func TestProgramReadsMap(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
	var objs prog.UsidObjects
	if err := prog.LoadUsidObjects(&objs, nil); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	reads, err := programReadsMap(objs.TpDeliver, objs.HostOnlyPortTable)
	if err != nil || !reads {
		t.Errorf("tp_deliver reads its host_only_port_table: got %v, %v; want true", reads, err)
	}

	spec, err := objs.HostOnlyPortTable.Info()
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: spec.Type, KeySize: spec.KeySize, ValueSize: spec.ValueSize, MaxEntries: spec.MaxEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orphan.Close() })
	reads, err = programReadsMap(objs.TpDeliver, orphan)
	if err != nil || reads {
		t.Errorf("tp_deliver reads a table it was not loaded with: got %v, %v; want false", reads, err)
	}
}
