// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package localprog

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to load the datapath; run task test:unit-root")
	}
}

// TestLoadRoot loads the Local programs against a freshly pinned uSID
// datapath, which runs them through the kernel verifier, and checks that a
// second load reuses the Local pins.
func TestLoadRoot(t *testing.T) {
	requireRoot(t)
	base := fmt.Sprintf("/sys/fs/bpf/galactic-localprog-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	usid, err := attach.Load(base + "/usid")
	if err != nil {
		t.Fatalf("load uSID datapath: %v", err)
	}
	t.Cleanup(func() { _ = usid.Close() })

	objs, err := Load(base+"/usid", base+"/local")
	if err != nil {
		t.Fatalf("load Local programs: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	if err := objs.Maps.Tap.Put(uint32(7), LocalLtTapValue{TableId: 9}); err != nil {
		t.Fatalf("write lt_tap: %v", err)
	}

	again, err := Load(base+"/usid", base+"/local")
	if err != nil {
		t.Fatalf("reload Local programs: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	var v LocalLtTapValue
	if err := again.Maps.Tap.Lookup(uint32(7), &v); err != nil || v.TableId != 9 {
		t.Fatalf("reloaded lt_tap row = %+v, %v; want the pinned row", v, err)
	}
	if _, err := Stats(again.Maps.Stats); err != nil {
		t.Fatal(err)
	}

	// A host with no uSID datapath refuses to load rather than create one.
	_, err = Load(base+"/absent", base+"/local2")
	if !errors.Is(err, ErrDatapathNotLoaded) {
		t.Fatalf("load with no uSID pins: %v, want ErrDatapathNotLoaded", err)
	}
	if _, statErr := os.Stat(base + "/absent/egress_route_table"); !os.IsNotExist(statErr) {
		t.Fatalf("load created a uSID pin: %v", statErr)
	}
}
