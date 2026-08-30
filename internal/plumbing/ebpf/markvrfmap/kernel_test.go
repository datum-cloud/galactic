// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package markvrfmap

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// requireRoot skips the test unless running as root (CAP_BPF/CAP_NET_ADMIN
// are needed to load real BPF maps), mirroring usidmap/kernel_test.go's own
// helper of the same name and purpose.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load real BPF maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// loadTestObjects loads a fresh, unpinned copy of internal/plumbing/ebpf/
// prog's compiled maps (and program) into the kernel, cleaned up when the
// test ends. Unpinned is deliberate: this file tests MarkVRFTable's
// Put/Lookup/Delete/Iterate wiring against a real kernel map, not
// attach/pin lifecycle -- so there is no reason to touch the real PinDir
// (/sys/fs/bpf/galactic) or leave anything behind on the test host. Mirrors
// usidmap/kernel_test.go's own helper of the same name.
func loadTestObjects(t *testing.T) *prog.UsidObjects {
	t.Helper()

	var objs prog.UsidObjects
	if err := prog.LoadUsidObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close objects: %v", err)
		}
	})
	return &objs
}

// TestKernelTable_MarkVRFTable_RealMap exercises MarkVRFTable's full
// read/write API -- Register, Get, List, Reconcile, Unregister -- against a
// real, kernel-loaded mark_vrf_table map, not the in-memory fake the rest
// of this package's tests use. This proves prog.UsidMarkVrfValue's field
// layout round-trips correctly through the kernel's own binary map
// encoding, not just through Go struct assignment in a fake -- the same
// genuine-verification role usidmap/kernel_test.go's
// TestKernelTable_VRFTable_RealMap plays for vrf_table.
func TestKernelTable_MarkVRFTable_RealMap(t *testing.T) {
	requireRoot(t)
	objs := loadTestObjects(t)
	mt := NewMarkVRFTable(usidmap.KernelTable{Map: objs.MarkVrfTable})
	mt.clock = constClock(10)

	if err := mt.Register(4242, testBlock, 0x123); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := mt.Get(4242)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register against a real kernel map")
	}
	want := MarkVRFEntry{Mark: 4242, Block: testBlock, Argument: 0x123, Generation: 10}
	if entry != want {
		t.Errorf("Get (real map) = %+v, want %+v", entry, want)
	}

	entries, err := mt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0] != want {
		t.Errorf("List (real map) = %+v, want exactly [%+v]", entries, want)
	}

	// Reconcile against a real map: entry is older than cutoff and absent
	// from live, so it must be removed for real -- proving Reconcile's
	// delete path (not just its in-memory bookkeeping) works against the
	// kernel.
	removed, err := mt.Reconcile(map[uint32]struct{}{}, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Mark != 4242 {
		t.Fatalf("Reconcile (real map) removed = %+v, want exactly mark 4242", removed)
	}

	if _, ok, err := mt.Get(4242); err != nil || ok {
		t.Errorf("Get after Reconcile (real map): ok=%v err=%v, want ok=false", ok, err)
	}

	// Unregister on an already-absent real-map entry must still not error
	// (mirrors TestMarkVRFTable_UnregisterAbsentIsNotError's fake-table
	// coverage, here against ebpf.ErrKeyNotExist for real).
	if err := mt.Unregister(4242); err != nil {
		t.Errorf("Unregister (real map, already absent) = %v, want nil", err)
	}
}
