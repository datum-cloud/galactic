// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// requireRoot skips the test unless running as root (CAP_BPF/CAP_NET_ADMIN
// are needed to load real BPF maps), matching prog/usid_test.go's own
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
// test ends. Unpinned is deliberate: this file tests KernelTable's
// Put/Lookup/Delete/Iterate wiring against real kernel maps, not
// attach/pin lifecycle (that is internal/plumbing/ebpf/attach's own
// Milestone 3.1 test coverage) -- so there is no reason to touch the real
// PinDir (/sys/fs/bpf/galactic) or leave anything behind on the test host.
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

// TestKernelTable_VRFTable_RealMap exercises VRFTable's full read/write
// API -- Register, Get, List, Reconcile, Unregister -- against a real,
// kernel-loaded vrf_table map (via KernelTable/NewRegistryFromObjects),
// not the in-memory fake the rest of this package's tests use. This is
// the genuine "actually attempt real verification" pass for this
// milestone's KernelTable adapter: it proves prog.UsidVrfValue's field
// layout (including the widened Generation field this milestone added)
// round-trips correctly through the kernel's own binary map encoding, not
// just through Go struct assignment in a fake.
func TestKernelTable_VRFTable_RealMap(t *testing.T) {
	requireRoot(t)
	objs := loadTestObjects(t)
	reg := NewRegistryFromObjects(objs)
	reg.VRF.clock = constClock(10)

	if err := reg.VRF.Register(testBlock, 0x123, 0x2A2A2A, EgressKindVeth); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := reg.VRF.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register against a real kernel map")
	}
	want := VRFEntry{VRFKey: VRFKey{Block: testBlock, Argument: 0x123}, VRFTableID: 0x2A2A2A, Generation: 10}
	if entry != want {
		t.Errorf("Get (real map) = %+v, want %+v", entry, want)
	}

	entries, err := reg.VRF.List()
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
	removed, err := reg.VRF.Reconcile(map[VRFKey]struct{}{}, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x123 {
		t.Fatalf("Reconcile (real map) removed = %+v, want exactly argument 0x123", removed)
	}

	if _, ok, err := reg.VRF.Get(testBlock, 0x123); err != nil || ok {
		t.Errorf("Get after Reconcile (real map): ok=%v err=%v, want ok=false", ok, err)
	}

	// Unregister on an already-absent real-map entry must still not
	// error (mirrors TestVRFTable_UnregisterAbsentIsNotError's fake-table
	// coverage, here against ebpf.ErrKeyNotExist for real).
	if err := reg.VRF.Unregister(testBlock, 0x123); err != nil {
		t.Errorf("Unregister (real map, already absent) = %v, want nil", err)
	}
}

// TestKernelTable_LocatorTable_RealMap and
// TestKernelTable_FunctionTable_RealMap cover the same "genuinely
// verified against the kernel, not just the fake" ground for the other
// two tables, more briefly since VRFTable's coverage above already proves
// the KernelTable adapter itself works.
func TestKernelTable_LocatorTable_RealMap(t *testing.T) {
	requireRoot(t)
	objs := loadTestObjects(t)
	reg := NewRegistryFromObjects(objs)
	reg.Locator.clock = constClock(3)

	if err := reg.Locator.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	entry, ok, err := reg.Locator.Get(testBlock, 0x0010)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if want := (LocatorEntry{Block: testBlock, NodeID: 0x0010, Generation: 3}); entry != want {
		t.Errorf("Get (real map) = %+v, want %+v", entry, want)
	}
	if err := reg.Locator.Unregister(testBlock, 0x0010); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if _, ok, err := reg.Locator.Get(testBlock, 0x0010); err != nil || ok {
		t.Errorf("Get after Unregister (real map): ok=%v err=%v, want ok=false", ok, err)
	}
}

func TestKernelTable_FunctionTable_RealMap(t *testing.T) {
	requireRoot(t)
	objs := loadTestObjects(t)
	reg := NewRegistryFromObjects(objs)

	if err := reg.Function.Register(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	entry, ok, err := reg.Function.Get(testBlock, uformat.FunctionEndDT46)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	want := FunctionEntry{Block: testBlock, Function: uformat.FunctionEndDT46, Behavior: BehaviorEndDT46}
	if entry != want {
		t.Errorf("Get (real map) = %+v, want %+v", entry, want)
	}
	if err := reg.Function.Unregister(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if _, ok, err := reg.Function.Get(testBlock, uformat.FunctionEndDT46); err != nil || ok {
		t.Errorf("Get after Unregister (real map): ok=%v err=%v, want ok=false", ok, err)
	}
}
