// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"fmt"
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// TestOpenPinnedRegistry_RoundTrip covers Milestone 7.1's cross-process
// integration point: a real, separate "open" of an already-pinned set of
// maps -- exactly the situation the short-lived galactic-cni plugin binary
// is in on every ADD, since it does not itself load the datapath (that's
// the long-lived "run" container's job, Milestone 3.1). Loads/pins via
// attach.Load (the real production loader) into a throwaway pin
// directory, then opens a second, independent handle via
// OpenPinnedRegistry and proves a write through one handle is visible
// through the other -- the whole point of pinning.
func TestOpenPinnedRegistry_RoundTrip(t *testing.T) {
	requireRoot(t)

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-registry-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close loader-side objects: %v", err)
		}
	})

	reg, closer, err := OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("close opened registry: %v", err)
		}
	})

	if err := reg.VRF.Register(testBlock, 0x001, 0x2A2A2A, EgressKindVeth); err != nil {
		t.Fatalf("Register via opened handle: %v", err)
	}

	// Read back through the *original* loader-side objects, not the
	// handle that wrote it -- proving the write actually landed in the
	// shared, pinned kernel map object, not just some private state.
	loaderSideVRF := NewVRFTable(KernelTable{Map: objs.VrfTable})
	entry, ok, err := loaderSideVRF.Get(testBlock, 0x001)
	if err != nil {
		t.Fatalf("Get via loader-side handle: %v", err)
	}
	if !ok {
		t.Fatal("entry registered via the opened handle is not visible via the original loader-side handle")
	}
	if entry.VRFTableID != 0x2A2A2A {
		t.Errorf("VRFTableID = %#x, want %#x", entry.VRFTableID, 0x2A2A2A)
	}

	if err := reg.Locator.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("Locator.Register via opened handle: %v", err)
	}
	if err := reg.Function.Register(testBlock, 0xE); err != nil {
		t.Fatalf("Function.Register via opened handle: %v", err)
	}
}

// TestOpenPinnedRegistry_MissingPinDirIsActionableError covers the
// cross-process failure mode: the CNI plugin runs with the eBPF datapath
// flag on, but the "run" container hasn't loaded/pinned the maps yet (or
// never will, e.g. flag misconfiguration skew between the two
// DaemonSet containers).
func TestOpenPinnedRegistry_MissingPinDirIsActionableError(t *testing.T) {
	requireRoot(t)

	_, _, err := OpenPinnedRegistry("/sys/fs/bpf/galactic-does-not-exist")
	if err == nil {
		t.Fatal("OpenPinnedRegistry against a nonexistent pin dir: error = nil, want an error")
	}
}
