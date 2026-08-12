// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgepreflight

import (
	"os"
	"testing"
)

// requireRoot skips the calling test unless running as root, matching
// internal/plumbing/ebpf/preflight's own convention for tests that need
// CAP_BPF to touch the real kernel.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF) to probe real kernel capabilities; re-run via sudo")
	}
}

// TestKernelProber_BTF exercises [KernelProber.BTF] against the real
// running kernel.
func TestKernelProber_BTF(t *testing.T) {
	k := NewKernelProber()
	if err := k.BTF(); err != nil {
		t.Errorf("KernelProber.BTF() = %v, want nil (this sandbox is documented to have kernel BTF)", err)
	}
}

// TestKernelProber_XDP exercises [KernelProber.XDP] against the real
// running kernel. Requires root: creating even a throwaway
// BPF_PROG_TYPE_XDP program needs CAP_BPF.
func TestKernelProber_XDP(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.XDP(); err != nil {
		t.Errorf("KernelProber.XDP() = %v, want nil", err)
	}
}

// TestKernelProber_HashMap exercises [KernelProber.HashMap].
func TestKernelProber_HashMap(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.HashMap(); err != nil {
		t.Errorf("KernelProber.HashMap() = %v, want nil", err)
	}
}

// TestKernelProber_LRUHashMap exercises [KernelProber.LRUHashMap].
func TestKernelProber_LRUHashMap(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.LRUHashMap(); err != nil {
		t.Errorf("KernelProber.LRUHashMap() = %v, want nil", err)
	}
}

// TestKernelProber_XDPAdjustHead exercises [KernelProber.XDPAdjustHead]
// against the real running kernel -- this is the same helper the Phase 0
// spike confirmed by hand (compiling a minimal program and attaching it to
// a live veth); this test confirms the same fact via the feature-probe path
// the real preflight check uses.
func TestKernelProber_XDPAdjustHead(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.XDPAdjustHead(); err != nil {
		t.Errorf("KernelProber.XDPAdjustHead() = %v, want nil (confirmed working via a live spike on this kernel)", err)
	}
}

// TestKernelProber_XDPCsumDiff exercises [KernelProber.XDPCsumDiff]
// against the real running kernel.
func TestKernelProber_XDPCsumDiff(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.XDPCsumDiff(); err != nil {
		t.Errorf("KernelProber.XDPCsumDiff() = %v, want nil (confirmed working via a live spike on this kernel)", err)
	}
}

// TestCheck_RealKernel runs the full, real Check() against this sandbox's
// actual kernel -- the end-to-end exit criterion: report what the real
// kernel supports, not an assumption.
func TestCheck_RealKernel(t *testing.T) {
	requireRoot(t)
	err := Check()
	t.Logf("Check() on this sandbox kernel: %v", err)
	if err != nil {
		t.Errorf("Check() = %v, want nil (every capability was individually confirmed present during Phase 0)", err)
	}
}
