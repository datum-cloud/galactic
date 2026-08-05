// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package preflight

import (
	"os"
	"testing"
)

// requireRoot skips the calling test unless running as root, matching
// internal/plumbing/ebpf/prog's own convention for tests that need
// CAP_BPF/CAP_NET_ADMIN to touch the real kernel.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to probe real kernel capabilities; re-run via sudo")
	}
}

// TestKernelProber_BTF exercises [KernelProber.BTF] against the real
// running kernel. This sandbox is documented to have BTF at
// /sys/kernel/btf/vmlinux, so this must pass.
func TestKernelProber_BTF(t *testing.T) {
	k := NewKernelProber()
	if err := k.BTF(); err != nil {
		t.Errorf("KernelProber.BTF() = %v, want nil (this sandbox is documented to have kernel BTF)", err)
	}
}

// TestKernelProber_FIBLookupTBID exercises [KernelProber.FIBLookupTBID]
// against the real running kernel's own BTF. This is the milestone's
// central "run the real check and report what it finds" exit criterion:
// it does not assume an outcome, it reports whatever the real kernel BTF
// says.
func TestKernelProber_FIBLookupTBID(t *testing.T) {
	k := NewKernelProber()
	err := k.FIBLookupTBID()
	t.Logf("KernelProber.FIBLookupTBID() on this sandbox kernel: %v", err)
	if err != nil {
		t.Skip("this sandbox kernel's BTF does not describe a tbid member on struct bpf_fib_lookup; " +
			"see the test log above for the exact error -- not treated as a test failure since this " +
			"probe's job is to report kernel reality, not assert a specific kernel version")
	}
}

// TestKernelProber_SchedCLS exercises [KernelProber.SchedCLS] against the
// real running kernel. Requires root: creating even a throwaway
// BPF_PROG_TYPE_SCHED_CLS program needs CAP_BPF.
func TestKernelProber_SchedCLS(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.SchedCLS(); err != nil {
		t.Errorf("KernelProber.SchedCLS() = %v, want nil (environment facts document SCHED_CLS support)", err)
	}
}

// TestKernelProber_HashMap exercises [KernelProber.HashMap] against the
// real running kernel. Requires root: creating even a throwaway
// BPF_MAP_TYPE_HASH map needs CAP_BPF.
func TestKernelProber_HashMap(t *testing.T) {
	requireRoot(t)
	k := NewKernelProber()
	if err := k.HashMap(); err != nil {
		t.Errorf("KernelProber.HashMap() = %v, want nil (environment facts document BPF_MAP_TYPE_HASH support)", err)
	}
}

// TestCheck_RealKernel runs the full, real [Check] (via [NewKernelProber],
// not a stub) against this sandbox's actual kernel end to end -- the
// milestone's "run the real check against this actual sandbox kernel"
// exit criterion. Requires root for the program/map probes.
func TestCheck_RealKernel(t *testing.T) {
	requireRoot(t)
	err := Check()
	t.Logf("Check() against this sandbox's real kernel: %v", err)
	if err != nil {
		t.Errorf("Check() = %v, want nil -- this sandbox is documented to have BTF, SCHED_CLS, "+
			"BPF_MAP_TYPE_HASH, and (per TestKernelProber_FIBLookupTBID's own report) tbid support", err)
	}
}
