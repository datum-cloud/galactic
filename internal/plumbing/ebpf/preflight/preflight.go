// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package preflight implements the startup kernel-capability check for the
// `uFMT 48+16` eBPF/TC-BPF uSID datapath (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §6 "Preflight capability check";
// Milestone 2.3 of .local/implementation-plan-ebpf-xdp-usid-datapath.md).
//
// Before Milestone 3.1's control daemon attempts to load and attach
// internal/plumbing/ebpf/prog's compiled BPF object, it must confirm the
// running kernel actually supports everything that object needs:
//
//   - BPF_PROG_TYPE_SCHED_CLS (the TC-BPF ingress hook usid.c attaches as,
//     design plan §4.1).
//   - BPF_MAP_TYPE_HASH (locator_table/function_table/vrf_table are all
//     this type, design plan §4.4).
//   - Kernel BTF (usid.c is compiled CO-RE -- Compile Once, Run Everywhere
//     -- and needs /sys/kernel/btf/vmlinux to load at all, design plan §6).
//   - bpf_fib_lookup()'s VRF-table-id (tbid) parameter, specifically --
//     not just that the bpf_fib_lookup helper exists at all. That
//     parameter (the BPF_FIB_LOOKUP_TBID flag plus struct bpf_fib_lookup's
//     `tbid` field) was added to the kernel in a later release than the
//     base helper. A kernel that has bpf_fib_lookup but predates tbid
//     support would pass a naive "is the helper present" check and then
//     either fail the load (if usid.c's struct layout doesn't match what
//     the running kernel expects) or, worse, silently misroute traffic at
//     runtime -- R5 of the design plan depends on FIB lookups being scoped
//     to the resolved Argument's Linux VRF table via exactly this
//     parameter. This package detects tbid support by walking the running
//     kernel's own BTF description of `struct bpf_fib_lookup` (via
//     [KernelProber], see kernel_prober.go) for a member literally named
//     `tbid`, rather than parsing a kernel version string: the kernel's
//     BTF is generated directly from the same struct definition its
//     bpf_fib_lookup() implementation reads, so if the field isn't there,
//     the running kernel provably doesn't support it, independent of
//     whatever version string /proc/version reports (backports/vendor
//     kernels routinely change what a given "version" supports).
//
// This check must never produce a partial pass: any missing capability
// fails the whole check, and the caller must not fall back to a
// degraded/unsafe mode (design plan §6). See [Check] and [CheckWith].
package preflight

import (
	"errors"
	"fmt"
)

// Prober is the kernel-capability probe interface this package's checks run
// against. [NewKernelProber] returns the real, kernel-backed implementation
// used in production; tests substitute a mocked/stubbed implementation (see
// preflight_test.go) to exercise the pass case and each individual failure
// case in [CheckWith] without touching the real kernel (Milestone 2.3 exit
// criteria).
type Prober interface {
	// SchedCLS reports whether the running kernel supports
	// BPF_PROG_TYPE_SCHED_CLS. Returns nil if supported, a non-nil error
	// otherwise.
	SchedCLS() error

	// HashMap reports whether the running kernel supports
	// BPF_MAP_TYPE_HASH. Returns nil if supported, a non-nil error
	// otherwise.
	HashMap() error

	// BTF reports whether the running kernel exposes BTF type
	// information (required for usid.c's CO-RE compilation to resolve
	// against this kernel). Returns nil if available, a non-nil error
	// otherwise.
	BTF() error

	// FIBLookupTBID reports whether this kernel's bpf_fib_lookup()
	// supports the VRF-table-id (tbid) parameter specifically -- not
	// merely that the base helper exists. Returns nil if supported, a
	// non-nil error otherwise.
	FIBLookupTBID() error
}

// capabilityCheck names one required capability, binds it to its probe
// function, and carries a one-line, actionable "why this matters" note used
// to build [CheckWith]'s aggregate error. The why text is independent of
// whatever detail the underlying Prober error carries, so the aggregate
// error is equally actionable regardless of which Prober implementation
// (real or stubbed) produced it.
type capabilityCheck struct {
	name string
	fn   func() error
	why  string
}

func capabilityChecks(p Prober) []capabilityCheck {
	return []capabilityCheck{
		{
			name: "BPF_PROG_TYPE_SCHED_CLS",
			fn:   p.SchedCLS,
			why:  "the TC-BPF ingress hook this datapath attaches as requires SCHED_CLS program support (design plan §4.1)",
		},
		{
			name: "BPF_MAP_TYPE_HASH",
			fn:   p.HashMap,
			why:  "locator_table, function_table, and vrf_table are all BPF_MAP_TYPE_HASH (design plan §4.4)",
		},
		{
			name: "kernel BTF",
			fn:   p.BTF,
			why: "the datapath is compiled CO-RE and requires /sys/kernel/btf/vmlinux to resolve against " +
				"this kernel (design plan §6)",
		},
		{
			name: "bpf_fib_lookup VRF-table-id (tbid) parameter",
			fn:   p.FIBLookupTBID,
			why: "R5 requires FIB lookups scoped to the resolved Argument's Linux VRF table via bpf_fib_lookup's tbid " +
				"parameter, added to the kernel later than the base helper (design plan §6, §10)",
		},
	}
}

// Check runs every capability probe this datapath depends on against the
// real running kernel (via [NewKernelProber]) and returns a clear,
// actionable error if any is missing. It is the entry point Milestone
// 3.1's control daemon calls before attempting to load
// internal/plumbing/ebpf/prog's compiled object.
func Check() error {
	return CheckWith(NewKernelProber())
}

// CheckWith runs the same checks as [Check] against an arbitrary [Prober],
// so tests can substitute a mocked/stubbed kernel-feature-probe
// implementation and exercise the pass case and each individual failure
// case without touching the real kernel.
//
// Every check always runs, even after an earlier one fails, so a caller
// sees every missing capability at once rather than one at a time across
// repeated fix-and-rerun cycles. If nothing is missing, CheckWith returns
// nil. If anything is missing, CheckWith returns a single non-nil error
// (built with [errors.Join]) describing every failure -- there is no
// partial-pass return value, and callers must treat any non-nil error as
// "do not load the datapath on this node," never as a signal to fall back
// to a degraded or unsafe mode (design plan §6).
func CheckWith(p Prober) error {
	checks := capabilityChecks(p)

	var errs []error
	for _, c := range checks {
		if err := c.fn(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", c.name, c.why, err))
		}
	}
	if len(errs) == 0 {
		return nil
	}

	return fmt.Errorf(
		"eBPF uSID datapath preflight check failed (%d/%d required kernel capabilities missing) -- "+
			"refusing to load the datapath on this node; there is no partial or unsafe fallback: %w",
		len(errs), len(checks), errors.Join(errs...),
	)
}
