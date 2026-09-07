// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package preflight implements the startup kernel-capability check for the
// eBPF uSID datapath.
//
// Before the control daemon loads and attaches the compiled BPF object, the
// running kernel must be confirmed to support everything that object needs:
//
//   - The TC-BPF program type usid.c attaches as.
//   - The hash map type all three lookup maps use.
//   - Kernel BTF, without which a CO-RE-compiled object cannot load at all.
//   - bpf_fib_lookup's VRF-table-id parameter specifically, not merely that
//     the helper exists.
//
// That last one needs its own check. The table-id flag and struct field were
// added later than the base helper, so a kernel with the helper but without
// them passes a naive presence check and then either fails the load or, worse,
// silently misroutes traffic, since scoping the FIB lookup to the resolved
// Argument's VRF table depends on exactly that parameter.
//
// Support is detected by walking the running kernel's own BTF for a member
// named tbid rather than parsing a version string. The BTF is generated from
// the same struct definition the helper implementation reads, so its absence is
// proof, whatever version the kernel reports: backports and vendor kernels
// routinely change what a given version supports.
//
// This check never passes partially. Any missing capability fails the whole
// check, and the caller must not fall back to a degraded mode.
package preflight

import (
	"errors"
	"fmt"
)

// Prober is the kernel-capability probe interface the checks run against.
// NewKernelProber returns the real implementation; tests substitute a stub to
// exercise the pass case and each failure case without a kernel.
type Prober interface {
	// SchedCLS reports whether the kernel supports the TC-BPF program type,
	// returning nil when it does.
	SchedCLS() error

	// HashMap reports whether the kernel supports the hash map type, returning
	// nil when it does.
	HashMap() error

	// BTF reports whether the kernel exposes BTF type information, which a
	// CO-RE-compiled object needs to resolve against it. Returns nil when
	// available.
	BTF() error

	// FIBLookupTBID reports whether this kernel's bpf_fib_lookup supports the
	// VRF-table-id parameter, not merely that the helper exists. Returns nil
	// when supported.
	FIBLookupTBID() error
}

// capabilityCheck names one required capability, binds it to its probe, and
// carries a one-line actionable note used to build the aggregate error. That
// note is independent of whatever detail the probe's own error carries, so the
// aggregate stays equally actionable whichever Prober produced it.
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
// running kernel and returns an actionable error if any is missing. It is what
// the control daemon calls before attempting to load the compiled object.
func Check() error {
	return CheckWith(NewKernelProber())
}

// CheckWith runs the same probes as Check against an arbitrary Prober, so tests
// can exercise the pass case and each failure case without a kernel.
//
// Every check runs even after an earlier one fails, so a caller sees every
// missing capability at once rather than one per fix-and-rerun cycle. It
// returns nil when nothing is missing, and otherwise a single joined error
// describing every failure. There is no partial-pass return: any non-nil error
// means do not load the datapath on this node, never fall back to a degraded
// mode.
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
