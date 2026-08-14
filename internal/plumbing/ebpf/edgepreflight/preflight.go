// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgepreflight implements the startup kernel-capability check for
// internal/plumbing/ebpf/edgeprog's XDP ingress NAT+LB gateway datapath.
//
// This is a sibling of internal/plumbing/ebpf/preflight, not an extension
// of it: that package's Prober interface is scoped specifically to the
// SRv6 uSID TC-BPF datapath's own capability list (SCHED_CLS, plain
// BPF_MAP_TYPE_HASH, bpf_fib_lookup's tbid parameter) and forcing every
// caller of either datapath to satisfy the union of both lists would be
// worse interface hygiene than two small, focused ones (CONVENTIONS.md:
// "prefer creating a focused sub-package over adding to an existing large
// one"). The two datapaths' checks are structurally identical (a Prober
// interface + KernelProber + capabilityChecks + Check/CheckWith) but list
// genuinely different capabilities:
//
//   - BPF_PROG_TYPE_XDP itself.
//   - bpf_xdp_adjust_head -- edgenat.c grows the packet by 40 bytes on the
//     forward/DNAT path (room for the pushed outer IPv6 header) and shrinks
//     it back by 40 on the return/decap path. This helper has no
//     __sk_buff-based equivalent usid.c's preflight needed to check for.
//   - bpf_csum_diff -- edgenat.c's checksum fixups after mutating an
//     address/port covered by the L4 pseudo-header. gwprog's earlier,
//     rejected Geneve-based design used bpf_l4_csum_replace/
//     bpf_l3_csum_replace instead, but those are __sk_buff-only helpers,
//     unavailable to an XDP program's xdp_md context -- bpf_csum_diff is
//     the XDP-safe replacement, and its availability is not implied by
//     BPF_PROG_TYPE_XDP support alone.
//   - BPF_MAP_TYPE_LRU_HASH -- conn_table is this type (self-evicting
//     under pressure, matching gwprog's own conn_table convention); rule_table
//     is plain BPF_MAP_TYPE_HASH, already covered by preflight's HashMap
//     check conceptually but probed again here independently so this
//     package has no runtime dependency on the other one.
//   - Kernel BTF, for the same CO-RE-adjacent reason usid.c's preflight
//     requires it: edgenat.c is compiled with -g and bpf2go's generated
//     Go bindings for rule_value/rule_stats_value/conn_value/backend
//     depend on the running kernel accepting BTF-annotated map value
//     types.
//
// Deliberately NOT checked here: whether a specific interface's driver
// supports *native* (driver-mode) XDP attach, as opposed to generic
// (SKB-mode) attach. That is a per-interface, per-driver property (the
// design's own spike found the geneve driver lacks it entirely, while a
// veth or a real NIC's driver normally has it) -- it cannot be answered in
// the abstract the way "does this kernel support BPF_PROG_TYPE_XDP at all"
// can, so it is checked at attach time, against the actual interface being
// attached to, by internal/plumbing/ebpf/edgeattach, not here.
//
// Every check below follows preflight's own hard invariant: no partial
// pass, and no unsafe/degraded fallback on failure -- a node missing any
// one of these capabilities must not run the edge gateway datapath at all.
package edgepreflight

import (
	"errors"
	"fmt"
)

// Prober is the kernel-capability probe interface this package's checks run
// against. [NewKernelProber] returns the real, kernel-backed implementation
// used in production; tests substitute a stubbed implementation to exercise
// the pass case and each individual failure case in [CheckWith] without
// touching the real kernel.
type Prober interface {
	// XDP reports whether the running kernel supports BPF_PROG_TYPE_XDP.
	XDP() error

	// LRUHashMap reports whether the running kernel supports
	// BPF_MAP_TYPE_LRU_HASH (edgenat.c's conn_table).
	LRUHashMap() error

	// HashMap reports whether the running kernel supports
	// BPF_MAP_TYPE_HASH (edgenat.c's rule_table).
	HashMap() error

	// BTF reports whether the running kernel exposes BTF type information,
	// required for edgenat.c's bpf2go-generated map value types to load.
	BTF() error

	// XDPAdjustHead reports whether this kernel's XDP programs can call
	// bpf_xdp_adjust_head -- required to grow/shrink the packet for the
	// pushed/stripped outer SRv6 header.
	XDPAdjustHead() error

	// XDPCsumDiff reports whether this kernel's XDP programs can call
	// bpf_csum_diff -- the XDP-safe checksum-fixup helper (unlike
	// bpf_l4_csum_replace/bpf_l3_csum_replace, which require __sk_buff and
	// are unavailable to an XDP program).
	XDPCsumDiff() error
}

// capabilityCheck names one required capability, binds it to its probe
// function, and carries a one-line "why this matters" note used to build
// [CheckWith]'s aggregate error.
type capabilityCheck struct {
	name string
	fn   func() error
	why  string
}

func capabilityChecks(p Prober) []capabilityCheck {
	return []capabilityCheck{
		{
			name: "BPF_PROG_TYPE_XDP",
			fn:   p.XDP,
			why:  "the edge gateway's ingress NAT+LB program attaches as an XDP program, not TC-BPF",
		},
		{
			name: "BPF_MAP_TYPE_HASH",
			fn:   p.HashMap,
			why:  "rule_table (VIP+port -> backend) is BPF_MAP_TYPE_HASH",
		},
		{
			name: "BPF_MAP_TYPE_LRU_HASH",
			fn:   p.LRUHashMap,
			why:  "conn_table is BPF_MAP_TYPE_LRU_HASH so it self-evicts under pressure instead of failing closed",
		},
		{
			name: "kernel BTF",
			fn:   p.BTF,
			why:  "edgenat.c is compiled with -g and its generated map value types require kernel BTF to load",
		},
		{
			name: "bpf_xdp_adjust_head",
			fn:   p.XDPAdjustHead,
			why: "the forward path grows the packet by 40 bytes for the pushed outer SRv6 header, and the " +
				"return path shrinks it back by 40 to strip it",
		},
		{
			name: "bpf_csum_diff",
			fn:   p.XDPCsumDiff,
			why: "checksum fixups after DNAT/SNAT must use this XDP-safe helper -- bpf_l4_csum_replace and " +
				"bpf_l3_csum_replace require __sk_buff and are unavailable to an XDP program",
		},
	}
}

// Check runs every capability probe this datapath depends on against the
// real running kernel (via [NewKernelProber]) and returns a clear,
// actionable error if any is missing.
func Check() error {
	return CheckWith(NewKernelProber())
}

// CheckWith runs the same checks as [Check] against an arbitrary [Prober].
// Every check always runs, even after an earlier one fails, so a caller
// sees every missing capability at once. If nothing is missing, CheckWith
// returns nil; otherwise it returns a single non-nil error (built with
// [errors.Join]) describing every failure. There is no partial-pass return
// value: callers must treat any non-nil error as "do not load the edge
// gateway datapath on this node," never as a signal to fall back to a
// degraded or unsafe mode.
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
		"edge gateway XDP datapath preflight check failed (%d/%d required kernel capabilities missing) -- "+
			"refusing to load the datapath on this node; there is no partial or unsafe fallback: %w",
		len(errs), len(checks), errors.Join(errs...),
	)
}
