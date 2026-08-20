// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgepreflight implements the startup kernel-capability check for
// internal/plumbing/ebpf/edgeprog's XDP Maglev/DSR load-balancing gateway
// datapath.
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
//   - bpf_xdp_adjust_head -- edgedsr.c grows the packet by 40 bytes to make
//     room for the pushed outer SRv6 header on every claimed-VIP packet.
//     This helper has no __sk_buff-based equivalent usid.c's preflight
//     needed to check for.
//   - BPF_MAP_TYPE_HASH -- vip_table and vip_stats_table are both this
//     type; already covered by preflight's HashMap check conceptually but
//     probed again here independently so this package has no runtime
//     dependency on the other one.
//   - Kernel BTF, for the same CO-RE-adjacent reason usid.c's preflight
//     requires it: edgedsr.c is compiled with -g and bpf2go's generated Go
//     bindings for vip_value/vip_stats_value/backend/encap_config depend
//     on the running kernel accepting BTF-annotated map value types.
//
// Deliberately NOT checked here, unlike this package's Full-NAT edgenat.c
// predecessor: BPF_MAP_TYPE_LRU_HASH (that was conn_table's type; DSR has
// no conn_table at all, see edgedsr.c's own header comment) and
// bpf_csum_diff (Full-NAT needed it to fix up checksums after DNAT/SNAT;
// DSR forwards every packet completely unmodified, so its own checksum is
// already correct and this program never touches one). Removed as a direct
// consequence of the DSR/Maglev rewrite, not carried forward unexamined.
//
// Also deliberately NOT checked here: whether a specific interface's driver
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

	// HashMap reports whether the running kernel supports
	// BPF_MAP_TYPE_HASH (edgedsr.c's vip_table/vip_stats_table).
	HashMap() error

	// BTF reports whether the running kernel exposes BTF type information,
	// required for edgedsr.c's bpf2go-generated map value types to load.
	BTF() error

	// XDPAdjustHead reports whether this kernel's XDP programs can call
	// bpf_xdp_adjust_head -- required to grow the packet for the pushed
	// outer SRv6 header.
	XDPAdjustHead() error
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
			why:  "the edge gateway's Maglev/DSR load-balancing program attaches as an XDP program, not TC-BPF",
		},
		{
			name: "BPF_MAP_TYPE_HASH",
			fn:   p.HashMap,
			why:  "vip_table (VIP+port -> backend set) and vip_stats_table are both BPF_MAP_TYPE_HASH",
		},
		{
			name: "kernel BTF",
			fn:   p.BTF,
			why:  "edgedsr.c is compiled with -g and its generated map value types require kernel BTF to load",
		},
		{
			name: "bpf_xdp_adjust_head",
			fn:   p.XDPAdjustHead,
			why:  "every claimed-VIP packet grows by 40 bytes for the pushed outer SRv6 header",
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
