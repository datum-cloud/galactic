// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgepreflight implements the startup kernel-capability check for the
// XDP Maglev load-balancing gateway datapath.
//
// It is a sibling of internal/plumbing/ebpf/preflight, not an extension: that
// package's probe interface is scoped to the SRv6 uSID datapath's own
// capability list, and forcing every caller of either datapath to satisfy the
// union would be worse than two small focused interfaces. The two are
// structurally identical but list genuinely different capabilities:
//
//   - The XDP program type itself.
//   - bpf_xdp_adjust_head, which the datapath uses to grow the packet for the
//     pushed outer header. It has no sk_buff-based equivalent the other
//     package needed to check.
//   - The hash map type, which both this datapath's maps use. Probed here
//     independently so this package has no runtime dependency on the other.
//   - Kernel BTF, since the program is compiled with debug info and the
//     generated bindings depend on the kernel accepting annotated map value
//     types.
//
// Deliberately not checked: the LRU hash type and the checksum-diff helper.
// This datapath has no connection table, and it forwards every packet
// unmodified, so its checksum is already correct and it never touches one.
//
// Also not checked: whether a specific interface's driver supports native XDP
// attach rather than generic. That is a per-interface, per-driver property,
// unanswerable in the abstract the way kernel-wide XDP support is, so it is
// checked at attach time against the actual interface.
//
// Every check follows the same invariant: no partial pass, and no degraded
// fallback on failure. A node missing any one of these must not run the edge
// gateway datapath at all.
package edgepreflight

import (
	"errors"
	"fmt"
)

// Prober is the kernel-capability probe interface the checks run against.
// NewKernelProber returns the real implementation; tests substitute a stub to
// exercise the pass case and each failure case without a kernel.
type Prober interface {
	// XDP reports whether the running kernel supports BPF_PROG_TYPE_XDP.
	XDP() error

	// HashMap reports whether the running kernel supports
	// BPF_MAP_TYPE_HASH (edgedsr.c's vip_table/vip_stats_table).
	HashMap() error

	// BTF reports whether the running kernel exposes BTF type information,
	// required for edgedsr.c's bpf2go-generated map value types to load.
	BTF() error

	// XDPAdjustHead reports whether this kernel's XDP programs can grow a
	// packet, which the pushed outer header requires.
	XDPAdjustHead() error
}

// capabilityCheck names one required capability, binds it to its probe, and
// carries a one-line actionable note used to build the aggregate error.
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
// running kernel and returns an actionable error if any is missing.
func Check() error {
	return CheckWith(NewKernelProber())
}

// CheckWith runs the same probes as Check against an arbitrary Prober. Every
// check runs even after an earlier one fails, so a caller sees every missing
// capability at once. It returns nil when nothing is missing, and otherwise a
// single joined error describing every failure. There is no partial-pass
// return: any non-nil error means do not load this datapath on this node.
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
