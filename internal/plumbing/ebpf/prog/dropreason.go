// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// Drop reason indices into the drop_reasons map (usid.c's `enum
// drop_reason`), exported for callers outside this package -- notably
// internal/plumbing/ebpf/metrics's Prometheus collector (Milestone 4 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md), which needs a
// stable, human-readable label per index. Hand-kept in sync with usid.c
// for the same reason usidmap's BehaviorEndDT46/BehaviorEndDT2 constants
// are (see usidmap/function.go's identical comment): bpf2go's -type flag
// cannot generate a Go type for a C enum that is only ever used as a
// literal constant, never as a typed variable/field the compiler retains
// distinct BTF for. prog/usid_test.go keeps its own unexported copy of
// these same values (predating this file) for the same reason -- if
// usid.c's enum drop_reason ever changes, update both.
const (
	DropReasonUnknownFunction uint32 = 0
	DropReasonUnknownArgument uint32 = 1
	DropReasonMalformedInner  uint32 = 2
	DropReasonUnknownInnerVer uint32 = 3
	DropReasonStripFailed     uint32 = 4
	DropReasonFibLookupFailed uint32 = 5
	DropReasonRedirectFailed  uint32 = 6
	DropReasonCount           uint32 = 7
)

// DropReasonNames maps each DropReason* index to a short, stable,
// metrics/log-friendly name, decoupling Prometheus label values (Milestone
// 4) and any other external representation from usid.c's C identifier
// spelling.
var DropReasonNames = map[uint32]string{
	DropReasonUnknownFunction: "unknown_function",
	DropReasonUnknownArgument: "unknown_argument",
	DropReasonMalformedInner:  "malformed_inner",
	DropReasonUnknownInnerVer: "unknown_inner_version",
	DropReasonStripFailed:     "strip_failed",
	DropReasonFibLookupFailed: "fib_lookup_failed",
	DropReasonRedirectFailed:  "redirect_failed",
}
