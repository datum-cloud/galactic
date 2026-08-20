// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

// Drop reason indices into the drop_reasons map (edgedsr.c's `enum
// edge_drop_reason`), exported for callers outside this package --
// notably internal/plumbing/ebpf/edgemetrics's Prometheus collector, which
// needs a stable, human-readable label per index. Hand-kept in sync with
// edgedsr.c for the same reason internal/plumbing/ebpf/prog's identical
// DropReason* constants are: bpf2go's -type flag cannot generate a Go type
// for a C enum that is only ever used as a literal constant, never as a
// typed variable/field the compiler retains distinct BTF for.
//
// A much smaller set than the Full-NAT edgenat.c predecessor's: DSR has no
// conn_table, no PAT/SNAT-port allocation, and no return/decap branch, so
// there is nothing analogous to DropReasonNoConnNotSyn/PATExhausted/
// MalformedReturn/NoReturnConn to carry forward.
const (
	DropReasonEmptyBackendList uint32 = 0
	DropReasonNoEncapConfig    uint32 = 1
	DropReasonFibNoNeigh       uint32 = 2
	DropReasonFibUnreachable   uint32 = 3
	DropReasonFibFragNeeded    uint32 = 4
	DropReasonFibLookupFailed  uint32 = 5
	DropReasonAdjustHeadFailed uint32 = 6
	DropReasonCount            uint32 = 7
)

// DropReasonNames maps each DropReason* index to a short, stable,
// metrics/log-friendly name, decoupling Prometheus label values and any
// other external representation from edgedsr.c's C identifier spelling.
var DropReasonNames = map[uint32]string{
	DropReasonEmptyBackendList: "empty_backend_list",
	DropReasonNoEncapConfig:    "no_encap_config",
	DropReasonFibNoNeigh:       "fib_no_neigh",
	DropReasonFibUnreachable:   "fib_unreachable",
	DropReasonFibFragNeeded:    "fib_frag_needed",
	DropReasonFibLookupFailed:  "fib_lookup_failed",
	DropReasonAdjustHeadFailed: "adjust_head_failed",
}
