// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

// Drop reason indices into the drop_reasons map (edgenat.c's `enum
// edge_drop_reason`), exported for callers outside this package --
// notably internal/plumbing/ebpf/edgemetrics's Prometheus collector
// (Phase E), which needs a stable, human-readable label per index.
// Hand-kept in sync with edgenat.c for the same reason
// internal/plumbing/ebpf/prog's identical DropReason* constants are:
// bpf2go's -type flag cannot generate a Go type for a C enum that is only
// ever used as a literal constant, never as a typed variable/field the
// compiler retains distinct BTF for.
const (
	DropReasonNoBackends       uint32 = 0
	DropReasonNoConnNotSyn     uint32 = 1
	DropReasonPATExhausted     uint32 = 2
	DropReasonMalformedReturn  uint32 = 3
	DropReasonNoReturnConn     uint32 = 4
	DropReasonFibNoNeigh       uint32 = 5
	DropReasonFibUnreachable   uint32 = 6
	DropReasonFibFragNeeded    uint32 = 7
	DropReasonFibLookupFailed  uint32 = 8
	DropReasonAdjustHeadFailed uint32 = 9

	// Egress (masquerade) drop reasons (datum-cloud/enhancements#865) --
	// see edgenat.c's handle_egress_forward/handle_egress_return.
	DropReasonMalformedEgressForward uint32 = 10
	DropReasonNoEgressConnNotSyn     uint32 = 11
	DropReasonEgressPATExhausted     uint32 = 12
	DropReasonMalformedEgressReturn  uint32 = 13
	DropReasonNoEgressReturnConn     uint32 = 14

	DropReasonCount uint32 = 15
)

// DropReasonNames maps each DropReason* index to a short, stable,
// metrics/log-friendly name, decoupling Prometheus label values and any
// other external representation from edgenat.c's C identifier spelling.
var DropReasonNames = map[uint32]string{
	DropReasonNoBackends:             "no_backends",
	DropReasonNoConnNotSyn:           "no_conn_not_syn",
	DropReasonPATExhausted:           "pat_exhausted",
	DropReasonMalformedReturn:        "malformed_return",
	DropReasonNoReturnConn:           "no_return_conn",
	DropReasonFibNoNeigh:             "fib_no_neigh",
	DropReasonFibUnreachable:         "fib_unreachable",
	DropReasonFibFragNeeded:          "fib_frag_needed",
	DropReasonFibLookupFailed:        "fib_lookup_failed",
	DropReasonAdjustHeadFailed:       "adjust_head_failed",
	DropReasonMalformedEgressForward: "malformed_egress_forward",
	DropReasonNoEgressConnNotSyn:     "no_egress_conn_not_syn",
	DropReasonEgressPATExhausted:     "egress_pat_exhausted",
	DropReasonMalformedEgressReturn:  "malformed_egress_return",
	DropReasonNoEgressReturnConn:     "no_egress_return_conn",
}
