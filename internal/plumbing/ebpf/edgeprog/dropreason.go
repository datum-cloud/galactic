// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

// Drop reason indices into the drop_reasons map, mirroring the datapath's own
// enum and exported for callers outside this package, notably the Prometheus
// collector, which needs a stable label per index. Hand-kept in sync with the C
// source, because the generator cannot produce a Go type for an enum used only
// as a literal constant.
//
// A small set: direct server return has no connection table, no port allocation,
// and no return path, so there is nothing analogous to a full-NAT datapath's
// state-related reasons.
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

// DropReasonNames maps each index to a short, stable, metrics-friendly name,
// decoupling label values and any other external representation from the C
// identifier spelling.
var DropReasonNames = map[uint32]string{
	DropReasonEmptyBackendList: "empty_backend_list",
	DropReasonNoEncapConfig:    "no_encap_config",
	DropReasonFibNoNeigh:       "fib_no_neigh",
	DropReasonFibUnreachable:   "fib_unreachable",
	DropReasonFibFragNeeded:    "fib_frag_needed",
	DropReasonFibLookupFailed:  "fib_lookup_failed",
	DropReasonAdjustHeadFailed: "adjust_head_failed",
}
