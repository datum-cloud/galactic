// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

// Drop reason indices into the drop_reasons map, mirroring the datapath's own
// enum and exported for callers outside this package. Hand-kept in sync with the
// C source, because the generator cannot produce a Go type for an enum used only
// as a literal constant.
//
// Indices 0-8 are the ones this datapath used when it served NAT66 alone, kept
// at those values through the generalization so an existing counter series
// stays the same series.
const (
	DropReasonNat66NoReturnConn     uint32 = 0
	DropReasonNat66MalformedReturn  uint32 = 1
	DropReasonNat66PatExhausted     uint32 = 2
	DropReasonNat66MalformedForward uint32 = 3
	DropReasonNatFibNoNeigh         uint32 = 4
	DropReasonNatFibUnreachable     uint32 = 5
	DropReasonNatFibFragNeeded      uint32 = 6
	DropReasonNatFibLookupFailed    uint32 = 7
	DropReasonNatAdjustHeadFailed   uint32 = 8
	DropReasonNat64NoReturnConn     uint32 = 9
	DropReasonNat64MalformedReturn  uint32 = 10
	DropReasonNat64PatExhausted     uint32 = 11
	DropReasonNat64MalformedForward uint32 = 12
	DropReasonNat64V4Fragment       uint32 = 13
	DropReasonNat64V4Options        uint32 = 14
	DropReasonNat64ShardUnavailable uint32 = 15
	DropReasonNatTenantLimit        uint32 = 16
	DropReasonNatCount              uint32 = 17
)

// DropReasonNames maps each DropReason* index to a short, stable,
// metrics/log-friendly name.
var DropReasonNames = map[uint32]string{
	DropReasonNat66NoReturnConn:     "nat66_no_return_conn",
	DropReasonNat66MalformedReturn:  "nat66_malformed_return",
	DropReasonNat66PatExhausted:     "nat66_pat_exhausted",
	DropReasonNat66MalformedForward: "nat66_malformed_forward",
	DropReasonNatFibNoNeigh:         "fib_no_neigh",
	DropReasonNatFibUnreachable:     "fib_unreachable",
	DropReasonNatFibFragNeeded:      "fib_frag_needed",
	DropReasonNatFibLookupFailed:    "fib_lookup_failed",
	DropReasonNatAdjustHeadFailed:   "adjust_head_failed",
	DropReasonNat64NoReturnConn:     "nat64_no_return_conn",
	DropReasonNat64MalformedReturn:  "nat64_malformed_return",
	DropReasonNat64PatExhausted:     "nat64_pat_exhausted",
	DropReasonNat64MalformedForward: "nat64_malformed_forward",
	DropReasonNat64V4Fragment:       "nat64_v4_fragment",
	DropReasonNat64V4Options:        "nat64_v4_options",
	DropReasonNat64ShardUnavailable: "nat64_shard_unavailable",
	DropReasonNatTenantLimit:        "tenant_session_limit",
}
