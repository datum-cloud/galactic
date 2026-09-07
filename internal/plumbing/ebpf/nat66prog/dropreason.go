// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66prog

// Drop reason indices into the drop_reasons map, mirroring the datapath's own
// enum and exported for callers outside this package. Hand-kept in sync with the
// C source, because the generator cannot produce a Go type for an enum used only
// as a literal constant.
const (
	DropReasonNat66NoReturnConn     uint32 = 0
	DropReasonNat66MalformedReturn  uint32 = 1
	DropReasonNat66PatExhausted     uint32 = 2
	DropReasonNat66MalformedForward uint32 = 3
	DropReasonNat66FibNoNeigh       uint32 = 4
	DropReasonNat66FibUnreachable   uint32 = 5
	DropReasonNat66FibFragNeeded    uint32 = 6
	DropReasonNat66FibLookupFailed  uint32 = 7
	DropReasonNat66AdjustHeadFailed uint32 = 8
	DropReasonNat66Count            uint32 = 9
)

// DropReasonNames maps each DropReason* index to a short, stable,
// metrics/log-friendly name.
var DropReasonNames = map[uint32]string{
	DropReasonNat66NoReturnConn:     "no_return_conn",
	DropReasonNat66MalformedReturn:  "malformed_return",
	DropReasonNat66PatExhausted:     "pat_exhausted",
	DropReasonNat66MalformedForward: "malformed_forward",
	DropReasonNat66FibNoNeigh:       "fib_no_neigh",
	DropReasonNat66FibUnreachable:   "fib_unreachable",
	DropReasonNat66FibFragNeeded:    "fib_frag_needed",
	DropReasonNat66FibLookupFailed:  "fib_lookup_failed",
	DropReasonNat66AdjustHeadFailed: "adjust_head_failed",
}
