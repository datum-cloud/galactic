// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// Drop reason indices into the drop_reasons map, mirroring the datapath's own
// enum and exported for callers outside this package, notably the Prometheus
// collector, which needs a stable label per index.
//
// Hand-kept in sync with the C source, because the generator cannot produce a Go
// type for an enum used only as a literal constant. This package's own tests use
// these same constants rather than keeping a copy, so a change to the enum means
// updating both this file and those tests.
const (
	DropReasonUnknownFunction            uint32 = 0
	DropReasonUnknownArgument            uint32 = 1
	DropReasonMalformedInner             uint32 = 2
	DropReasonUnknownInnerVer            uint32 = 3
	DropReasonStripFailed                uint32 = 4
	DropReasonFibLookupFailed            uint32 = 5
	DropReasonRedirectFailed             uint32 = 6
	DropReasonFibNoNeigh                 uint32 = 7
	DropReasonFibUnreachable             uint32 = 8
	DropReasonFibFragNeeded              uint32 = 9
	DropReasonUnexpectedNextHdr          uint32 = 10
	DropReasonUnsupportedBehavior        uint32 = 11
	DropReasonEgressRouteEncapFailed     uint32 = 12
	DropReasonEgressRouteFibLookupFailed uint32 = 13
	DropReasonEgressRouteRedirectFailed  uint32 = 14
	DropReasonPublicUplinkRedirectFailed uint32 = 15
	DropReasonCount                      uint32 = 16
)

// DropReasonNames maps each index to a short, stable, metrics-friendly name,
// decoupling label values and any other external representation from the C
// identifier spelling.
var DropReasonNames = map[uint32]string{
	DropReasonUnknownFunction:            "unknown_function",
	DropReasonUnknownArgument:            "unknown_argument",
	DropReasonMalformedInner:             "malformed_inner",
	DropReasonUnknownInnerVer:            "unknown_inner_version",
	DropReasonStripFailed:                "strip_failed",
	DropReasonFibLookupFailed:            "fib_lookup_failed",
	DropReasonRedirectFailed:             "redirect_failed",
	DropReasonFibNoNeigh:                 "fib_no_neigh",
	DropReasonFibUnreachable:             "fib_unreachable",
	DropReasonFibFragNeeded:              "fib_frag_needed",
	DropReasonUnexpectedNextHdr:          "unexpected_nexthdr",
	DropReasonUnsupportedBehavior:        "unsupported_behavior",
	DropReasonEgressRouteEncapFailed:     "egress_route_encap_failed",
	DropReasonEgressRouteFibLookupFailed: "egress_route_fib_lookup_failed",
	DropReasonEgressRouteRedirectFailed:  "egress_route_redirect_failed",
	DropReasonPublicUplinkRedirectFailed: "public_uplink_redirect_failed",
}
