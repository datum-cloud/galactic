// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// Path MTU stat indices into the pmtu_stats map, mirroring the datapath's enum
// pmtu_stat. Hand-kept in sync with the C source, for the same reason as the
// drop reason indices in dropreason.go.
const (
	PMTUStatTooBigSentIPv6     uint32 = 0
	PMTUStatFragNeededSentIPv4 uint32 = 1
	PMTUStatDroppedNoDF        uint32 = 2
	PMTUStatDroppedICMPError   uint32 = 3
	PMTUStatRateLimited        uint32 = 4
	PMTUStatNoGateway          uint32 = 5
	PMTUStatBuildFailed        uint32 = 6
	PMTUStatCount              uint32 = 7
)

// PMTUStatNames maps each index to a short, stable, metrics-friendly name.
var PMTUStatNames = map[uint32]string{
	PMTUStatTooBigSentIPv6:     "too_big_sent_ipv6",
	PMTUStatFragNeededSentIPv4: "frag_needed_sent_ipv4",
	PMTUStatDroppedNoDF:        "dropped_no_df",
	PMTUStatDroppedICMPError:   "dropped_icmp_error",
	PMTUStatRateLimited:        "rate_limited",
	PMTUStatNoGateway:          "no_gateway",
	PMTUStatBuildFailed:        "build_failed",
}
