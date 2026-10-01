// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// MSS clamp stat indices into the mss_clamp_stats map, mirroring the datapath's
// enum mss_clamp_stat. Hand-kept in sync with the C source, for the same reason
// as the drop reason indices in dropreason.go.
const (
	MSSClampStatClampedIPv4      uint32 = 0
	MSSClampStatClampedIPv6      uint32 = 1
	MSSClampStatWithinLimit      uint32 = 2
	MSSClampStatNoMSSOption      uint32 = 3
	MSSClampStatSkippedExtHdr    uint32 = 4
	MSSClampStatMalformedOptions uint32 = 5
	MSSClampStatRewriteFailed    uint32 = 6
	MSSClampStatWalkLimit        uint32 = 7
	MSSClampStatCount            uint32 = 8
)

// MSSClampStatNames maps each index to a short, stable, metrics-friendly name.
var MSSClampStatNames = map[uint32]string{
	MSSClampStatClampedIPv4:      "clamped_ipv4",
	MSSClampStatClampedIPv6:      "clamped_ipv6",
	MSSClampStatWithinLimit:      "within_limit",
	MSSClampStatNoMSSOption:      "no_mss_option",
	MSSClampStatSkippedExtHdr:    "skipped_extension_header",
	MSSClampStatMalformedOptions: "malformed_options",
	MSSClampStatRewriteFailed:    "rewrite_failed",
	MSSClampStatWalkLimit:        "walk_limit",
}
