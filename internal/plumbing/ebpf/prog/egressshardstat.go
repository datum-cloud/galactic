// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// Egress shard stat indices into the egress_shard_stats map, mirroring the
// datapath's enum egress_shard_stat. Hand-kept in sync with the C source, for
// the same reason as the drop reason indices in dropreason.go.
const (
	EgressShardStatGroupEmpty  uint32 = 0
	EgressShardStatPinStale    uint32 = 1
	EgressShardStatPinHit      uint32 = 2
	EgressShardStatMaglev      uint32 = 3
	EgressShardStatShardDead   uint32 = 4
	EgressShardStatParseFailed uint32 = 5
	EgressShardStatCount       uint32 = 6
)

// EgressShardStatNames maps each index to a short, stable, metrics-friendly
// name.
var EgressShardStatNames = map[uint32]string{
	EgressShardStatGroupEmpty:  "group_empty",
	EgressShardStatPinStale:    "pin_stale",
	EgressShardStatPinHit:      "pin_hit",
	EgressShardStatMaglev:      "maglev",
	EgressShardStatShardDead:   "shard_dead",
	EgressShardStatParseFailed: "parse_failed",
}
