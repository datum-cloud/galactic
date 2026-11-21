// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

// LocalStat indexes nat_local_stats, mirroring enum nat_local_stat in nat.c.
type LocalStat uint32

// The nat_local_stats indices.
const (
	// LocalStatForward counts tenant packets from a pair's NAT end that were
	// translated and sent.
	LocalStatForward LocalStat = 0
	// LocalStatReturn counts replies sent back into a pair.
	LocalStatReturn LocalStat = 1
	// LocalStatReturnNoPair counts replies whose session names a pair the
	// redirect could not reach.
	LocalStatReturnNoPair LocalStat = 2
	// LocalStatForwardUnclaimed counts packets from a pair's NAT end the shard
	// does not translate, dropped so none reaches the host's stack.
	LocalStatForwardUnclaimed LocalStat = 3
	// LocalStatCount is the number of indices.
	LocalStatCount = 4
)

// String names a LocalStat as its metric label value.
func (s LocalStat) String() string {
	switch s {
	case LocalStatForward:
		return "forward"
	case LocalStatReturn:
		return "return"
	case LocalStatReturnNoPair:
		return "return_no_pair"
	case LocalStatForwardUnclaimed:
		return "forward_unclaimed"
	}
	return "unknown"
}
