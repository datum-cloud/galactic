// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import "time"

// Budgets bounds one query's results. A deployment may configure lower values;
// Clamp keeps every field at or below the hard ceilings regardless of what a
// caller asks for.
type Budgets struct {
	// MaxNodes bounds the nodes one cell executes on.
	MaxNodes int
	// MaxNodeResponseBytes bounds one node's serialized gRPC response.
	MaxNodeResponseBytes int
	// MaxObjectBytes bounds the serialized internal query object, status
	// included.
	MaxObjectBytes int
	// MaxPrefixes bounds prefix observations per location.
	MaxPrefixes int
	// MaxPathsPerPrefix bounds the paths kept for one prefix.
	MaxPathsPerPrefix int
	// MaxCommunitiesPerPath bounds communities and large communities kept for
	// one path, each.
	MaxCommunitiesPerPath int
}

// Ceilings are the hard upper bounds from the plan's initial budget table.
// Raising one requires boundary and load tests.
var Ceilings = Budgets{
	MaxNodes:              32,
	MaxNodeResponseBytes:  128 << 10,
	MaxObjectBytes:        384 << 10,
	MaxPrefixes:           100,
	MaxPathsPerPrefix:     8,
	MaxCommunitiesPerPath: 64,
}

// Fixed bounds that are not caller-tunable.
const (
	// MaxFRRResponseBytes caps one read from an FRR vty socket.
	MaxFRRResponseBytes = 4 << 20
	// MaxRequestLifetime is a query's lifetime from public creation.
	MaxRequestLifetime = 120 * time.Second
	// MaxNodeExecution caps one node's execution, within the remaining
	// request lifetime.
	MaxNodeExecution = 30 * time.Second
	// MaxCellsPerQuery bounds the cells one public query selects.
	MaxCellsPerQuery = 8
	// MaxErrorMessageLength bounds one error message carried in a result.
	MaxErrorMessageLength = 256
)

// Probe limits.
const (
	// PingCount is the number of echo requests one ping sends.
	PingCount = 3
	// TracerouteMaxHops bounds the hops a traceroute walks.
	TracerouteMaxHops = 20
	// TracerouteProbesPerHop is the number of probes sent per hop.
	TracerouteProbesPerHop = 1
	// MaxProbePayload bounds the ICMP echo payload, in bytes.
	MaxProbePayload = 64
	// ProbeWait bounds the wait for one reply.
	ProbeWait = time.Second
)

// Clamp returns b with every zero field set to its ceiling and every field
// above its ceiling lowered to it.
func (b Budgets) Clamp() Budgets {
	clamp := func(v, ceiling int) int {
		if v <= 0 || v > ceiling {
			return ceiling
		}
		return v
	}
	return Budgets{
		MaxNodes:              clamp(b.MaxNodes, Ceilings.MaxNodes),
		MaxNodeResponseBytes:  clamp(b.MaxNodeResponseBytes, Ceilings.MaxNodeResponseBytes),
		MaxObjectBytes:        clamp(b.MaxObjectBytes, Ceilings.MaxObjectBytes),
		MaxPrefixes:           clamp(b.MaxPrefixes, Ceilings.MaxPrefixes),
		MaxPathsPerPrefix:     clamp(b.MaxPathsPerPrefix, Ceilings.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: clamp(b.MaxCommunitiesPerPath, Ceilings.MaxCommunitiesPerPath),
	}
}
