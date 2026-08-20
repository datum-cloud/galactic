// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maglev implements Google's Maglev consistent-hashing lookup table
// (Eisenbrand et al., "Maglev: A Fast and Reliable Software Network Load
// Balancer", NSDI 2016, §3.4). Every backend gets an independent
// pseudo-random permutation of table slots (derived from two hashes of its
// own key, never from any other backend's key or from table contents), and
// slots are handed out round-robin over each backend's own permutation
// until the table is full. Two properties fall out of that construction,
// both load-bearing for how this package is used:
//
//   - Given the identical backend set and the identical table size, every
//     caller builds the byte-identical table — no coordination, no shared
//     state, no RPC between callers. This is what makes it safe for every
//     galactic-gateway node to independently compute the same backend
//     assignment for the design's anycast/DSR forwarding model (see the
//     design plan's §0): ECMP or BGP reconvergence can move a flow's
//     packets to a different gateway node mid-connection, and that node
//     still picks the identical backend, because it built the identical
//     table from the identical (VIP, backend list) input.
//   - Removing or adding one backend only reassigns approximately 1/N of
//     the table's slots (N = backend count) rather than reshuffling
//     everything, unlike a plain hash(key) % len(backends) scheme (see
//     TestTable_DisruptionBound). This is the property that makes this
//     package usable for both this repo's own consistent-hash use sites
//     without sharing a ring between them: galactic-gateway's ingress
//     backend-selection ring, and galactic-nat66's independent
//     shard-placement ring (design plan §3.1) — conflating the two rings
//     is explicitly not what this package is for; construct one *Table
//     per ring.
//
// This package is pure Go with no kernel/CRD dependency, mirroring
// internal/plumbing/nptv6's identical split between pure computation and
// whatever eBPF/CRD wiring consumes it.
package maglev
