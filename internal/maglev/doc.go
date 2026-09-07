// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maglev implements the Maglev consistent-hashing lookup table.
//
// Every backend gets an independent pseudo-random permutation of table slots,
// derived from two hashes of its own key and never from another backend's key
// or from table contents, and slots are handed out round-robin over each
// backend's permutation until the table is full. Two properties follow, both
// load-bearing here:
//
//   - Given the same backend set and table size, every caller builds the
//     byte-identical table, with no coordination, shared state, or messaging
//     between them. That is what lets every gateway node independently compute
//     the same backend assignment under anycast forwarding: reconvergence can
//     move a flow's packets to a different node mid-connection, and that node
//     still picks the same backend, having built the same table from the same
//     inputs.
//   - Removing or adding one backend reassigns roughly one slot in N rather
//     than reshuffling everything, unlike a plain modulo scheme. That is what
//     makes this usable for both consistent-hash sites here without sharing a
//     ring: the gateway's backend selection and the NAT66 tier's shard
//     placement. Conflating those rings is explicitly not what this is for;
//     construct one table per ring.
//
// Pure Go, with no kernel or CRD dependency.
package maglev
