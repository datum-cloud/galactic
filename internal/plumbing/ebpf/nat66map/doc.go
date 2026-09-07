// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nat66map implements the read/write API for the NAT66 datapath's two
// control-plane-facing maps, shard_config_table and drop_reasons, plus a
// read-only accessor for nat66_conn_table, the datapath's self-managed LRU flow
// table.
//
// # nat66_conn_table is never written here
//
// The datapath alone writes that table: it allocates masquerade ports, claims
// rows, and self-evicts under memory pressure, with no GC needed. ConnTable
// exposes only Get and List, since there is no control-plane liveness set to
// reconcile it against.
//
// # shard_config_table is what the control plane does write
//
// A single-entry array carrying this shard's identity, its SID and public
// address, both operator-supplied, written once at process startup.
// ShardConfigTable gives it a typed, validated wrapper rather than a raw Put,
// as the other map layers here do, because the value has two address fields.
//
// # Its own Table interface, not usidmap's or edgemap's
//
// This is a standalone datapath sharing no map or key layout with the others, so
// this package declares its own Table, KernelTable, and Iterator rather than
// importing either neighbor's.
//
// # Testability
//
// Every table type is built against the Table interface rather than directly
// against a loaded map: KernelTable adapts a real map for production, and tests
// substitute an in-memory fake to exercise every path without a kernel or root.
package nat66map
