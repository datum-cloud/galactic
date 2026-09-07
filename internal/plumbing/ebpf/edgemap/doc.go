// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemap implements the read/write API that populates the edge
// Maglev datapath's vip_table, its only control-plane-writable map with a
// nontrivial schema. encap_config_table, a single entry holding this node's
// encapsulation source address, is written directly at process startup rather
// than through a wrapper: one field, one call.
//
// vip_stats_table is a partial exception. This package reads it, to report a
// VIP's counters, and deletes from it, so a removed VIP's counters do not
// linger, but never writes it: the datapath populates each row lazily on a
// VIP's first matching packet.
//
// The two were once one map, and Register's read-modify-write to preserve
// counters across re-registration raced the datapath's per-packet increments
// into the same fields, discarding whichever landed second. Splitting the
// counters into a map Register never touches removes the race rather than
// narrowing it.
//
// This package decides nothing about when to register, and neither loads nor
// attaches the program. Those are the engine's and the attach package's jobs.
//
// # Why VIPTable carries a generation
//
// The engine is a single long-lived process, but it can crash mid-reconcile and
// leave entries behind with no rule left to reconcile them against. Reconcile's
// cutoff guards exactly that restart window, the same register-after-snapshot
// guarantee usidmap.VRFTable documents. The generation lives on vip_table's own
// value, not on the stats map, since Register never touches that one.
//
// # Testability
//
// VIPTable is built against the Table interface rather than directly against a
// loaded map: KernelTable adapts a real map for production, and tests
// substitute an in-memory fake. Table, Iterator, and KernelTable are a
// deliberate duplicate of usidmap's rather than an import: the two packages
// serve unrelated datapaths with no shared map or key layout, so importing
// would gain nothing but coupling.
package edgemap
