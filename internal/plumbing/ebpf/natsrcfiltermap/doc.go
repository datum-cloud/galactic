// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package natsrcfiltermap is the typed control-plane API for the egress
// translation datapath's SRv6 source filter: the allow-list of fabric source
// prefixes and the uplinks each is reachable through, the uplink slot
// numbering those bindings refer to, the filter's mode and sync state, and its
// read-only decision counters and denied-source record.
//
// # Who writes what
//
// The process that owns a shard writes the mode and its own uplink slots at
// startup. The allow-list, and the populated flag that arms it, belong to a
// reconciler that derives peer prefixes from fabric routes: it writes entries
// with PutAllow and DeleteAllow, then calls MarkPopulated once a full sync has
// landed. Until MarkPopulated runs, the datapath applies only its structural
// source checks and counts every other decision as a bypass, so an allow-list
// that has not been built yet cannot drop traffic.
//
// # Testability
//
// Filter is written against the Table and PerCPUReader interfaces rather than
// loaded maps. NewKernelFilter adapts a loaded object set; NewFakeFilter
// returns one backed by in-memory tables, for tests in this package and in
// callers such as the reconciler.
package natsrcfiltermap
