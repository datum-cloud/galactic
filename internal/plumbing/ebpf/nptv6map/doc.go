// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nptv6map implements the read/write API for the eBPF uSID datapath's
// nptv6_table map: one row per VRF configuring stateless RFC 6296 prefix
// translation, keyed identically to vrf_table on Block and Argument.
//
// # Reusing usidmap's map interfaces
//
// nptv6_table belongs to the same datapath program as vrf_table, not a separate
// one, so the map-operation seam usidmap already defines, its kernel adapter
// and its iterator, applies unchanged. This package imports them rather than
// re-declaring an identical interface that would only drift.
//
// # No kernel-persisted generation, unlike vrf_table
//
// vrf_table carries a generation in its kernel value because two unsynchronized
// processes write it and can race. nptv6_table has one writer: the periodic
// sweep in the same container that owns eBPF map access, since the CRD
// reconciler's own DaemonSet has neither the bpffs mount nor CAP_BPF to open a
// pinned map. A single writer ticking sequentially cannot race itself between
// listing CRDs and reconciling against them.
//
// NPTv6Table still exposes Generation and Reconcile with usidmap.VRFTable's
// method shape, for parity and against a future second writer, but the value is
// tracked only in this process's memory. A restart therefore forgets every
// entry's generation, which reads back as zero and so older than any cutoff.
// That is an accepted tradeoff: the sweep re-registers every live mapping on
// each tick before reconciling stale ones away, so a post-restart Reconcile
// misjudges freshness for at most one interval before the same tick re-stamps
// it.
//
// # No counter preservation
//
// Unlike vrf_table, nptv6_table carries no counters: its value is the two
// prefixes and the precomputed adjustment. Register therefore has no
// read-modify-write step, and every call is a plain overwrite.
package nptv6map
