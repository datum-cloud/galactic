// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package markvrfmap implements the read/write API for the eBPF uSID
// datapath's mark_vrf_table map (internal/plumbing/ebpf/prog/usid.c's
// struct mark_vrf_value comment): one row per VPC a shared trunk interface
// serves, keyed by the SO_MARK value Envoy stamps on a socket bound to that
// VPC, mapping it to the (Block, Argument) that VPC's VRF resolves to.
//
// usid_egress consults mark_vrf_table only as a fallback, after
// ifindex_vrf_table (internal/plumbing/ebpf/ifindexvrfmap) has already
// missed -- an ordinary per-attachment tenant veth/tap always has its own
// ifindex_vrf_table entry and never reaches this table at all. Mark-based
// resolution only becomes load-bearing for traffic arriving on a shared
// trunk interface, where a single ifindex serves many VPCs and therefore
// cannot disambiguate them the way a per-attachment ifindex does.
//
// # Reusing usidmap.Table/KernelTable/Iterator instead of duplicating them
//
// Same reasoning as ifindexvrfmap's own doc comment: mark_vrf_table is a
// map of the same usid.c/prog package as vrf_table and ifindex_vrf_table,
// not a second datapath, so this package imports and depends on
// usidmap.Table/KernelTable/Iterator directly rather than re-declaring
// them.
//
// # Lifecycle: driven by internal/ingresssidecar's per-VPC reconciler
//
// Register happens from internal/ingresssidecar's ensureEgressDatapath,
// the same call site that already registers this VPC's vrf_table entry --
// keyed additionally by a mark value derived from the VPC's own VRF table
// ID (markForTableID), not by any attachment-scoped ifindex, since the
// trunk interface backing this mark is shared across every VPC that
// process's Envoy Gateway pod reaches. Unregister happens from the
// matching removeEgressDatapath, mirroring ifindex_vrf_table's own
// register/unregister lifecycle but keyed on mark instead of ifindex, and
// without ever tearing down the shared trunk interface itself -- that
// persists for the owning process's lifetime.
//
// Register/Unregister/Get/List/Reconcile method shapes mirror
// ifindexvrfmap.IfindexVRFTable's own for API consistency and testability,
// including a process-local Generation not persisted in the kernel value.
package markvrfmap
