// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nat66map implements the read/write API for
// internal/plumbing/ebpf/nat66prog's two control-plane-facing maps
// (shard_config_table, a single-entry write target this shard's own
// operator-supplied identity is stamped into; drop_reasons, a per-CPU
// counter array) plus a read-only accessor for nat66_conn_table, the
// datapath's own self-managed LRU flow-state table.
//
// # nat66_conn_table is never written here
//
// nat66_conn_table (a BPF_MAP_TYPE_LRU_HASH) is written ONLY by
// nat66.c's own handle_forward/handle_return -- it allocates masquerade
// ports, claims rows via BPF_NOEXIST, and self-evicts under memory
// pressure with no GC needed, entirely inside the datapath. This mirrors
// the identical "never write conn_table, only read for observability"
// boundary internal/plumbing/ebpf/edgemap's now-removed edgenat.c-era
// ruletable.go doc comment described for that program's own conn_table:
// ConnTable in this package exposes Get/List only, no Register/Unregister/
// Reconcile at all -- there is no control-plane liveness set to reconcile
// this table against in the first place.
//
// # shard_config_table is the one thing the control plane does write
//
// shard_config_table (a single-entry BPF_MAP_TYPE_ARRAY, key uint32(0))
// carries this shard's own identity -- shard_sid and shard_pub_addr,
// both operator-supplied (see internal/config.NAT66Config) -- and is
// written exactly once, at process startup, by cmd/galactic-nat66's
// setupNat66Datapath. ShardConfigTable's Set/Get mirror
// internal/plumbing/ebpf/edgemap/doc.go's own reasoning for why
// encap_config_table (edgeprog's analogous single-entry map) doesn't get a
// dedicated wrapper there: unlike that case, this package does give
// shard_config_table one, because unlike edgeprog's encap_config_table
// (a single field, written directly by internal/gateway.NewKernelDatapath)
// this map's value has two fields and benefits from the same
// netip.Addr-typed, validated API every other table in this codebase's
// eBPF map layer already offers -- see internal/plumbing/ebpf/prog's own
// locator_table/vrf_table wrappers (internal/plumbing/ebpf/usidmap) for the
// precedent this package follows instead.
//
// # Reusing usidmap's or edgemap's Table/KernelTable/Iterator? No.
//
// nat66prog.nat66.c is its own standalone datapath -- no map or key layout
// shared with usid.c (usidmap) or edgedsr.c (edgemap) -- so, following
// edgemap's own doc comment's precedent for why it does not import
// usidmap's identical interface, this package declares its own Table/
// KernelTable/Iterator (table.go) rather than importing either.
//
// # Testability
//
// Every table type here is built against the Table interface (table.go),
// not directly against *ebpf.Map: KernelTable adapts a real, loaded map
// (e.g. nat66prog.Nat66Objects.ShardConfigTable) for production use, while
// this package's own tests substitute an in-memory fake to exercise every
// code path without a kernel or root privileges.
package nat66map
