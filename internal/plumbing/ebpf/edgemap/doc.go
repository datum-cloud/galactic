// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemap implements the read/write API that populates
// internal/plumbing/ebpf/edgeprog's vip_table -- the Maglev/DSR datapath's
// only control-plane-writable map with a nontrivial schema. encap_config_table
// (a single entry: this node's own SRv6-reachable encap source address) is
// written directly by internal/gateway.NewKernelDatapath instead of through
// a wrapper here -- one field, one Put call, at process startup only, not
// worth a dedicated type.
//
// vip_stats_table is a partial exception to "control-plane maps": this
// package reads it (VIPTable.Get/List, to report a VIP's hit counters) and
// deletes from it (VIPTable.Unregister, so a removed VIP's counters don't
// linger), but never writes to it -- edgedsr.c populates every
// vip_stats_table row itself, lazily, on a VIP's first matching packet. See
// VIPTable.Register's doc comment for why (issue #361): vip_table and
// vip_stats_table used to be one map (edgenat.c's rule_table/
// rule_stats_table predecessor), and Register's read-modify-write to
// preserve that map's counters across re-registration raced the datapath's
// own per-packet increments into the same fields, discarding whichever
// landed second. Splitting the counters into a map Register never touches
// at all removes the race instead of narrowing it.
//
// This package does not itself decide *when* to register anything, load the
// program, or attach it to an interface -- that is internal/gateway.Engine's
// job (via its Datapath interface) and internal/plumbing/ebpf/edgeattach's,
// analogous to internal/plumbing/ebpf/attach but for this program.
//
// # Why VIPTable carries a Generation field
//
// internal/gateway.Engine is a single long-lived process, but it can still
// crash mid-reconcile and leave vip_table entries behind with no
// corresponding NetworkRule left to reconcile them against.
// VIPTable.Reconcile's cutoff/Generation mechanism guards exactly that
// crash-restart window -- the same register-after-snapshot-is-safe
// guarantee internal/plumbing/ebpf/usidmap.VRFTable's identical mechanism
// already documents. Generation lives on vip_table's own value
// (EdgedsrVipValue), not vip_stats_table -- it is stamped by Register, which
// never touches vip_stats_table (see above).
//
// # Testability
//
// VIPTable is built against the Table interface (table.go), not directly
// against *ebpf.Map -- KernelTable adapts a real, loaded map (e.g.
// edgeprog.EdgedsrObjects.VipTable) for production use, while this
// package's own tests substitute an in-memory fake implementation to
// exercise register/unregister/reconcile logic without a kernel or root
// privileges. Table/Iterator/KernelTable are a deliberate duplicate of
// usidmap's identical types, not an import of them -- this package and
// usidmap serve two unrelated datapaths (edge ingress Maglev/DSR LB vs.
// SRv6 uSID decap) with no shared map/key layout, so importing usidmap
// would gain nothing but coupling.
package edgemap
