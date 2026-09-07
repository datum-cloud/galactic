// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package usidmap implements the read/write API that populates and reconciles
// the eBPF uSID datapath's three control-plane maps: locator_table,
// function_table, and vrf_table.
//
// It decides nothing about when to register or reconcile. The CNI ADD path
// registers a VRF entry and the rollback path unregisters it; the GC sweep
// calls Generation then Reconcile, comparing vrf_table against live
// BGPVRFInstance CRDs; the control daemon seeds locator_table and
// function_table for this node's active uSID Blocks at startup and whenever the
// router's locator changes.
//
// # The two-writer race
//
// Map writes come from two unsynchronized processes: the kubelet-invoked CNI
// plugin binary, on the ADD and rollback paths, and the long-lived control
// container, on the GC sweep. Both hold independent handles on the same pinned
// maps, so they race by construction.
//
// The failure this package prevents: a Register for a new attachment lands
// between the sweep's list-CRDs step, which snapshots which Arguments have a
// live CRD, and its delete-stale-entries step. Without protection the sweep
// deletes an entry that is not stale at all, the CRD write and the map write
// being two systems that can complete in either order.
//
// The fix is a per-entry generation, stamped by Register from the table's
// monotonic clock. The sweep reads Generation immediately before listing CRDs
// and passes it to Reconcile as a cutoff: an entry at or above the cutoff was
// written at or after the snapshot, so it is always kept and re-evaluated on
// the next sweep, once the CRD has had a chance to appear. Only older entries
// whose key is genuinely absent from the live set are deleted.
//
// vrf_table's kernel value carries that generation directly, alongside the
// per-Argument counters, so it survives a control-daemon restart the way the
// rest of the table's state does. locator_table's value carries a generation of
// its own for unrelated multi-Block bookkeeping. Neither locator_table nor
// function_table is swept, so their table types expose no Reconcile.
//
// # Testability
//
// Every table type is built against the Table interface rather than directly
// against a loaded map. KernelTable adapts a real map for production, while
// tests substitute an in-memory fake to exercise register, unregister, and
// reconcile logic, including the race above, without a kernel or root. Registry
// wires all three kernel-backed tables from a loaded object set in one call.
package usidmap
