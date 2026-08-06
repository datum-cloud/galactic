// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package usidmap implements the read/write API that populates and
// reconciles the eBPF uSID datapath's three control-plane maps --
// locator_table, function_table, and vrf_table (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §4.4; Milestone 3.3 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md).
//
// This package does not itself decide *when* to register or reconcile
// anything -- that is later milestones' job:
//
//   - Milestone 7.1 (CNI registration) calls VRFTable.Register from the
//     CNI ADD path (design plan §5.1) -- the only ingress/decap
//     registration; the legacy srv6.RouteIngressAdd static-route path
//     this originally ran alongside was deleted in the 2026-08-02 direct
//     cutover. The design plan's placeholder signature,
//     `usidmap.Register(argument, locatorBlock, vrfTableID)`, is
//     VRFTable.Register below (argument order: block, then argument, to
//     match Block-then-Argument ordering used throughout uformat).
//   - Milestone 7.2 (explicit unregister) calls VRFTable.Unregister from
//     the failed-ADD rollback path (internal/cni/resource.go's
//     resourceTracker.cleanup).
//   - Milestone 7.3 (GC sweep extension) calls VRFTable.Generation then
//     VRFTable.Reconcile from internal/gc's controller, comparing vrf_table
//     against live BGPVRFInstance CRDs.
//   - Milestone 3.1's control daemon (internal/plumbing/ebpf/attach) is
//     expected to call LocatorTable.Register/FunctionTable.Register at
//     startup (and on BGPRouter.Spec.SRv6Locator change) to seed
//     locator_table/function_table for this node's active uSID Block(s) --
//     that wiring is not part of this milestone's scope either; this
//     package only builds the API those call sites use.
//
// # The plugin-binary-vs-run-container race (design plan §5.4)
//
// Map writes happen from two different, unsynchronized processes: the
// kubelet-invoked galactic-cni plugin binary (Register/Unregister, on the
// CNI ADD/rollback path) and the long-lived `run` container (GC's
// reconciliation sweep). Because both hold an independent handle onto the
// same pinned kernel maps, they race by construction. The specific failure
// mode this package exists to prevent: a Register call for a brand new
// VPCAttachment lands *between* the GC sweep's list-CRDs step (which
// snapshots which Arguments currently have a live BGPVRFInstance) and its
// delete-stale-entries step (which removes vrf_table entries absent from
// that snapshot) -- without protection, the sweep would delete the
// just-registered entry, even though it is not stale at all: the CRD
// write and the map write are two different systems that can complete in
// either order or with a delay between them.
//
// The fix is a per-entry generation field, stamped by Register with the
// table's own monotonic clock reading (VRFTable.Generation; CLOCK_MONOTONIC,
// not wall-clock -- see table.go's monotonicNow for why). The GC controller
// calls VRFTable.Generation immediately *before* listing CRDs and passes
// the result to VRFTable.Reconcile as cutoff: any vrf_table entry with
// Generation >= cutoff was written at or after that snapshot was taken, so
// Reconcile always keeps it regardless of whether its key appears in the
// live set -- it is simply re-evaluated, correctly, on the *next* sweep,
// once the CRD has had a chance to actually appear in a fresh list. Only
// entries older than the snapshot (Generation < cutoff) are ever eligible
// for deletion, and then only if their key is genuinely absent from the
// live set.
//
// vrf_table's kernel-side value struct (prog.UsidVrfValue) carries this
// generation field directly, alongside the per-Argument hit counters
// (packets/bytes/last_seen_ns) that already existed from Milestone 2.2 --
// see usid.c's struct vrf_value comment for why this reconciles an
// apparent tension between the design plan's §4.2 (which described
// vrf_table's value as `{linux_vrf_table_id, generation, hit counter}`)
// and its later, narrower §4.4 map-inventory table (which listed only the
// counter fields): this milestone treats §4.2's inclusion of generation as
// the one this specific race requires, and implements it as a real
// struct field rather than an out-of-band side table, so it survives a
// control-daemon restart the same way the rest of vrf_table's state does
// (pinned under bpffs, design plan §4.4/§9). locator_table's value
// already had its own `generation` field from Milestone 2.2 (used for a
// different purpose -- R7's multiple-concurrent-Block bookkeeping, not
// this race -- since the GC sweep's scope, design plan §5.3, is vrf_table
// only; locator_table/function_table are not swept, so LocatorTable and
// FunctionTable below expose plain Register/Unregister/Get/List with no
// Reconcile/race handling to match).
//
// # Testability
//
// Every table type in this package (VRFTable, LocatorTable, FunctionTable)
// is built against the Table interface (table.go), not directly against
// *ebpf.Map -- KernelTable adapts a real, loaded map (e.g.
// prog.UsidObjects.VrfTable) to that interface for production use, while
// usidmap_test.go substitutes an in-memory fake implementation to exercise
// register/unregister/reconcile logic, including the race scenario above,
// without a kernel or root privileges (Milestone 3.3's own exit
// criterion). Registry (registry.go) is the convenience entry point that
// wires all three real, kernel-backed tables from a loaded
// *prog.UsidObjects in one call, for whichever later milestone's
// production code needs it.
package usidmap
