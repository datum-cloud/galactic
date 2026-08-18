// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ifindexvrfmap implements the read/write API for the eBPF uSID
// datapath's ifindex_vrf_table map (internal/plumbing/ebpf/prog/usid.c's
// struct ifindex_vrf_value comment): one row per attachment (veth or tap),
// keyed by that attachment's own host-side interface ifindex, mapping it to
// the (Block, Argument) its VRF resolves to. usid_egress consults this to
// resolve which VRF a plain, not-yet-encapsulated outbound packet on a
// tenant's own interface belongs to, since it has no outer uSID destination
// to decode that from the way usid_ingress does.
//
// # Reusing usidmap.Table/KernelTable/Iterator instead of duplicating them
//
// Same reasoning as nptv6map's own doc comment: ifindex_vrf_table is a map
// of the same usid.c/prog package as vrf_table, not a second datapath, so
// this package imports and depends on usidmap.Table/KernelTable/Iterator
// directly rather than re-declaring them.
//
// # Lifecycle: CNI DEL, not a periodic GC sweep
//
// Unlike vrf_table (whose (Block, Argument) key is shared by every
// attachment on one VPC/node, and therefore needs the GC-driven
// list-live-CRDs-then-reconcile pattern -- see usidmap.VRFTable.Reconcile
// and gc.SweepEBPFVRFTable), ifindex_vrf_table's key is a single
// attachment's own host-side ifindex: genuinely private to that one
// attachment, exactly the same category internal/cni's own cmdDel doc
// comment already puts the host/guest veth pair itself in ("the veth pair
// is genuinely private to this attachment ... no sibling pod can ever still
// be depending on it, so there is no ADD-race to defer to GC for") and
// internal/cnitap's cmdDel puts the tap device in.
//
// Register happens from internal/cnibgp's registerEBPFDatapath, the exact
// call site that already registers this same attachment's vrf_table entry
// (Milestone 7.1), keyed additionally by the host-side interface's ifindex
// (resolved there via netlink.LinkByName + intf.GenerateInterfaceNameHost --
// see registerEBPFDatapath's own doc comment for why that one, narrow,
// read-only kernel query is an accepted exception to galactic-bgp's
// otherwise "zero kernel-interface dependency" design).
//
// Unregister happens directly at CNI DEL time -- internal/cni's and
// internal/cnitap's own cmdDel, immediately before (and using the same
// already-resolved ifindex as) their existing veth.Delete/tap.Delete calls
// -- rather than from a periodic GC sweep: no CRD anywhere records an
// ifindex (crdnames carries no such annotation), so there is no live-set
// gc.SweepEBPFVRFTable's own pattern could reconcile against without
// inventing a new liveness-tracking mechanism this codebase has no
// analogue for. CNI DEL already knows precisely when this attachment's own
// interface is being destroyed and is best-effort/log-only on every other
// step in that same function, so wiring Unregister there needs no new
// machinery at all.
//
// Register/Unregister/Get/List/Reconcile method shapes mirror
// usidmap.VRFTable's own for API consistency and testability, including a
// process-local Generation (see nptv6map's doc comment for why this table's
// value carries no kernel-persisted generation field either) -- but
// Reconcile is not wired into any production sweep today, precisely because
// CNI DEL already owns this table's cleanup; it exists for parity, test
// coverage, and as a future defense-in-depth backstop (e.g. a kubelet force
// delete that skips CNI DEL entirely) should one ever be added.
package ifindexvrfmap
