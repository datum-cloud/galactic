// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nptv6map implements the read/write API for the eBPF uSID
// datapath's nptv6_table map (internal/plumbing/ebpf/prog/usid.c's struct
// nptv6_value comment) -- one row per VRF configuring stateless RFC 6296
// Network Prefix Translation (internal/plumbing/nptv6), keyed identically to
// vrf_table: Block(48)<<12 | Argument(12) (internal/plumbing/ebpf/uformat's
// NewVRFKey).
//
// # Reusing usidmap.Table/KernelTable/Iterator instead of duplicating them
//
// nptv6_table is defined in the exact same usid.c/prog package as vrf_table
// (internal/plumbing/ebpf/usidmap), not a second, independent datapath --
// unlike internal/plumbing/ebpf/edgemap (a different eBPF program entirely,
// with no shared map layout at all, which is usidmap/doc.go's own stated
// reason for NOT importing edgemap's duplicate Table/KernelTable/Iterator
// definitions). Because nptv6_table and vrf_table are two maps of the one
// uSID datapath, the map-operation seam usidmap.Table already defines (plus
// its KernelTable adapter over a real *ebpf.Map, and its Iterator interface)
// applies unchanged here: this package imports and depends on usidmap
// directly rather than re-declaring an identical interface, which would
// only invite the two to drift.
//
// # Why this table has no Generation/monotonic-clock kernel field, unlike vrf_table
//
// vrf_table's value (struct vrf_value) carries a real `generation` field,
// because vrf_table has two independent, unsynchronized OS-process writers
// that can race each other: the kubelet-invoked galactic-cni plugin binary
// (VRFTable.Register, on the CNI ADD path) and the long-lived "run"
// container's periodic GC sweep (VRFTable.Reconcile) -- see usidmap/doc.go's
// "plugin-binary-vs-run-container race" section. nptv6_table's value
// (struct nptv6_value) was deliberately not given an equivalent field: this
// milestone's only writer of nptv6_table is that same "run" container's own
// periodic sweep (gc.SweepEBPFNPTv6Table, called from
// internal/installer.Run's ebpfGCSweepTicker, exactly where
// gc.SweepEBPFVRFTable already runs -- see that function's own doc comment
// for why eBPF map access is confined to this one container: galactic-router's
// DaemonSet has no /sys/fs/bpf hostPath mount or CAP_BPF at all, so the
// BGPVRFInstance reconciler (internal/controller) cannot open a pinned eBPF
// map to register anything into directly, regardless of how the CRD's own
// NPTv6 field is validated). A single writer, ticking sequentially in one
// goroutine, cannot race itself between listing BGPVRFInstance CRDs and
// reconciling nptv6_table against them -- there is no second process able to
// register a brand-new mapping in the gap the way a concurrent CNI ADD can
// for vrf_table.
//
// NPTv6Table still exposes Generation/Reconcile with the same method shape
// as usidmap.VRFTable, for interface parity and because a future second
// writer is not inconceivable, but the generation value itself is tracked
// only in this process's own memory (an internal map keyed by NPTv6Key),
// not persisted into the kernel value the way vrf_table's is. This means a
// process restart forgets every previously-registered entry's generation
// (it reads back as zero, "older than any cutoff"), unlike vrf_table's
// kernel-persisted field, which survives a control-daemon restart within
// the same boot. This is an accepted, intentional tradeoff, not an
// oversight: gc.SweepEBPFNPTv6Table's own caller (internal/installer.Run)
// re-registers every currently-live NPTv6 mapping on every tick before
// reconciling stale ones away, so a post-restart Reconcile call only ever
// mis-judges an entry's freshness for at most one sweep interval before the
// same tick's own Register calls (which run first) re-stamp it -- see
// SweepEBPFNPTv6Table's own doc comment for the exact ordering.
//
// # No counter-preservation
//
// Unlike vrf_table's per-Argument hit counters (packets/bytes/last_seen_ns/
// dropped_packets), nptv6_table carries no counters at all -- its value is
// purely the two prefixes and the precomputed RFC 6296 adjustment. Register
// therefore has no read-modify-write step to carry anything forward from an
// existing entry; every call is a plain overwrite.
package nptv6map
