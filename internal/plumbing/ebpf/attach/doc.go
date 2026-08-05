// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attach implements the eBPF/TC-BPF uSID datapath's control-daemon
// load/attach/pin/watch lifecycle (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §4.1, §4.4, §5.4, §9; Milestones
// 3.1 and 3.2 of .local/implementation-plan-ebpf-xdp-usid-datapath.md).
//
// StartWatching (the package's entry point for galactic-cni's `run`
// subcommand, internal/installer.Run) wraps Start (below) and additionally
// launches Watch in a background goroutine: for as long as the caller's
// context isn't canceled, Watch subscribes to netlink link and route change
// events and re-evaluates the resolved interface set whenever one occurs
// (design plan §4.1: "re-evaluate on interface/route change events
// (netlink subscription), not just at startup"), attaching to newly
// resolved interfaces and detaching from ones that dropped out -- Milestone
// 3.2, this package's own gap flagged by Milestone 3.1's handoff notes.
//
// Start itself (still exported directly for tests and any caller that only
// wants the one-time startup behavior) does three things, in order:
//
//  1. Runs internal/plumbing/ebpf/preflight's kernel-capability check and
//     refuses to proceed at all if it fails -- there is no partial/unsafe
//     fallback (design plan §6). This must run before anything below.
//  2. Loads internal/plumbing/ebpf/prog's compiled usid_ingress object,
//     pinning every map under a fixed bpffs directory (PinDir,
//     /sys/fs/bpf/galactic by default) so a control-daemon restart reuses
//     the maps already pinned there from a previous run instead of
//     recreating them empty -- pinned-map continuity across a container
//     restart (design plan §4.4/§9), this milestone's exit criterion.
//  3. Resolves the interface set to attach to (design plan §4.1): an
//     explicit GALACTIC_CNI_EBPF_INTERFACES override, if set, or
//     auto-detection of the interface(s) carrying the default IPv6 route,
//     then attaches usid_ingress to each one's ingress hook via a clsact
//     qdisc + direct-action BPF filter (classic TC-BPF, not the newer
//     kernel-6.6+-only TCX link mechanism -- the design plan explicitly
//     says "TC-BPF (clsact qdisc, ingress)", and this keeps the attach path
//     working across the widest kernel range the preflight check already
//     targets). Re-running Attach against an interface that already has a
//     galactic uSID filter replaces it (netlink.FilterReplace) rather than
//     stacking a duplicate -- this is what makes Start idempotent across a
//     container restart, alongside the maps' own pin persistence.
//
// Once attached, the classic tc filter holds its own kernel reference to
// the loaded program independent of the process that created it (design
// plan §5.4: "BPF programs, once attached, run independently of the
// process that loaded them") -- so the returned *prog.UsidObjects can be
// (and, in internal/installer.Run, is) kept open for the life of the
// process and Closed only on shutdown, without disrupting already-attached
// forwarding: Close releases this process's own map/program file
// descriptors, it does not detach the filter or unpin the maps.
//
// This package does not yet populate locator_table/function_table/
// vrf_table with real data (that's Milestone 3.3's GC-facing map API and
// Milestones 6/7's control-plane encoder and CNI registration call), and
// does not expose a health-check surface (Milestone 4). It only builds the
// load/attach/pin/watch lifecycle those milestones build on.
package attach
