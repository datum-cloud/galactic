// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attach implements the eBPF uSID datapath's control-daemon load,
// attach, pin, and watch lifecycle.
//
// StartWatching is the entry point for the control daemon. It wraps Start and
// additionally launches Watch in a background goroutine, which subscribes to
// netlink link and route events and re-evaluates the resolved interface set
// whenever one occurs, attaching to newly resolved interfaces and detaching
// from ones that dropped out, for as long as the caller's context lives.
//
// Start is exported for tests and for a caller wanting only the one-time
// startup behavior. It does three things in order:
//
//  1. Runs the kernel-capability preflight check and refuses to proceed if it
//     fails. There is no partial fallback, and this must run before anything
//     below.
//  2. Loads the compiled usid_ingress object, pinning every map under a fixed
//     bpffs directory, so a control-daemon restart reuses the maps already
//     pinned there instead of recreating them empty.
//  3. Resolves the interface set, from an explicit override or by
//     auto-detection, and attaches usid_ingress to each one's ingress hook
//     through a clsact qdisc and a direct-action filter. Classic TC-BPF rather
//     than the newer tcx link mechanism, which keeps the attach path working
//     across the kernel range the preflight check targets. Re-attaching
//     replaces an existing galactic filter rather than stacking a duplicate,
//     which together with the pins makes Start idempotent across a restart.
//
// Once attached, the filter holds its own kernel reference to the program,
// independent of the process that loaded it. The returned objects can therefore
// stay open for the life of the process and be closed on shutdown without
// disrupting forwarding: closing releases this process's descriptors, and does
// not detach the filter or unpin the maps.
//
// This package populates none of the maps with real data and owns no
// health-check surface beyond Health itself. It builds the lifecycle the
// control-plane packages sit on.
package attach
