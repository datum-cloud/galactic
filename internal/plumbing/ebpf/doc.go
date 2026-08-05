// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ebpf is the umbrella directory for the TC-BPF uSID datapath that
// replaced galactic's legacy per-endpoint seg6local ingress route model in
// the 2026-08-02 direct cutover (internal/plumbing/srv6/srv6.go, deleted --
// this datapath is now the only ingress/decap path). It holds no code of
// its own; see design plan .local/plan-ebpf-xdp-usid-datapath.md and its
// milestone breakdown, .local/implementation-plan-ebpf-xdp-usid-datapath.md,
// for the full design. This file only orients a reader across the
// sub-packages, roughly in the order a packet (and a reader) passes through
// them:
//
//   - preflight: the kernel-capability check (BTF, HASH maps, SCHED_CLS,
//     and specifically bpf_fib_lookup's VRF-tbid parameter) that must pass
//     before anything below is loaded -- there is no partial/unsafe
//     fallback.
//   - uformat: the pure-Go bit-layout encode/decode library for the uFMT
//     48+16 uSID carrier (Block/Node-ID/Function/Argument) -- no kernel
//     dependency; shared by prog's map-key arithmetic and by
//     internal/plumbing/srv6's ComputeSID so the kernel program and the Go
//     control plane can never drift on bit positions.
//   - prog: the compiled TC-BPF program itself (usid.c) and its bpf2go-
//     generated Go bindings; the single source of truth for the 9-step
//     packet path (parse, locator_table match, read Function, function_table
//     match, read Argument, vrf_table match, strip outer header,
//     bpf_fib_lookup, redirect).
//   - attach: the load/pin/attach/detach/watch lifecycle that wires prog's
//     compiled object into galactic-cni's `run` subcommand, including
//     netlink-driven re-attachment when an interface/route change -- or an
//     external event silently clearing the filter -- requires it.
//   - usidmap: the read/write API that populates and reconciles
//     locator_table/function_table/vrf_table, used by the CNI ADD path's
//     registration call (internal/cni/bgp.go) and by the GC controller's
//     sweep (internal/gc).
//   - metrics: Prometheus metrics and health-check event hooks spanning the
//     whole datapath (load/attach events, drops by reason, per-Argument
//     hit counters and Argument-space utilization).
//
// internal/cni and internal/gc are the two callers outside this tree that
// drive usidmap's register/unregister/reconcile calls; internal/reconcile
// and internal/plumbing/srv6's ComputeSID independently compute the same
// SID this datapath decodes, for the BGP control-plane side of the same
// design.
package ebpf
