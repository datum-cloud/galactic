// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ebpf is the umbrella directory for the TC-BPF uSID datapath, the only
// ingress and decap path in this codebase. It holds no code of its own; this
// file orients a reader across the sub-packages, roughly in the order a packet
// passes through them:
//
//   - preflight: the kernel-capability check that must pass before anything
//     below is loaded. There is no partial fallback.
//   - uformat: the pure-Go bit-layout library for the uFMT 48+16 uSID carrier,
//     with no kernel dependency. Shared by the program's map-key arithmetic and
//     by the control plane's SID computation, so the two cannot drift on bit
//     positions.
//   - prog: the compiled program itself and its generated bindings, and the
//     single source of truth for the nine-step packet path.
//   - attach: the load, pin, attach, detach, and watch lifecycle, including
//     netlink-driven re-attachment when an interface or route change, or an
//     external event silently clearing the filter, requires it.
//   - usidmap: the read/write API that populates and reconciles the three
//     control-plane maps, used by the CNI ADD path and by garbage collection.
//   - metrics: Prometheus metrics and health event hooks spanning the whole
//     datapath.
//
// The CNI publish path and garbage collection are the two callers outside this
// tree driving the map registrations; the BGP reconcilers independently compute
// the same SID this datapath decodes.
package ebpf
