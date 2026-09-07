// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gateway implements the in-process edge Maglev direct-server-return
// load-balancing engine. One Engine runs per gateway-role node, converging that
// node's accepted NetworkRule resources into calls against a pluggable
// Datapath.
//
// It backs onto the edge XDP program directly: no tunnel, no per-tenant
// provisioning, and no VRF dependency, since the outer SRv6 header is pushed
// from the program's own vip_table rather than a kernel route.
//
// There is no primary or secondary gateway node and no BGP local preference to
// carry. Every node computes the same consistent-hash backend assignment from
// the same VIP and backend list, so every node in a PoP serves every rule
// identically under anycast.
//
//   - engine.go: Engine, the mutex-guarded convergence loop. It applies
//     everything in desired state and removes everything absent from it, rather
//     than diffing field by field, so a partial previous failure self-heals on
//     the next pass.
//   - types.go: the engine's own representation of a rule and its backends,
//     assembled by the reconcilers.
//   - datapath.go: the Datapath, QuotaEnforcer, and TelemetryEmitter interfaces
//     Engine calls through. KernelDatapath is the real implementation: it builds
//     a Maglev table over each rule's backend set and flattens it into the
//     fixed-size arrays the map layer expects. Loading and attaching the program
//     happens at process startup, not here. The other two interfaces have real
//     implementations, with no-op variants kept for tests.
//   - recovery.go: the crash-recovery pass for a process that died
//     mid-reconcile, delegating to the map layer's generation cutoff, since
//     map state is the only thing this design can leak on a crash.
//   - diff.go: the pure key-set diff both reconcile paths build on.
package gateway
