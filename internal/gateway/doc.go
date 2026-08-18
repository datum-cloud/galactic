// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gateway implements the in-process edge Maglev/DSR (Direct Server
// Return) load-balancing gateway engine. One Engine runs per gateway-role
// node (one process, one NetworkGateway object), converging the set of
// accepted network.datumapis.com/v1alpha1 NetworkRule resources for that
// node into calls against a pluggable Datapath (datapath.go).
//
// This package backs onto internal/plumbing/ebpf/edgeprog's XDP program
// directly: no tunnel, no per-tenant provisioning, and — because the outer
// SRv6 header is pushed straight from the program's own vip_table (resolved
// via internal/plumbing/ebpf/edgemap) rather than a kernel VRF route — no
// VRF dependency.
//
// This is also a pivot away from this package's own earlier, Full-NAT
// (DNAT+SNAT) design: that design needed an Active-Active BGP model
// (placement.go/localpref.go, both since deleted) because only one gateway
// node at a time could hold a given rule's translation/conntrack state.
// Maglev/DSR has no such state — every gateway node computes the identical
// consistent-hash backend assignment for the identical (VIP, backend list)
// input (internal/maglev's own doc comment), so every gateway node in a PoP
// serves every rule identically under anycast/ECMP, with no primary/
// secondary distinction and no BGP local-preference to carry. See
// edgedsr.c's own header comment for the full packet-path rationale.
//
//   - engine.go: Engine, the mutex-guarded convergence loop, mirroring
//     internal/runtime/gobgp's GoBGPRuntime shape ("apply everything in
//     desired, remove everything not in desired" rather than a
//     field-level diff, so a partial previous failure self-heals on the
//     next Reconcile).
//   - types.go: DesiredRule/DesiredBackend/EngineState/EngineStatus, the
//     engine's own representation of a NetworkRule, assembled by the
//     future NetworkGateway/NetworkRule controllers. DesiredBackend
//     implements internal/maglev.Backend directly (see its Key() method).
//   - datapath.go: the Datapath/QuotaEnforcer/TelemetryEmitter interfaces
//     Engine calls through. KernelDatapath (kerneldatapath.go) is the
//     real Datapath implementation: it builds an internal/maglev.Table
//     over each rule's backend set and flattens it into the fixed-size
//     arrays internal/plumbing/ebpf/edgemap's VIPTable expects, backed by
//     a loaded internal/plumbing/ebpf/edgeprog.EdgedsrObjects (loading/
//     attaching that object to an interface is
//     internal/plumbing/ebpf/edgeattach's job, called from
//     cmd/galactic-gateway's own startup, not from anywhere in this
//     package). QuotaEnforcer/TelemetryEmitter have real implementations
//     (quota.go/telemetry.go); Noop variants remain for tests.
//   - recovery.go: Engine.ReconcileOrphans, the crash-recovery pass for a
//     process that died mid-reconcile — delegates directly to
//     edgemap.VIPTable.Reconcile's own Generation-cutoff mechanism (see
//     that package's doc comment), since vip_table state (not a kernel
//     interface) is the only thing this design can leak on a crash.
//   - diff.go: diffRuleKeys, the pure key-set diff both Reconcile and
//     ReconcileOrphans build on.
package gateway
