// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gateway implements the in-process edge NAT+LB gateway engine
// described in the design plan
// (.claude/plans/merry-percolating-tulip.md). One Engine runs per
// gateway-role node (one process, one NetworkGateway object), converging
// the set of accepted network.datumapis.com/v1alpha1 NetworkRule resources
// for that node into calls against a pluggable Datapath (datapath.go).
//
// This is a deliberate pivot away from an earlier, rejected design that
// tunneled tenant traffic to gateway nodes over Geneve and drove a TC-BPF
// program keyed by (VNI, 5-tuple), after three rounds of live spikes ruled
// out driving LoxiLB directly and found native XDP unavailable
// specifically on Geneve tunnel devices. This package instead backs onto
// internal/plumbing/ebpf/edgeprog's XDP program directly: no tunnel, no
// per-tenant Geneve provisioning, and — because the outer SRv6 header is
// pushed straight from the program's own rule_table (resolved via
// internal/plumbing/ebpf/edgemap) rather than a kernel VRF route — no VRF
// dependency and no exposure to the two GoBGP bugs
// ([[project_vpc20_siit_gateway_design]] in the operator's memory; see
// internal/runtime/gobgp/monitor.go's processEVPNPath and runtime.go's
// rtIndex) that forced every earlier per-VPC gateway design to colocate
// with the workload's own VRF.
//
//   - engine.go: Engine, the mutex-guarded convergence loop, mirroring
//     internal/runtime/gobgp's GoBGPRuntime shape ("apply everything in
//     desired, remove everything not in desired" rather than a
//     field-level diff, so a partial previous failure self-heals on the
//     next Reconcile).
//   - types.go: DesiredRule/DesiredBackend/EngineState/EngineStatus, the
//     engine's own representation of a NetworkRule, assembled by the
//     future NetworkGateway/NetworkRule controllers.
//   - datapath.go: the Datapath/QuotaEnforcer/TelemetryEmitter interfaces
//     Engine calls through. KernelDatapath (kerneldatapath.go) is the
//     real Datapath implementation, backed by
//     internal/plumbing/ebpf/edgemap's RuleTable and a loaded
//     internal/plumbing/ebpf/edgeprog.EdgenatObjects (loading/attaching
//     that object to an interface is internal/plumbing/ebpf/edgeattach's
//     job, called from cmd/galactic-router's own startup, not from
//     anywhere in this package). QuotaEnforcer/TelemetryEmitter remain
//     Noop-stubbed (deferred to the design plan's Phase E).
//   - placement.go/localpref.go: the Active-Active BGP model's pure,
//     dependency-free primary-node hashing and local-preference lookup —
//     unaffected by the datapath pivot above, since they never touched
//     Geneve/TC-BPF/VRF state in the first place.
//   - recovery.go: Engine.ReconcileOrphans, the crash-recovery pass for a
//     process that died mid-reconcile — unlike the earlier design's
//     Geneve-interface scan, this delegates directly to
//     edgemap.RuleTable.Reconcile's own Generation-cutoff mechanism (see
//     that package's doc comment), since rule_table state (not a kernel
//     interface) is the only thing this design can leak on a crash.
//   - diff.go: diffRuleKeys, the pure key-set diff both Reconcile and
//     ReconcileOrphans build on.
package gateway
