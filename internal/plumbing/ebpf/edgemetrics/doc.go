// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemetrics implements the edge XDP NAT+LB gateway's Prometheus
// instrumentation (design plan Phase E), following the same split
// internal/plumbing/ebpf/metrics already established for the SRv6 uSID
// datapath:
//
//   - Per-rule hit counters (Packets/Bytes/DroppedPackets, current
//     backend count) and aggregate drop/conn_table-utilization state are
//     all *state currently held in a BPF map* -- rule_table, conn_table,
//     drop_reasons. Collector (collector.go) reads these live, directly
//     from the map, at every Prometheus scrape via a custom
//     prometheus.Collector, rather than mirroring them into
//     incrementally-Set() Gauges: a rule_table entry
//     internal/gateway.Engine.ReconcileOrphans removes simply stops being
//     emitted on the *next* scrape this way, instead of leaking a stale
//     label combination forever (a Gauge/GaugeVec has no way to "expire" a
//     label combination on its own; only a Collector that re-derives its
//     label set from the live source of truth at every Collect() call
//     gets that for free).
//   - Which gateway node is primary/secondary for a rule, and rule
//     applications rejected before ever reaching the datapath (e.g.
//     QuotaEnforcer denials), are control-plane-only facts with no BPF
//     map to read them back from -- those are
//     internal/gateway.PrometheusTelemetryEmitter's ordinary
//     GaugeVec/CounterVec, incremented in place at Engine's own call
//     sites, not this package's concern.
package edgemetrics
