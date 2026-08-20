// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemetrics implements the edge XDP Maglev/DSR gateway's
// Prometheus instrumentation, following the same split
// internal/plumbing/ebpf/metrics already established for the SRv6 uSID
// datapath:
//
//   - Per-VIP hit counters (Packets/Bytes/DroppedPackets, current backend
//     count) and drop-by-reason state are all *state currently held in a
//     BPF map* -- vip_table, vip_stats_table, drop_reasons. Collector
//     (collector.go) reads these live, directly from the map, at every
//     Prometheus scrape via a custom prometheus.Collector, rather than
//     mirroring them into incrementally-Set() Gauges: a vip_table entry
//     internal/gateway.Engine.ReconcileOrphans removes simply stops being
//     emitted on the *next* scrape this way, instead of leaking a stale
//     label combination forever (a Gauge/GaugeVec has no way to "expire" a
//     label combination on its own; only a Collector that re-derives its
//     label set from the live source of truth at every Collect() call
//     gets that for free).
//   - Rule applications rejected before ever reaching the datapath (e.g.
//     QuotaEnforcer denials) are a control-plane-only fact with no BPF map
//     to read it back from -- that is
//     internal/gateway.PrometheusTelemetryEmitter's ordinary CounterVec,
//     incremented in place at Engine's own call sites, not this package's
//     concern.
//
// Unlike this package's Full-NAT edgenat.c-backed predecessor, there is no
// conn_table utilization metric here at all: DSR keeps no per-flow state
// to report on (see edgedsr.c's own header comment), and there is no
// per-rule primary/secondary placement metric either -- DSR's anycast
// model means every gateway node serves every VIP identically, with no
// primary/secondary distinction left to report.
package edgemetrics
