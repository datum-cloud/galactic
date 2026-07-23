// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics implements the eBPF uSID datapath's Prometheus
// instrumentation (design plan .local/plan-ebpf-xdp-usid-datapath.md §9's
// observability bullet: "Export Prometheus metrics for: packets/bytes per
// Argument (VRF), drops by reason (drop_reasons map), BPF program
// load/reload events and failures, and ... current Argument-space
// utilization per uSID Block"; Milestone 4 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md).
//
// Two different kinds of signal need two different Prometheus
// instrumentation styles here, and this package keeps them in separate
// files for that reason:
//
//   - packets/bytes per Argument, drops by reason, and per-Block Argument
//     utilization (collector.go) are all *state currently held in a BPF
//     map* -- vrf_table, locator_table, drop_reasons. These are read live,
//     directly from the map, at every Prometheus scrape via a custom
//     prometheus.Collector, rather than mirrored into incrementally-
//     `Set()` Gauges: a vrf_table entry the GC sweep removes (Milestone
//     7.3, internal/plumbing/ebpf/usidmap.VRFTable.Reconcile) simply stops
//     being emitted on the *next* scrape this way, instead of leaking a
//     stale label combination in a Gauge/GaugeVec forever (Prometheus
//     Gauges have no way to "expire" a label combination on their own;
//     only a Collector that re-derives its label set from the live source
//     of truth at every Collect() call gets that for free).
//   - BPF program load/reload events and failures (events.go) are
//     discrete occurrences at the moment they happen (a Load() call
//     succeeding or failing; an interface being attached/detached),
//     not values held anywhere the collector could re-read later --
//     so these are ordinary prometheus.CounterVecs, incremented in place
//     via internal/plumbing/ebpf/attach's LoadHook/AttachHook callbacks
//     (attach/hooks.go), wired once via attach.SetHooks at process
//     startup (internal/installer.Run).
//
// Metrics (metrics.go) bundles both into one prometheus.Registry plus an
// http.Handler for internal/installer.Run to serve, so that package only
// needs to call metrics.New() once and doesn't need to import
// prometheus/promhttp directly.
package metrics
