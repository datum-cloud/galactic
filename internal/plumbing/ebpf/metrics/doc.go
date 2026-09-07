// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics implements the eBPF uSID datapath's Prometheus
// instrumentation.
//
// Two kinds of signal need two instrumentation styles, which is why they live
// in separate files:
//
//   - Per-Argument counters, drops by reason, and per-Block Argument
//     utilization are state currently held in a BPF map. They are read live
//     from the map at every scrape through a custom collector, rather than
//     mirrored into gauges. An entry the GC sweep removes then simply stops
//     being emitted on the next scrape, instead of leaking a stale label
//     combination forever: a gauge cannot expire one, while a collector that
//     re-derives its label set from the live source at every collection gets
//     that for free.
//   - Program load and attach events are discrete occurrences at the moment
//     they happen, held nowhere a collector could re-read them, so they are
//     ordinary counters incremented in place through the attach package's
//     hooks, wired once at process startup.
//
// Metrics bundles both into one registry plus an HTTP handler, so the caller
// constructs it once and needs no Prometheus imports of its own.
package metrics
