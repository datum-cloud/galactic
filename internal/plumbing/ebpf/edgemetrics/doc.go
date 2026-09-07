// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemetrics implements the edge XDP gateway's Prometheus
// instrumentation, following the same split as the uSID datapath's:
//
//   - Per-VIP counters, backend counts, and drops by reason are state
//     currently held in a BPF map, read live at every scrape through a custom
//     collector rather than mirrored into gauges. An entry the engine's orphan
//     sweep removes then stops being emitted on the next scrape, instead of
//     leaking a stale label combination forever: a gauge cannot expire one,
//     while a collector that re-derives its label set at every collection gets
//     that for free.
//   - Rule applications rejected before reaching the datapath, such as a quota
//     denial, are a control-plane fact with no map to read them back from.
//     Those are an ordinary counter incremented at the engine's own call sites,
//     not this package's concern.
//
// There is no connection-table utilization metric: direct server return keeps
// no per-flow state to report. There is no per-rule placement metric either,
// every gateway node serving every VIP identically under anycast.
package edgemetrics
