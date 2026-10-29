// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemetrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once it holds the series run creates
// at startup that need no kernel: the telemetry emitter's and the dispatcher
// lease's. It lints them too. The edge datapath collector reads loaded maps,
// so it is left out.
func TestMetricsScrape(t *testing.T) {
	gateway.NewPrometheusTelemetryEmitter()
	xdpdispatch.NewLeaseMetrics(edgemetrics.Namespace)
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
