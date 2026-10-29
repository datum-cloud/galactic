// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/serviceroute"
)

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once the service route metrics run
// creates at startup exist, and lints them. The traffic policy collector
// reads pinned eBPF maps, so it is left out.
func TestMetricsScrape(t *testing.T) {
	serviceroute.NewMetrics()
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
