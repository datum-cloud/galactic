// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"
)

// TestMetricsScrape scrapes what the agent serves at /metrics, the
// instrumentation library's registry, once newMetrics has created the
// agent's series, and lints them.
func TestMetricsScrape(t *testing.T) {
	newMetrics()
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
