// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/edge/diag"
)

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once it holds the failure counters run
// creates, and lints them. The node collector reads the agent's pinned gate
// maps, so it is left out.
func TestMetricsScrape(t *testing.T) {
	diag.NewMetrics(diag.RoleNode)
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
