// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/config"
)

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once newSidecarMetrics has created
// every series the sidecar serves, and lints them.
func TestMetricsScrape(t *testing.T) {
	cfg := config.NewVRFConfig()
	cfg.NodeName = "node-a"
	newSidecarMetrics(cfg)
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
