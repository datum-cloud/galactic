// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/installer"
)

// TestMetricsScrape scrapes what the run daemon serves at /metrics, the
// instrumentation library's registry, once installer.NewMetrics has created
// its series, and lints them. The datapath collectors that read loaded eBPF
// maps need a kernel, so they are left out.
func TestMetricsScrape(t *testing.T) {
	installer.NewMetrics()
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
