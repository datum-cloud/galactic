// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/fabric/gateway"
	"go.datum.net/galactic/internal/fabric/index"
	"go.datum.net/galactic/internal/fabric/node"
)

// TestMetricsScrape scrapes what both roles serve at /metrics, the
// instrumentation library's registry, once it holds the series each creates
// at startup, and lints them. Both roles define the certificate and
// credential gauges, so this also checks that their definitions agree. The
// gateway's admission and service switch gauges read a running cell, so they
// are left out.
func TestMetricsScrape(t *testing.T) {
	gateway.NewMetrics(func() float64 { return 0 })
	m := node.NewMetrics()
	m.RegisterClock(func() error { return nil })
	m.RegisterIndex(index.New())
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
