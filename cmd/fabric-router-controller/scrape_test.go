// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	routingmetrics "go.datum.net/galactic/internal/fabric/routing/metrics"
)

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, with the fleet collector run
// registers. Only the leader's collector emits series, so this one, never
// started, checks that its descriptors fit beside the others.
func TestMetricsScrape(t *testing.T) {
	metrics.MustRegister(&routingmetrics.Collector{})
	instrumenttest.AssertScrapes(t, metrics.Handler())
}
