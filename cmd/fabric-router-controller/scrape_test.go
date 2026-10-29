// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"sync"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	routingmetrics "go.datum.net/galactic/internal/fabric/routing/metrics"
)

// startup registers the collector once per test process, as run does once
// per process, so repeated runs of TestMetricsScrape share it.
var startup sync.Once

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, with the fleet collector run
// registers. Only the leader's collector emits series, so this one, never
// started, checks that its descriptors fit beside the others.
func TestMetricsScrape(t *testing.T) {
	startup.Do(func() { metrics.MustRegister(&routingmetrics.Collector{}) })
	instrumenttest.AssertScrapes(t, metrics.Handler())
}
