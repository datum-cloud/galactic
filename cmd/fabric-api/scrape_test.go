// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/fabric/node"
)

// TestMetricsScrape scrapes both roles' /metrics: the gateway's manager
// serves controller-runtime's registry, which metrics.Handler serves
// unchanged, and the node sidecar serves its own registry.
func TestMetricsScrape(t *testing.T) {
	t.Run("gateway", func(t *testing.T) {
		instrumenttest.AssertScrapes(t, metrics.Handler())
	})
	t.Run("node", func(t *testing.T) {
		instrumenttest.AssertScrapes(t, node.NewMetrics().Handler())
	})
}
