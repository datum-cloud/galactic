// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
)

// TestMetricsScrape scrapes the registry the agent serves at /metrics.
func TestMetricsScrape(t *testing.T) {
	m, _ := newMetrics()
	instrumenttest.AssertScrapes(t, m.Handler())
}
