// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"
)

// TestMetricsScrape scrapes what the manager serves at /metrics:
// controller-runtime's registry, which metrics.Handler serves unchanged,
// holding every metric this command's packages register when linked.
func TestMetricsScrape(t *testing.T) {
	instrumenttest.AssertScrapes(t, metrics.Handler())
}
