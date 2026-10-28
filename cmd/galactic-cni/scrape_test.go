// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"

	"go.datum.net/galactic/internal/installer"
)

// TestMetricsScrape scrapes the registry the run daemon serves at /metrics.
func TestMetricsScrape(t *testing.T) {
	instrumenttest.AssertScrapes(t, installer.NewMetrics().Handler())
}
