// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabric

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

// Reasons a tenant route is skipped rather than written.
const (
	// reasonTableMismatch is a route galactic-router recorded for another
	// table than the VPC's current one: a VRF that moved, or a route that
	// would cross into another VPC's table.
	reasonTableMismatch = "TableMismatch"
	// reasonOwnLocator is a route toward this node's own locator, which
	// would loop back into this node.
	reasonOwnLocator = "OwnLocator"
)

var routesSkippedTotal = metrics.NewCounterVec(prometheus.CounterOpts{
	Name: "galactic_worker_fabric_routes_skipped_total",
	Help: "Tenant routes the Fabric module did not write, by reason, counted on each reconcile pass that skipped them.",
}, []string{labels.Reason})

// InitMetrics creates the module's series at zero, so a scrape shows them
// before the first skip.
func InitMetrics() {
	for _, r := range []string{reasonTableMismatch, reasonOwnLocator} {
		routesSkippedTotal.WithLabelValues(r)
	}
}

func skipped(reason string) { routesSkippedTotal.WithLabelValues(reason).Inc() }
