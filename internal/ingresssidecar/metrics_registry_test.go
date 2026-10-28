// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import "github.com/prometheus/client_golang/prometheus"

// The collectors methods below list every collector a metrics type exports, so
// a test can register them on its own registry and read them apart from the
// rest of the process. The library's registry holds the same collectors.

func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.VRFActive, m.RouteActive, m.VRFPending, m.RoutePending,
		m.ReconcileErrs, m.ReconcileTime, m.Reapplies}
}

func (m *LifecycleMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.stageStatus, m.attempts, m.complete, m.sweepLast, m.sweepDuration,
		m.sweepInterval, m.grace, m.prunedRows}
}

func (m *ConvergenceMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.desired, m.applyPending, m.oldest, m.overdue, m.operations}
}

func (m *InputMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.slices, m.evaluations}
}

func (m *DatapathMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.checks, m.status, m.lastCompleted, m.reapplies, m.pending}
}

func (m *NodeSourceMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.check, m.repairs}
}

func (m *GatewayMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.publicationEnabled, m.addressAssignmentEnabled, m.vrfs, m.oldest, m.operations}
}
