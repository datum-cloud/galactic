// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// EndpointSliceRepair reports galactic-cni's per-pod EndpointSlice repair: how
// many missing slices it recreated, each one a pod whose HTTP ingress was down
// until then, and how many passes failed. All methods are safe on a nil
// receiver, which tests use.
type EndpointSliceRepair struct {
	restored prometheus.Counter
	failures prometheus.Counter
}

// NewEndpointSliceRepair builds an EndpointSliceRepair registered in reg.
func NewEndpointSliceRepair(reg prometheus.Registerer) *EndpointSliceRepair {
	r := &EndpointSliceRepair{
		restored: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "galactic",
			Subsystem: "endpointslice_repair",
			Name:      "restored_total",
			Help:      "Per-pod EndpointSlices the repair pass recreated after finding them missing.",
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "galactic",
			Subsystem: "endpointslice_repair",
			Name:      "failures_total",
			Help:      "EndpointSlice repair passes that could not list this node's pods or write a slice.",
		}),
	}
	reg.MustRegister(r.restored, r.failures)
	return r
}

// Pass records one repair pass that recreated restored slices and failed when
// failed is set.
func (r *EndpointSliceRepair) Pass(restored int, failed bool) {
	if r == nil {
		return
	}
	r.restored.Add(float64(restored))
	if failed {
		r.failures.Inc()
	}
}
