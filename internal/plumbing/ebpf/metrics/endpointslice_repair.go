// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	instmetrics "go.miloapis.com/instrumentation/metrics"
)

// endpointSliceRepairSubsystem names galactic-cni's EndpointSlice repair
// series.
const endpointSliceRepairSubsystem = "endpointslice_repair"

// EndpointSliceRepair reports galactic-cni's per-pod EndpointSlice repair: how
// many missing slices it recreated, each one a pod whose HTTP ingress was down
// until then, how many Running pods are left on a superseded VPC attachment,
// and how many passes failed. All methods are safe on a nil
// receiver, which tests use.
type EndpointSliceRepair struct {
	restored   prometheus.Counter
	superseded prometheus.Gauge
	failures   prometheus.Counter
}

// NewEndpointSliceRepair creates the counters on the instrumentation
// library's registry.
func NewEndpointSliceRepair() *EndpointSliceRepair {
	r := &EndpointSliceRepair{
		restored: instmetrics.NewCounter(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: endpointSliceRepairSubsystem,
			Name:      "restored_total",
			Help:      "Per-pod EndpointSlices the repair pass recreated after finding them missing.",
		}),
		superseded: instmetrics.NewGauge(prometheus.GaugeOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: endpointSliceRepairSubsystem,
			Name:      "superseded_pods",
			Help: "Running pods on this node whose NetworkAttachmentDefinition names a VPC attachment " +
				"this node holds no host link for, as of the last pass that examined every pod. " +
				"That attachment stays unprogrammed until the pod is recreated.",
		}),
		failures: instmetrics.NewCounter(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: endpointSliceRepairSubsystem,
			Name:      "failures_total",
			Help:      "EndpointSlice repair passes that could not list this node's pods or write a slice.",
		}),
	}
	return r
}

// Pass records one repair pass that recreated restored slices and found
// superseded pods. complete says the pass examined every pod, so superseded
// is a full count; otherwise the gauge keeps its last value. failed counts a
// pass that returned an error.
func (r *EndpointSliceRepair) Pass(restored, superseded int, complete, failed bool) {
	if r == nil {
		return
	}
	r.restored.Add(float64(restored))
	if complete {
		r.superseded.Set(float64(superseded))
	}
	if failed {
		r.failures.Inc()
	}
}
