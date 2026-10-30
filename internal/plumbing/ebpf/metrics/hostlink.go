// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	instmetrics "go.miloapis.com/instrumentation/metrics"
)

// hostLinkSubsystem names galactic-cni's host link series.
const hostLinkSubsystem = "cni"

// HostLinks reports galactic-cni's repair of Galactic host links, the taps
// and host-side veths of attachments, that have lost their VRF master. All
// methods are safe on a nil receiver, which tests use.
type HostLinks struct {
	masterless prometheus.Gauge
	reenslaved prometheus.Counter
	failures   prometheus.Counter
}

// NewHostLinks creates the series on the instrumentation library's registry.
func NewHostLinks() *HostLinks {
	return &HostLinks{
		masterless: instmetrics.NewGauge(prometheus.GaugeOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: hostLinkSubsystem,
			Name:      "host_links_masterless",
			Help: "Galactic host links with no VRF master after the last repair pass: " +
				"their VPC's VRF is gone or re-enslaving failed, so their guest is routed outside the VPC.",
		}),
		reenslaved: instmetrics.NewCounter(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: hostLinkSubsystem,
			Name:      "host_link_reenslaved_total",
			Help:      "Galactic host links the repair pass found with no VRF master and enslaved back to their VPC's VRF.",
		}),
		failures: instmetrics.NewCounter(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace,
			Subsystem: hostLinkSubsystem,
			Name:      "host_link_repair_failures_total",
			Help: "Host link repair passes that failed. A pass that could not take the VRF lock or list links " +
				"leaves host_links_masterless at its last value.",
		}),
	}
}

// Pass records one repair pass that re-enslaved reenslaved links and left
// masterless links without a master. complete says the pass examined every
// link, so masterless is a full count; otherwise the gauge keeps its last
// value rather than reading a pass that saw nothing as a healthy node.
// failed counts a pass that returned an error.
func (h *HostLinks) Pass(reenslaved, masterless int, complete, failed bool) {
	if h == nil {
		return
	}
	h.reenslaved.Add(float64(reenslaved))
	if complete {
		h.masterless.Set(float64(masterless))
	}
	if failed {
		h.failures.Inc()
	}
}
