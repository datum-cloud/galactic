// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// Metrics bundles this milestone's Prometheus instrumentation into one
// private registry (deliberately not prometheus.DefaultRegisterer -- a
// private registry keeps this package's metrics free of global-registration
// panics if a test, or a future caller, constructs more than one Metrics in
// the same process) plus an http.Handler for internal/installer.Run to
// serve, so that package doesn't need to import prometheus/promhttp
// directly.
type Metrics struct {
	Registry *prometheus.Registry
	Events   *EventCounters
}

// New builds a Metrics with EventCounters already registered. Call
// RegisterDatapathCollector once the eBPF uSID datapath has actually been
// loaded to also expose live vrf_table/locator_table/drop_reasons state.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	events := NewEventCounters()
	events.MustRegister(reg)
	return &Metrics{Registry: reg, Events: events}
}

// RegisterDatapathCollector registers a Collector reading live
// vrf_table/locator_table/drop_reasons state from objs at every scrape.
// Call once, after the datapath is loaded (internal/installer.Run, right
// after a successful ebpfStartFn call).
func (m *Metrics) RegisterDatapathCollector(objs *prog.UsidObjects) error {
	return m.Registry.Register(NewCollectorFromObjects(objs))
}

// Handler returns the http.Handler serving this Metrics' registry in the
// Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
