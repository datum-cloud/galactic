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

// Metrics bundles this datapath's Prometheus instrumentation into one private
// registry, plus an HTTP handler for the caller to serve so it needs no
// Prometheus imports of its own. A private registry rather than the global one,
// so constructing more than one in a process cannot panic on duplicate
// registration.
type Metrics struct {
	Registry *prometheus.Registry
	Events   *EventCounters
}

// New builds a Metrics with the event counters already registered. Call
// RegisterDatapathCollector once the datapath is loaded to also expose live map
// state.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	events := NewEventCounters()
	events.MustRegister(reg)
	return &Metrics{Registry: reg, Events: events}
}

// RegisterDatapathCollector registers a collector reading live map state from
// objs at every scrape. Call it once, after the datapath is loaded.
func (m *Metrics) RegisterDatapathCollector(objs *prog.UsidObjects) error {
	return m.Registry.Register(NewCollectorFromObjects(objs))
}

// Handler returns the http.Handler serving this Metrics' registry in the
// Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
