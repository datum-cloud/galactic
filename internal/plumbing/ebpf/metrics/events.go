// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	instmetrics "go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// EventCounters are ordinary Prometheus counters for program load and attach
// events. Unlike the collector, which reads map state live at scrape time, these
// are discrete events observed exactly once, when they happen, through the
// attach package's hooks.
type EventCounters struct {
	load   *prometheus.CounterVec
	attach *prometheus.CounterVec
}

// NewEventCounters creates the event counters on the instrumentation
// library's registry.
func NewEventCounters() *EventCounters {
	return &EventCounters{
		load: instmetrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "datapath",
			Name:      "load_events_total",
			Help:      "BPF program load attempts (internal/plumbing/ebpf/attach.Load), by result.",
		}, []string{labelResult}),
		attach: instmetrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "datapath",
			Name:      "attach_events_total",
			Help: "TC-BPF ingress filter attach/detach attempts -- both the initial Start and every " +
				"subsequent netlink-driven re-attachment ('reload') Watch performs -- by interface, action, and result.",
		}, []string{"interface", "action", labelResult}),
	}
}

// Hooks returns the attach.Hooks wiring these counters. Pass the result to
// attach.SetHooks once at process startup, before starting the datapath.
func (c *EventCounters) Hooks() attach.Hooks {
	return attach.Hooks{
		OnLoad: func(err error) {
			c.load.WithLabelValues(result(err)).Inc()
		},
		OnAttach: func(iface string, err error) {
			c.attach.WithLabelValues(iface, "attach", result(err)).Inc()
		},
		OnDetach: func(iface string, err error) {
			c.attach.WithLabelValues(iface, "detach", result(err)).Inc()
		},
	}
}

func result(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}
