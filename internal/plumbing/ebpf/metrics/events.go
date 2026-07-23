// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// EventCounters are ordinary Prometheus counters for BPF program
// load/reload events and failures (package doc comment). Unlike Collector
// (map state read live at scrape time), these are discrete events observed
// exactly once, at the moment they happen, via
// internal/plumbing/ebpf/attach's LoadHook/AttachHook callbacks.
type EventCounters struct {
	load   *prometheus.CounterVec
	attach *prometheus.CounterVec
}

// NewEventCounters builds a fresh, unregistered set of event counters.
func NewEventCounters() *EventCounters {
	return &EventCounters{
		load: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "datapath",
			Name:      "load_events_total",
			Help:      "BPF program load attempts (internal/plumbing/ebpf/attach.Load), by result.",
		}, []string{"result"}),
		attach: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "datapath",
			Name:      "attach_events_total",
			Help: "TC-BPF ingress filter attach/detach attempts -- both the initial Start and every " +
				"subsequent netlink-driven re-attachment ('reload') Watch performs -- by interface, action, and result.",
		}, []string{"interface", "action", "result"}),
	}
}

// MustRegister registers every counter this type owns against reg. Panics
// on a duplicate registration, matching prometheus.Registerer.MustRegister's
// own documented behavior -- callers only ever do this once per process, at
// startup (see Metrics.New).
func (c *EventCounters) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(c.load, c.attach)
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
