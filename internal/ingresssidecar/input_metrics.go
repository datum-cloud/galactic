// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// EndpointSlice input states and evaluation results. A selected slice is
// ready once it parses into a route, waiting_sid until its node's SID
// annotation appears, and invalid when it is selected but cannot be parsed;
// not_selected is an evaluation of a slice without the tenant label.
const (
	InputReady       = "ready"
	InputWaitingSID  = "waiting_sid"
	InputInvalid     = "invalid"
	InputNotSelected = "not_selected"
)

// Where an evaluation came from.
const (
	SourceSeed  = "seed"
	SourceWatch = "watch"
)

var (
	inputStates  = []string{InputReady, InputWaitingSID, InputInvalid}
	inputResults = []string{InputReady, InputWaitingSID, InputInvalid, InputNotSelected}
	inputSources = []string{SourceSeed, SourceWatch}
)

// classifySlice evaluates slice the way BuildDesiredRoute does, returning its
// input state, or InputNotSelected, alongside BuildDesiredRoute's result.
func classifySlice(slice *discoveryv1.EndpointSlice) (string, *DesiredRoute, error) {
	if !IsSelected(slice) {
		return InputNotSelected, nil, nil
	}
	desired, err := BuildDesiredRoute(slice)
	switch {
	case err != nil:
		return InputInvalid, nil, err
	case desired == nil:
		return InputWaitingSID, nil, nil
	}
	return InputReady, desired, nil
}

// InputMetrics reports the EndpointSlices this sidecar selects by input state,
// and every evaluation of one, so a slice that is waiting for its SID or
// cannot be parsed is visible even though it has no route. It holds one entry
// per selected slice it has seen, removed when the reconciler finds the slice
// deleted or no longer selected, and nothing else. Every method is safe on a
// nil receiver.
//
// The startup seed and the watch evaluate slices concurrently. A watch
// observation always wins: once the watch has seen a key during a seed, the
// seed's result for that key, taken from a list that may be older, is
// counted as an evaluation but not recorded as the key's state, so it can
// neither overwrite a newer update nor bring back a deleted slice. The state
// is eventually consistent rather than strictly newest: a watch observation
// read from a lagging cache can briefly hold older data than the seed's list,
// until the next event for that slice. The seed still applies its route for
// such a key, as it always has; only these metrics prefer the watch.
type InputMetrics struct {
	slices      *prometheus.GaugeVec
	evaluations *prometheus.CounterVec

	mu      sync.Mutex
	state   map[string]string
	counts  map[string]int
	seeding bool
	watched map[string]struct{}
}

// NewInputMetrics builds unregistered input metrics with no slices seen.
func NewInputMetrics() *InputMetrics {
	m := &InputMetrics{
		slices: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "endpoint_slices",
			Help: "Selected EndpointSlices, by state: ready (parses into a route), waiting_sid (no SID " +
				"annotation yet) or invalid (cannot be parsed; any route it had is kept).",
		}, []string{"state"}),
		evaluations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "endpoint_slice_evaluations_total",
			Help: "EndpointSlice evaluations, by source (seed, watch) and result (ready, waiting_sid, " +
				"invalid, not_selected). Counts evaluations, including a reconcile retried after its route " +
				"failed to apply, not distinct slices.",
		}, []string{"source", resultLabel}),
		state:  map[string]string{},
		counts: map[string]int{},
	}
	for _, s := range inputStates {
		m.slices.WithLabelValues(s)
	}
	for _, src := range inputSources {
		for _, r := range inputResults {
			m.evaluations.WithLabelValues(src, r)
		}
	}
	return m
}

// MustRegister registers every input metric against reg, panicking on a
// duplicate. Call it once per process.
func (m *InputMetrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.slices, m.evaluations)
}

// beginSeed marks the start of a seed attempt. Call it before the seed lists
// slices, so any watch observation from then on takes precedence.
func (m *InputMetrics) beginSeed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seeding = true
	m.watched = map[string]struct{}{}
}

// endSeed marks the end of a seed attempt.
func (m *InputMetrics) endSeed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seeding = false
	m.watched = nil
}

// observeSeed records the seed's evaluation of key as result.
func (m *InputMetrics) observeSeed(key, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evaluations.WithLabelValues(SourceSeed, result).Inc()
	if _, ok := m.watched[key]; ok {
		return // the watch has seen it since the seed started
	}
	m.setLocked(key, result)
}

// observeWatch records the watch's evaluation of key as result.
func (m *InputMetrics) observeWatch(key, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evaluations.WithLabelValues(SourceWatch, result).Inc()
	m.markWatchedLocked(key)
	m.setLocked(key, result)
}

// forget removes key, whose slice the watch found deleted.
func (m *InputMetrics) forget(key string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markWatchedLocked(key)
	m.setLocked(key, InputNotSelected)
}

func (m *InputMetrics) markWatchedLocked(key string) {
	if m.seeding {
		m.watched[key] = struct{}{}
	}
}

// setLocked makes result key's state, removing key when it is not a
// selected slice, and publishes the changed counts.
func (m *InputMetrics) setLocked(key, result string) {
	if old, ok := m.state[key]; ok {
		if old == result {
			return
		}
		m.counts[old]--
		m.slices.WithLabelValues(old).Set(float64(m.counts[old]))
		delete(m.state, key)
	}
	if result == InputNotSelected {
		return
	}
	m.state[key] = result
	m.counts[result]++
	m.slices.WithLabelValues(result).Set(float64(m.counts[result]))
}
