// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
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
//
// It also times how long each slice created after it took to reach the watch
// as ready (observeReady): projection plus watch lag, before this sidecar
// does anything with the slice.
type InputMetrics struct {
	slices       *prometheus.GaugeVec
	evaluations  *prometheus.CounterVec
	observeDelay prometheus.Histogram

	mu      sync.Mutex
	state   map[string]string
	counts  map[string]int
	seeding bool
	watched map[string]struct{}

	// clock and startedAt bound observeReady to slices created after these
	// metrics, so the watch's initial list of existing slices is not
	// mistaken for slow projection. readySeen holds the UID last timed for
	// each key.
	clock     func() time.Time
	startedAt time.Time
	readySeen map[string]string
}

// NewInputMetrics creates input metrics on the instrumentation library's
// registry with no slices seen. The registry keeps the series across calls,
// so each call starts them over.
func NewInputMetrics() *InputMetrics {
	m := &InputMetrics{
		slices: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "endpoint_slices",
			Help: "Selected EndpointSlices, by state: ready (parses into a route), waiting_sid (no SID " +
				"annotation yet) or invalid (cannot be parsed; any route it had is kept).",
		}, []string{"state"}),
		evaluations: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "endpoint_slice_evaluations_total",
			Help: "EndpointSlice evaluations, by source (seed, watch) and result (ready, waiting_sid, " +
				"invalid, not_selected). Counts evaluations, including a reconcile retried after its route " +
				"failed to apply, not distinct slices.",
		}, []string{"source", resultLabel}),
		observeDelay: newHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "endpoint_slice_observe_delay_seconds",
			Help: "Time from an EndpointSlice's creationTimestamp to this sidecar's watch first observing it " +
				"ready: projection, SID annotation and watch lag. Only slices created after the sidecar " +
				"started; second resolution, from the API server's clock.",
			Buckets: delayBuckets,
		}),
		state:     map[string]string{},
		counts:    map[string]int{},
		clock:     time.Now,
		readySeen: map[string]string{},
	}
	m.startedAt = m.clock()
	m.slices.Reset()
	m.evaluations.Reset()
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

// observeReady times the watch's first ready observation of the slice at key
// with UID uid against its creationTimestamp, created. A new UID under a key
// already timed, a slice deleted and recreated under its name, is timed
// again even when no reconcile saw it gone. Slices with no creationTimestamp,
// or created before these metrics, are skipped. creationTimestamp has whole
// seconds, so startedAt is truncated to match; a negative delay from clock
// skew counts as zero.
func (m *InputMetrics) observeReady(key, uid string, created time.Time) {
	if m == nil || created.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if seen, ok := m.readySeen[key]; ok && seen == uid {
		return
	}
	m.readySeen[key] = uid
	if created.Before(m.startedAt.Truncate(time.Second)) {
		return
	}
	m.observeDelay.Observe(max(m.clock().Sub(created), 0).Seconds())
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
		delete(m.readySeen, key) // a slice recreated under this name is timed again
		return
	}
	m.state[key] = result
	m.counts[result]++
	m.slices.WithLabelValues(result).Set(float64(m.counts[result]))
}
