// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

var (
	refusalsTotal = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_worker_refusals_total",
		Help: "Calls Worker refused, by contract reason. A refusal records nothing and changes no host state.",
	}, []string{labels.Reason})
	reconcilesTotal = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_worker_reconciles_total",
		Help: "Reconcile passes over a VPC scope, by outcome.",
	}, []string{labels.Outcome})
	reconcileSeconds = metrics.NewHistogram(prometheus.HistogramOpts{
		Name:    "galactic_worker_reconcile_duration_seconds",
		Help:    "Time one reconcile pass over a VPC scope took.",
		Buckets: prometheus.ExponentialBuckets(0.001, 4, 8),
	})
	claimsGauge = metrics.NewGauge(prometheus.GaugeOpts{
		Name: "galactic_worker_claims",
		Help: "Claims Worker holds, including claims being withdrawn.",
	})
	sessionsGauge = metrics.NewGauge(prometheus.GaugeOpts{
		Name: "galactic_worker_sessions",
		Help: "Live client sessions.",
	})
)

// Outcome label values.
const (
	outcomeSuccess = "success"
	outcomeError   = "error"
)

// InitMetrics creates every labelled series at zero, so a scrape shows
// them before the first event.
func InitMetrics() {
	reconcilesTotal.WithLabelValues(outcomeSuccess)
	reconcilesTotal.WithLabelValues(outcomeError)
}

func countRefusal(reason string) {
	if reason == "" {
		reason = "Unknown"
	}
	refusalsTotal.WithLabelValues(reason).Inc()
}

func observeReconcile(err error, d time.Duration) {
	outcome := outcomeSuccess
	if err != nil {
		outcome = outcomeError
	}
	reconcilesTotal.WithLabelValues(outcome).Inc()
	reconcileSeconds.Observe(d.Seconds())
}

func updateClaimGauge(w *Worker) {
	w.mu.Lock()
	n := len(w.claims)
	w.mu.Unlock()
	claimsGauge.Set(float64(n))
}

func setSessions(n int) { sessionsGauge.Set(float64(n)) }
