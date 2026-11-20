// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/diag"
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
	capabilityReady = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_worker_capability_ready",
		Help: "1 when the capability is available on this node, 0 with the reason it is not.",
	}, []string{labelCapability, labels.Reason})
	destinationsGauge = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_worker_destinations",
		Help: "Destinations of live claims, by the capability that delivers them, locality (local, fabric, " +
			"or unresolved) and reason: AsExpected when ready, otherwise the first reason it is not.",
	}, []string{labelCapability, labelLocality, labels.Reason})
	localHooksGauge = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_worker_local_hooks",
		Help: "Programmed Local destinations by hook coverage: covered, missing (a Local program or the " +
			"dispatcher's public slot is off its hook) or unsupported (a hook in a mode the handoff cannot use).",
	}, []string{labelState})
	scopesGauge = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_worker_scopes",
		Help: "VPC scopes Worker tracks, by state: owned by this Worker, owned elsewhere, transitioning, " +
			"pending (a commit must be a snapshot), resyncing after start and repairing after a failed commit. " +
			"A scope can count in several states.",
	}, []string{labelState})
	driftRepairsTotal = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_worker_drift_repairs_total",
		Help: "Repairs of host state that changed under Worker while the scope's desired state did not, " +
			"such as a Local filter another process removed, by module.",
	}, []string{labelModule})
	claimsBehindGauge = metrics.NewGauge(prometheus.GaugeOpts{
		Name: "galactic_worker_claims_behind",
		Help: "Live claims whose status describes an older generation than the accepted one.",
	})
)

// capabilitySeries are the capability_ready label pairs last set.
var capabilitySeries struct {
	sync.Mutex
	set map[[2]string]bool
}

// Label names with no instrumentation constant.
const (
	labelCapability = "capability"
	labelLocality   = "locality"
	labelState      = "state"
	labelModule     = "module"
)

// Hook coverage and scope states.
const (
	hookCovered     = "covered"
	hookMissing     = "missing"
	hookUnsupported = "unsupported"

	scopeOwned         = "owned"
	scopeElsewhere     = "owned_elsewhere"
	scopeTransitioning = "transitioning"
	scopePending       = "pending"
	scopeResyncing     = "resyncing"
	scopeRepair        = "repair"

	localityUnresolved = "unresolved"
	// localityLocal and localityFabric are modeName's values, which are
	// also the module names.
	localityLocal  = "local"
	localityFabric = "fabric"
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
	for _, m := range []string{localityLocal, localityFabric} {
		driftRepairsTotal.WithLabelValues(m)
	}
	for _, h := range []string{hookCovered, hookMissing, hookUnsupported} {
		localHooksGauge.WithLabelValues(h)
	}
	for _, st := range []string{scopeOwned, scopeElsewhere, scopeTransitioning, scopePending, scopeResyncing,
		scopeRepair} {
		scopesGauge.WithLabelValues(st)
	}
}

// updateDiagnosticGauges sets the diagnostic gauges from a snapshot.
func updateDiagnosticGauges(s diag.Snapshot) {
	// Each capability has one series, whose reason label changes with it:
	// set the current ones, then drop the series of earlier reasons, so a
	// scrape never sees a capability without one.
	now := map[[2]string]bool{}
	for _, c := range s.Capabilities {
		v := 0.0
		reason := c.Reason
		if c.Available {
			v, reason = 1, workerv1alpha1.ReasonAsExpected
		}
		capabilityReady.WithLabelValues(c.Name, reason).Set(v)
		now[[2]string{c.Name, reason}] = true
	}
	capabilitySeries.Lock()
	for k := range capabilitySeries.set {
		if !now[k] {
			capabilityReady.DeleteLabelValues(k[0], k[1])
		}
	}
	capabilitySeries.set = now
	capabilitySeries.Unlock()

	type destKey struct{ capability, locality, reason string }
	dests := map[destKey]int{}
	hooks := map[string]int{hookCovered: 0, hookMissing: 0, hookUnsupported: 0}
	scopes := map[string]int{scopeOwned: 0, scopeElsewhere: 0, scopeTransitioning: 0, scopePending: 0,
		scopeResyncing: 0, scopeRepair: 0}
	behind := 0
	for _, sc := range s.Scopes {
		switch {
		case sc.Fence.Owner == s.Owner:
			scopes[scopeOwned]++
		case sc.Fence.Owner != "":
			scopes[scopeElsewhere]++
		}
		for st, on := range map[string]bool{scopeTransitioning: sc.Fence.Transitioning,
			scopePending: sc.Fence.Pending, scopeResyncing: sc.Resyncing, scopeRepair: sc.Repair} {
			if on {
				scopes[st]++
			}
		}
		for _, c := range sc.Claims {
			if c.ObservedGeneration < c.Generation {
				behind++
			}
			for _, d := range c.Destinations {
				k := destKey{d.Capability, d.Locality, d.Reason}
				if k.locality == "" {
					k.locality = localityUnresolved
				}
				if d.Ready {
					k.reason = workerv1alpha1.ReasonAsExpected
				}
				dests[k]++
				if d.Locality != localityLocal || !d.Programmed {
					continue
				}
				switch d.Reason {
				case workerv1alpha1.ReasonHandoffHookMissing, workerv1alpha1.ReasonDispatcherSlotUnclaimed:
					hooks[hookMissing]++
				case workerv1alpha1.ReasonHookUnsupported:
					hooks[hookUnsupported]++
				default:
					hooks[hookCovered]++
				}
			}
		}
	}
	destinationsGauge.Reset()
	for k, n := range dests {
		destinationsGauge.WithLabelValues(k.capability, k.locality, k.reason).Set(float64(n))
	}
	for h, n := range hooks {
		localHooksGauge.WithLabelValues(h).Set(float64(n))
	}
	for st, n := range scopes {
		scopesGauge.WithLabelValues(st).Set(float64(n))
	}
	claimsBehindGauge.Set(float64(behind))
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
