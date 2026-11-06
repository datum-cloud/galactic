// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.miloapis.com/instrumentation/labels"
)

func TestUnresolvedNextHopsGauge(t *testing.T) {
	metrics := NewMetrics()
	metrics.SetUnresolvedNextHops(2)
	if got := testutil.ToFloat64(metrics.unresolved); got != 2 {
		t.Fatalf("unresolved_next_hops = %v, want 2", got)
	}
}

func TestObserveReconcile(t *testing.T) {
	metrics := &Metrics{
		reconciliations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "reconciliations_total"},
			[]string{reconcileResultLabel, labels.Reason}),
		reconcileTime: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "reconcile_duration_seconds"}),
	}
	metrics.ObserveReconcile("", time.Millisecond)
	metrics.ObserveReconcile(ReconcileDependencyNotReady, time.Millisecond)
	metrics.ObserveReconcile(ReconcileDependencyNotReady, time.Millisecond)
	metrics.ObserveReconcile("some error text", time.Millisecond)
	metrics.ObserveReconcile(ReconcileReasonNone, time.Millisecond)
	for _, tc := range []struct {
		result, reason string
		want           float64
	}{
		{ReconcileResultSuccess, ReconcileReasonNone, 1},
		{ReconcileResultError, ReconcileDependencyNotReady, 2},
		{ReconcileResultError, ReconcileOther, 2},
		{ReconcileResultError, ReconcileReasonNone, 0},
	} {
		if got := testutil.ToFloat64(metrics.reconciliations.WithLabelValues(tc.result, tc.reason)); got != tc.want {
			t.Errorf("reconciliations_total{result=%q,reason=%q} = %v, want %v", tc.result, tc.reason, got, tc.want)
		}
	}
}

func TestReconcileReasonsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/observability/routing.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range ReconcileReasons {
		if !strings.Contains(string(doc), "`"+reason+"`") {
			t.Errorf("reason %q is missing from docs/observability/routing.md", reason)
		}
	}
}
