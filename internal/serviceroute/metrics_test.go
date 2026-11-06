// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUnresolvedNextHopsGauge(t *testing.T) {
	metrics := NewMetrics()
	metrics.SetUnresolvedNextHops(2)
	if got := testutil.ToFloat64(metrics.unresolved); got != 2 {
		t.Fatalf("unresolved_next_hops = %v, want 2", got)
	}

	metrics.ObserveReconcile("", time.Millisecond)
	metrics.ObserveReconcile("dependency_not_ready", time.Millisecond)
	metrics.ObserveReconcile("dependency_not_ready", time.Millisecond)
	for _, tc := range []struct {
		result, reason string
		want           float64
	}{
		{ReconcileResultSuccess, ReconcileReasonNone, 1},
		{ReconcileResultError, "dependency_not_ready", 2},
		{ReconcileResultError, ReconcileReasonNone, 0},
	} {
		if got := testutil.ToFloat64(metrics.reconciliations.WithLabelValues(tc.result, tc.reason)); got != tc.want {
			t.Errorf("reconciliations_total{result=%q,reason=%q} = %v, want %v", tc.result, tc.reason, got, tc.want)
		}
	}
}
