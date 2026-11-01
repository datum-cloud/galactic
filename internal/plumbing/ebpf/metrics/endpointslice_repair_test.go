// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The superseded gauge follows every pass that examined every pod and keeps
// its value through one that did not, so a pass that saw only part of the node
// never reads as a node with nothing superseded.
func TestEndpointSliceRepairPassSupersededGauge(t *testing.T) {
	r := &EndpointSliceRepair{
		restored:   prometheus.NewCounter(prometheus.CounterOpts{Name: "restored"}),
		superseded: prometheus.NewGauge(prometheus.GaugeOpts{Name: "superseded"}),
		failures:   prometheus.NewCounter(prometheus.CounterOpts{Name: "failures"}),
	}

	r.Pass(1, 2, true, false)
	r.Pass(0, 0, false, true)
	if got := testutil.ToFloat64(r.superseded); got != 2 {
		t.Fatalf("superseded after an incomplete pass = %v, want 2 kept", got)
	}
	r.Pass(0, 0, true, true)
	if got := testutil.ToFloat64(r.superseded); got != 0 {
		t.Errorf("superseded after a complete pass = %v, want 0", got)
	}
	if got := testutil.ToFloat64(r.restored); got != 1 {
		t.Errorf("restored = %v, want 1", got)
	}
	if got := testutil.ToFloat64(r.failures); got != 2 {
		t.Errorf("failures = %v, want 2", got)
	}
}
