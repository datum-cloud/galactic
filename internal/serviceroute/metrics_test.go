// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUnresolvedNextHopsGauge(t *testing.T) {
	metrics := NewMetrics()
	metrics.SetUnresolvedNextHops(2)
	if got := testutil.ToFloat64(metrics.unresolved); got != 2 {
		t.Fatalf("unresolved_next_hops = %v, want 2", got)
	}
}
