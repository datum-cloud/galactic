// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLeaseMetricsObserve(t *testing.T) {
	m := NewLeaseMetrics("test")
	reg := prometheus.NewPedanticRegistry()
	if err := m.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	renewedAt := time.Unix(1_000_000, 0)
	m.now = func() time.Time { return renewedAt }

	var passed []error
	onRenew := m.Observe(SlotNAT, func(err error) { passed = append(passed, err) })

	if got := testutil.ToFloat64(m.renewals.WithLabelValues("nat", leaseResultError)); got != 0 {
		t.Errorf("error renewals before any renewal = %v, want a zero series", got)
	}

	onRenew(nil)
	onRenew(nil)
	boom := errors.New("map write failed")
	onRenew(boom)

	if got := testutil.ToFloat64(m.renewals.WithLabelValues("nat", leaseResultSuccess)); got != 2 {
		t.Errorf("success renewals = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.renewals.WithLabelValues("nat", leaseResultError)); got != 1 {
		t.Errorf("error renewals = %v, want 1", got)
	}
	wantExpiry := float64(renewedAt.Add(LeaseTTL).Unix())
	if got := testutil.ToFloat64(m.expiry.WithLabelValues("nat")); got != wantExpiry {
		t.Errorf("expiry = %v, want %v: a failed renewal must leave the last expiry in place", got, wantExpiry)
	}
	if len(passed) != 1 || !errors.Is(passed[0], boom) {
		t.Errorf("onError got %v, want only the failure", passed)
	}
}

func TestLeaseMetricsNilPassesFailuresOn(t *testing.T) {
	var m *LeaseMetrics
	var passed []error
	onRenew := m.Observe(SlotGatewayLB, func(err error) { passed = append(passed, err) })
	onRenew(nil)
	onRenew(errors.New("boom"))
	if len(passed) != 1 {
		t.Errorf("onError called %d times, want once for the failure", len(passed))
	}
}

func TestSlotString(t *testing.T) {
	for slot, want := range map[Slot]string{
		SlotGatewayLB: "gateway_lb", SlotGatewayReturn: "gateway_return", SlotNAT: "nat", Slot(9): "slot_9",
	} {
		if got := slot.String(); got != want {
			t.Errorf("Slot(%d).String() = %q, want %q", slot, got, want)
		}
	}
}
