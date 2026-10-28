// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
)

// String names slot as its metrics label: "gateway_lb", "gateway_return",
// "nat", or "slot_<n>" for any other.
func (s Slot) String() string {
	switch s {
	case SlotGatewayLB:
		return "gateway_lb"
	case SlotGatewayReturn:
		return "gateway_return"
	case SlotNAT:
		return "nat"
	default:
		return "slot_" + strconv.FormatUint(uint64(s), 10)
	}
}

// Lease renewal results, as the renewals counter labels them.
const (
	leaseResultSuccess = "success"
	leaseResultError   = "error"
)

// LeaseMetrics records each renewal of a slot's dispatcher lease: how many
// succeeded and failed, and when the lease last renewed expires. A slot whose
// renewals fail stops claiming packets once that time passes.
type LeaseMetrics struct {
	renewals *prometheus.CounterVec
	expiry   *prometheus.GaugeVec
	now      func() time.Time
}

// NewLeaseMetrics creates the lease series on the instrumentation library's
// registry under namespace, the caller's own metric prefix:
// <namespace>_dispatch_lease_renewals_total{slot, result} and
// <namespace>_dispatch_lease_expiry_timestamp_seconds{slot}.
func NewLeaseMetrics(namespace string) *LeaseMetrics {
	return &LeaseMetrics{
		renewals: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dispatch_lease",
			Name:      "renewals_total",
			Help: "Renewals of this process's XDP dispatcher slot leases, by slot and result. A slot whose " +
				"renewals keep failing is skipped by the dispatcher once its lease expires.",
		}, []string{"slot", "result"}),
		expiry: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "dispatch_lease",
			Name:      "expiry_timestamp_seconds",
			Help: "Unix time at which the slot's lease, as last renewed, expires: the time of the last " +
				"successful renewal plus the lease TTL.",
		}, []string{"slot"}),
		now: time.Now,
	}
}

// Observe returns the onRenew callback for Lease on slot: it records each
// renewal's result and then calls onError, which may be nil, with a failed
// renewal's error. Both of slot's result series exist from this call on, at
// zero until a renewal lands in them. A nil m records nothing and only passes
// failures on.
func (m *LeaseMetrics) Observe(slot Slot, onError func(error)) func(error) {
	if m == nil {
		return func(err error) {
			if err != nil && onError != nil {
				onError(err)
			}
		}
	}
	label := slot.String()
	success := m.renewals.WithLabelValues(label, leaseResultSuccess)
	failure := m.renewals.WithLabelValues(label, leaseResultError)
	expiry := m.expiry.WithLabelValues(label)
	return func(err error) {
		if err != nil {
			failure.Inc()
			if onError != nil {
				onError(err)
			}
			return
		}
		success.Inc()
		expiry.Set(float64(m.now().Add(LeaseTTL).UnixNano()) / 1e9)
	}
}
