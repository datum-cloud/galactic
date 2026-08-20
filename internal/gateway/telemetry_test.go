// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// collect runs c's Collect method to completion and returns every emitted
// metric decoded to its protobuf form -- same convention as
// internal/plumbing/ebpf/metrics/collector_test.go's identical helper,
// duplicated rather than imported (unexported, different package).
func collect(t *testing.T, c prometheus.Collector) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []*dto.Metric
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		out = append(out, &pb)
	}
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

// TestPrometheusTelemetryEmitter_RuleAppliedAndRemovedDoNotPanic covers the
// no-op RuleApplied/RuleRemoved hooks -- DSR's anycast model leaves no
// per-rule placement fact to record (see telemetry.go's doc comment), so
// these are only exercised for interface conformance and to guard against
// a future accidental panic.
func TestPrometheusTelemetryEmitter_RuleAppliedAndRemovedDoNotPanic(t *testing.T) {
	e := NewPrometheusTelemetryEmitter()
	e.RuleApplied(context.Background(), DesiredRule{Key: testRuleKeyR1})
	e.RuleRemoved(context.Background(), testRuleKeyR1)
}

func TestPrometheusTelemetryEmitter_DropObservedIncrementsCounter(t *testing.T) {
	e := NewPrometheusTelemetryEmitter()
	e.DropObserved(context.Background(), testRuleKeyR1, "quota_exceeded")
	e.DropObserved(context.Background(), testRuleKeyR1, "quota_exceeded")

	metrics := collect(t, e.controlPlaneDrops)
	if len(metrics) != 1 {
		t.Fatalf("got %d metrics, want 1", len(metrics))
	}
	m := metrics[0]
	if labelValue(m, "rule") != testRuleKeyR1 || labelValue(m, "reason") != "quota_exceeded" {
		t.Errorf("labels = rule=%q reason=%q, want rule=ns/r1 reason=quota_exceeded",
			labelValue(m, "rule"), labelValue(m, "reason"))
	}
	if m.GetCounter().GetValue() != 2 {
		t.Errorf("counter value = %v, want 2", m.GetCounter().GetValue())
	}
}

func TestPrometheusTelemetryEmitter_MustRegisterIsIdempotentPerInstance(t *testing.T) {
	e := NewPrometheusTelemetryEmitter()
	reg := prometheus.NewRegistry()
	e.MustRegister(reg) // must not panic
}
