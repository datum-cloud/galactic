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

func TestPrometheusTelemetryEmitter_RuleAppliedRecordsPrimary(t *testing.T) {
	e := NewPrometheusTelemetryEmitter()
	e.RuleApplied(context.Background(), DesiredRule{Key: testRuleKeyR1, IsPrimary: true})
	e.RuleApplied(context.Background(), DesiredRule{Key: testRuleKeyR2, IsPrimary: false})

	metrics := collect(t, e.rulePrimary)
	if len(metrics) != 2 {
		t.Fatalf("got %d metrics, want 2", len(metrics))
	}
	for _, m := range metrics {
		switch labelValue(m, "rule") {
		case testRuleKeyR1:
			if m.GetGauge().GetValue() != 1 {
				t.Errorf("ns/r1 is_primary = %v, want 1", m.GetGauge().GetValue())
			}
		case testRuleKeyR2:
			if m.GetGauge().GetValue() != 0 {
				t.Errorf("ns/r2 is_primary = %v, want 0", m.GetGauge().GetValue())
			}
		default:
			t.Errorf("unexpected rule label %q", labelValue(m, "rule"))
		}
	}
}

func TestPrometheusTelemetryEmitter_RuleRemovedDeletesSeries(t *testing.T) {
	e := NewPrometheusTelemetryEmitter()
	e.RuleApplied(context.Background(), DesiredRule{Key: testRuleKeyR1, IsPrimary: true})
	e.RuleRemoved(context.Background(), testRuleKeyR1)

	if metrics := collect(t, e.rulePrimary); len(metrics) != 0 {
		t.Errorf("got %d metrics after RuleRemoved, want 0", len(metrics))
	}
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
