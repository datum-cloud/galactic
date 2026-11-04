// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cell

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestReadiness(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const gen = 3
	at := func(age time.Duration) *metav1.Time { t := metav1.NewTime(now.Add(-age)); return &t }
	dir := func(state galacticv1alpha1.AppliedState, g int64) *galacticv1alpha1.AppliedPolicy {
		return &galacticv1alpha1.AppliedPolicy{State: state, ObservedGeneration: g}
	}
	node := func(name string, mode galacticv1alpha1.EnforcementMode) galacticv1alpha1.NodeBindingStatus {
		return galacticv1alpha1.NodeBindingStatus{
			Node: name, Ingress: dir(galacticv1alpha1.StateApplied, gen), Egress: dir(galacticv1alpha1.StateApplied, gen),
			Mode: mode, HeartbeatTime: at(time.Minute),
		}
	}
	with := func(n galacticv1alpha1.NodeBindingStatus,
		f func(*galacticv1alpha1.NodeBindingStatus),
	) galacticv1alpha1.NodeBindingStatus {
		f(&n)
		return n
	}

	for _, tc := range []struct {
		name                       string
		nodes                      []galacticv1alpha1.NodeBindingStatus
		installed, enforcing       metav1.ConditionStatus
		installReason, enforReason string
		wantNext                   bool
	}{
		{"no report yet from the current node", nil, metav1.ConditionFalse, metav1.ConditionFalse,
			galacticv1alpha1.ReasonPending, galacticv1alpha1.ReasonPending, false},
		{"enforce", []galacticv1alpha1.NodeBindingStatus{node("a", galacticv1alpha1.ModeEnforce)},
			metav1.ConditionTrue, metav1.ConditionTrue, galacticv1alpha1.ReasonInstalled,
			galacticv1alpha1.ReasonEnforcing, true},
		{"audit is installed but not enforcing", []galacticv1alpha1.NodeBindingStatus{node("a", galacticv1alpha1.ModeAudit)},
			metav1.ConditionTrue, metav1.ConditionFalse, galacticv1alpha1.ReasonInstalled, "Audit", true},
		{"off is installed but not enforcing", []galacticv1alpha1.NodeBindingStatus{node("a", galacticv1alpha1.ModeOff)},
			metav1.ConditionTrue, metav1.ConditionFalse, galacticv1alpha1.ReasonInstalled, "Off", true},
		{"unsupported kernel", []galacticv1alpha1.NodeBindingStatus{node("a", galacticv1alpha1.ModeUnsupported)},
			metav1.ConditionTrue, metav1.ConditionFalse, galacticv1alpha1.ReasonInstalled, "Unsupported", true},
		{"node predating mode", []galacticv1alpha1.NodeBindingStatus{node("a", "")},
			metav1.ConditionTrue, metav1.ConditionFalse, galacticv1alpha1.ReasonInstalled, "Unknown", true},
		{"a stale entry left by the previous node is ignored", []galacticv1alpha1.NodeBindingStatus{
			node("a", galacticv1alpha1.ModeEnforce),
			with(node("b", galacticv1alpha1.ModeAudit),
				func(n *galacticv1alpha1.NodeBindingStatus) { n.HeartbeatTime = at(time.Hour) })},
			metav1.ConditionTrue, metav1.ConditionTrue, galacticv1alpha1.ReasonInstalled,
			galacticv1alpha1.ReasonEnforcing, true},
		{"only another node reports", []galacticv1alpha1.NodeBindingStatus{node("b", galacticv1alpha1.ModeEnforce)},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonPending,
			galacticv1alpha1.ReasonPending, false},
		{"pending direction", []galacticv1alpha1.NodeBindingStatus{with(node("a", galacticv1alpha1.ModeEnforce),
			func(n *galacticv1alpha1.NodeBindingStatus) { n.Egress = dir(galacticv1alpha1.StatePending, gen) })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonPending, galacticv1alpha1.ReasonPending, true},
		{"missing direction", []galacticv1alpha1.NodeBindingStatus{with(node("a", galacticv1alpha1.ModeEnforce),
			func(n *galacticv1alpha1.NodeBindingStatus) { n.Ingress = nil })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonPending, galacticv1alpha1.ReasonPending, true},
		{"older generation", []galacticv1alpha1.NodeBindingStatus{with(node("a", galacticv1alpha1.ModeEnforce),
			func(n *galacticv1alpha1.NodeBindingStatus) { n.Ingress = dir(galacticv1alpha1.StateApplied, gen-1) })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonPending, galacticv1alpha1.ReasonPending, true},
		{"failed installation", []galacticv1alpha1.NodeBindingStatus{
			with(node("a", galacticv1alpha1.ModeEnforce),
				func(n *galacticv1alpha1.NodeBindingStatus) { n.Ingress = dir(galacticv1alpha1.StateFailed, gen) })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonFailed, galacticv1alpha1.ReasonFailed, true},
		{"stale enforcing node", []galacticv1alpha1.NodeBindingStatus{with(node("a", galacticv1alpha1.ModeEnforce),
			func(n *galacticv1alpha1.NodeBindingStatus) { n.HeartbeatTime = at(25 * time.Minute) })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonStale, galacticv1alpha1.ReasonStale, false},
		{"no heartbeat", []galacticv1alpha1.NodeBindingStatus{with(node("a", galacticv1alpha1.ModeEnforce),
			func(n *galacticv1alpha1.NodeBindingStatus) { n.HeartbeatTime = nil })},
			metav1.ConditionFalse, metav1.ConditionFalse, galacticv1alpha1.ReasonStale, galacticv1alpha1.ReasonStale, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &galacticv1alpha1.TrafficPolicyBinding{}
			b.Generation = gen
			b.Status.Nodes = tc.nodes
			installed, enforcing, next := Readiness(b, "a", now)
			if installed.Status != tc.installed || installed.Reason != tc.installReason {
				t.Errorf("Installed = %s/%s (%s), want %s/%s", installed.Status, installed.Reason, installed.Message,
					tc.installed, tc.installReason)
			}
			if enforcing.Status != tc.enforcing || enforcing.Reason != tc.enforReason {
				t.Errorf("Enforcing = %s/%s (%s), want %s/%s", enforcing.Status, enforcing.Reason, enforcing.Message,
					tc.enforcing, tc.enforReason)
			}
			if installed.ObservedGeneration != gen || enforcing.ObservedGeneration != gen {
				t.Errorf("observedGeneration = %d/%d, want %d", installed.ObservedGeneration,
					enforcing.ObservedGeneration, gen)
			}
			if (next > 0) != tc.wantNext {
				t.Errorf("next = %s, want a requeue: %v", next, tc.wantNext)
			}

			// A restarted controller derives the same conditions.
			again, againEnforcing, _ := Readiness(b.DeepCopy(), "a", now)
			if again != installed || againEnforcing != enforcing {
				t.Error("Readiness is not deterministic")
			}
		})
	}
}

func TestReadinessWithoutANode(t *testing.T) {
	b := &galacticv1alpha1.TrafficPolicyBinding{}
	installed, enforcing, next := Readiness(b, "", time.Now())
	if installed.Reason != galacticv1alpha1.ReasonNoNodes || enforcing.Reason != galacticv1alpha1.ReasonNoNodes ||
		installed.Status != metav1.ConditionFalse || next != 0 {
		t.Fatalf("Installed %s/%s, Enforcing %s, next %s; want False/NoNodes", installed.Status, installed.Reason,
			enforcing.Reason, next)
	}
}

func TestReadinessGoesStaleWithoutEvents(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	hb := metav1.NewTime(now.Add(-20 * time.Minute))
	applied := &galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, ObservedGeneration: 1}
	b := &galacticv1alpha1.TrafficPolicyBinding{}
	b.Generation = 1
	b.Status.Nodes = []galacticv1alpha1.NodeBindingStatus{{
		Node: "a", Ingress: applied, Egress: applied, Mode: galacticv1alpha1.ModeEnforce, HeartbeatTime: &hb,
	}}
	_, enforcing, next := Readiness(b, "a", now)
	if enforcing.Status != metav1.ConditionTrue || next != 5*time.Minute {
		t.Fatalf("Enforcing = %s, next = %s; want True and 5m", enforcing.Status, next)
	}
	_, enforcing, _ = Readiness(b, "a", now.Add(next))
	if enforcing.Status != metav1.ConditionFalse || enforcing.Reason != galacticv1alpha1.ReasonStale {
		t.Fatalf("at the requeue, Enforcing = %s/%s, want False/Stale", enforcing.Status, enforcing.Reason)
	}
}
