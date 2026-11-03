// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/model"
)

const (
	metricsTestPeerA = "2001:db8::a"
	metricsTestPeerB = "2001:db8::b"
)

func metricsTestKey(t *testing.T) types.NamespacedName {
	t.Helper()
	key := types.NamespacedName{Namespace: "router-metrics", Name: t.Name()}
	t.Cleanup(func() { forgetRouterMetrics(key) })
	return key
}

// peerSeries collects peerEstablished and returns, by peer, the value of every
// series it exports for router.
func peerSeries(t *testing.T, router string) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		peerEstablished.Collect(ch)
		close(ch)
	}()
	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels[labelRouter] == router {
			got[labels[labelPeer]] = pb.GetGauge().GetValue()
		}
	}
	return got
}

func TestRecordRouterReadyMirrorsCondition(t *testing.T) {
	key := metricsTestKey(t)
	router := &bgpv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}

	tests := []struct {
		name string
		cond *metav1.Condition
		want float64
	}{
		{name: "no condition", want: 0},
		{
			name: "ready",
			cond: &metav1.Condition{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "RuntimeReady"},
			want: 1,
		},
		{
			name: "not ready",
			cond: &metav1.Condition{Type: ConditionReady, Status: metav1.ConditionFalse, Reason: "RuntimeNotReady"},
			want: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cond != nil {
				setRouterCondition(router, *tc.cond)
			}
			recordRouterReady(router)
			if got := testutil.ToFloat64(routerReady.WithLabelValues(key.String())); got != tc.want {
				t.Errorf("galactic_router_ready = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRecordPeerStates(t *testing.T) {
	key := metricsTestKey(t)
	router := key.String()

	recordPeerStates(key, model.RuntimeStatus{Healthy: true, Peers: []model.PeerStatus{
		{Address: metricsTestPeerA, SessionState: model.BGPPeerStateEstablished},
		{Address: metricsTestPeerB, SessionState: model.BGPPeerStateActive},
	}})
	want := map[string]float64{metricsTestPeerA: 1, metricsTestPeerB: 0}
	if got := peerSeries(t, router); !equalSeries(got, want) {
		t.Fatalf("after first status: %v, want %v", got, want)
	}

	// The runtime is down: both peers read 0 rather than disappearing.
	recordPeerStates(key, model.RuntimeStatus{Healthy: false})
	want = map[string]float64{metricsTestPeerA: 0, metricsTestPeerB: 0}
	if got := peerSeries(t, router); !equalSeries(got, want) {
		t.Fatalf("with the runtime unhealthy: %v, want %v", got, want)
	}

	// Peer B was removed from the runtime: its series goes.
	recordPeerStates(key, model.RuntimeStatus{Healthy: true, Peers: []model.PeerStatus{
		{Address: metricsTestPeerA, SessionState: model.BGPPeerStateEstablished},
	}})
	want = map[string]float64{metricsTestPeerA: 1}
	if got := peerSeries(t, router); !equalSeries(got, want) {
		t.Fatalf("after peer B was removed: %v, want %v", got, want)
	}
	forgetRouterMetrics(key)
	if got := peerSeries(t, router); len(got) != 0 {
		t.Fatalf("after the router stopped: %v, want no series", got)
	}
}

// TestReconcileRouterMetrics drives Reconcile through the paths that set and
// remove the router metrics: a healthy and an unhealthy runtime, a reconcile
// that fails before its status update, a router retargeted to another node,
// and a deleted router.
func TestReconcileRouterMetrics(t *testing.T) {
	ctx := context.Background()
	key := types.NamespacedName{Namespace: testNamespace, Name: testVRFRouterName}
	router := key.String()
	t.Cleanup(func() { forgetRouterMetrics(key) })

	rm := &fakeRuntimeManager{status: model.RuntimeStatus{Healthy: true, Peers: []model.PeerStatus{
		{Address: metricsTestPeerA, SessionState: model.BGPPeerStateEstablished},
	}}}
	r, c := newVRFStatusTestReconciler(t, rm)
	reconcileOnce := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	ready := func() float64 { return testutil.ToFloat64(routerReady.WithLabelValues(router)) }

	reconcileOnce()
	if got := ready(); got != 1 {
		t.Errorf("ready with a healthy runtime = %v, want 1", got)
	}
	if got := peerSeries(t, router); !equalSeries(got, map[string]float64{metricsTestPeerA: 1}) {
		t.Errorf("peers with a healthy runtime = %v, want peer A at 1", got)
	}

	rm.status = model.RuntimeStatus{}
	reconcileOnce()
	if got := ready(); got != 0 {
		t.Errorf("ready with the runtime down = %v, want 0", got)
	}
	if got := peerSeries(t, router); !equalSeries(got, map[string]float64{metricsTestPeerA: 0}) {
		t.Errorf("peers with the runtime down = %v, want peer A at 0", got)
	}

	// A reconcile that fails before its status update still refreshes the
	// peers.
	rm.status = model.RuntimeStatus{Healthy: true, Peers: []model.PeerStatus{
		{Address: metricsTestPeerA, SessionState: model.BGPPeerStateEstablished},
	}}
	r.Hasher = func(model.DesiredRouter) (string, error) { return "", errors.New("hash failed") }
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("Reconcile with a failing hasher returned no error")
	}
	if got := peerSeries(t, router); !equalSeries(got, map[string]float64{metricsTestPeerA: 1}) {
		t.Errorf("peers after a failed reconcile = %v, want peer A at 1", got)
	}
	r.Hasher = hash.DesiredRouter

	// Retargeted to another node: this node stops exporting the router.
	obj := &bgpv1alpha1.BGPRouter{}
	if err := c.Get(ctx, key, obj); err != nil {
		t.Fatalf("get BGPRouter: %v", err)
	}
	obj.Spec.TargetRef.Name = "metrics-other-node"
	if err := c.Update(ctx, obj); err != nil {
		t.Fatalf("retarget BGPRouter: %v", err)
	}
	reconcileOnce()
	if got := peerSeries(t, router); len(got) != 0 {
		t.Errorf("peers after the router was retargeted = %v, want none", got)
	}
	if n := testutil.CollectAndCount(routerReady); n != countReadySeriesExcept(t, router) {
		t.Errorf("galactic_router_ready still has a series for the retargeted router")
	}

	// Back on this node, then deleted.
	obj.Spec.TargetRef.Name = testVRFRouterNode
	if err := c.Update(ctx, obj); err != nil {
		t.Fatalf("retarget BGPRouter back: %v", err)
	}
	reconcileOnce()
	if got := peerSeries(t, router); len(got) != 1 {
		t.Fatalf("peers after retargeting back = %v, want peer A", got)
	}
	if err := c.Delete(ctx, obj); err != nil {
		t.Fatalf("delete BGPRouter: %v", err)
	}
	reconcileOnce()
	if got := peerSeries(t, router); len(got) != 0 {
		t.Errorf("peers after the router was deleted = %v, want none", got)
	}
	if n := testutil.CollectAndCount(routerReady); n != countReadySeriesExcept(t, router) {
		t.Errorf("galactic_router_ready still has a series for the deleted router")
	}
}

// countReadySeriesExcept returns how many galactic_router_ready series exist
// for routers other than router.
func countReadySeriesExcept(t *testing.T, router string) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		routerReady.Collect(ch)
		close(ch)
	}()
	n := 0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		other := true
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == labelRouter && lp.GetValue() == router {
				other = false
			}
		}
		if other {
			n++
		}
	}
	return n
}

func equalSeries(a, b map[string]float64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
