// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/reconcile"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVRFRouterNode = "edge-node"
	testVRFRouterName = "edge-node"
	testVRFName       = "35-edge-node"
)

// fakeRuntimeManager is a RuntimeManager whose reported status the test
// controls. onApply, when set, runs on every Apply with the 1-based call
// count, standing in for the runtime's own VRF outcome changing.
type fakeRuntimeManager struct {
	status  model.RuntimeStatus
	applies int
	onApply func(n int, rs *model.RuntimeStatus)
}

func (f *fakeRuntimeManager) Apply(_ context.Context, _ types.NamespacedName, _ model.DesiredRouter) error {
	f.applies++
	if f.onApply != nil {
		f.onApply(f.applies, &f.status)
	}
	return nil
}

func (f *fakeRuntimeManager) Stop(context.Context, types.NamespacedName) error { return nil }

func (f *fakeRuntimeManager) StopAll(context.Context) error { return nil }

func (f *fakeRuntimeManager) Status(context.Context, types.NamespacedName) (model.RuntimeStatus, error) {
	return f.status, nil
}

func routerRefIndex(obj client.Object) []string {
	switch o := obj.(type) {
	case *bgpv1alpha1.BGPAdvertisement:
		return []string{o.Spec.RouterRef.Name}
	case *bgpv1alpha1.BGPVRFInstance:
		if o.Spec.RouterRef != nil {
			return []string{o.Spec.RouterRef.Name}
		}
	case *bgpv1alpha1.BGPPeer:
		if o.Spec.RouterRef != nil {
			return []string{o.Spec.RouterRef.Name}
		}
	case *bgpv1alpha1.BGPPolicy:
		if o.Spec.RouterRef != nil {
			return []string{o.Spec.RouterRef.Name}
		}
	}
	return nil
}

func newVRFStatusTestReconciler(t *testing.T, rm *fakeRuntimeManager) (*BGPRouterReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add bgpv1alpha1 to scheme: %v", err)
	}
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: testVRFRouterName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Name: testVRFRouterNode},
			LocalASN:  65000,
			RouterID:  "192.0.2.10",
		},
	}
	vrf := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: testVRFName, Namespace: testNamespace, Generation: 1},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: testVRFRouterName}},
			VRFID:              7,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:100"}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:100"}},
		},
	}
	b := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.BGPRouter{}, &bgpv1alpha1.BGPVRFInstance{}).
		WithObjects(router, vrf)
	for _, obj := range []client.Object{
		&bgpv1alpha1.BGPAdvertisement{}, &bgpv1alpha1.BGPVRFInstance{},
		&bgpv1alpha1.BGPPeer{}, &bgpv1alpha1.BGPPolicy{},
	} {
		b = b.WithIndex(obj, ".spec.routerRef.name", routerRefIndex)
	}
	c := b.Build()

	return &BGPRouterReconciler{
		Client:         c,
		Scheme:         scheme,
		Reconciler:     reconcile.New(c, testVRFRouterNode, "2001:db8::1"),
		RuntimeManager: rm,
		Hasher:         hash.DesiredRouter,
		NodeName:       testVRFRouterNode,
	}, c
}

func vrfReady(t *testing.T, c client.Client) *metav1.Condition {
	t.Helper()
	got := &bgpv1alpha1.BGPVRFInstance{}
	key := types.NamespacedName{Namespace: testNamespace, Name: testVRFName}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get BGPVRFInstance: %v", err)
	}
	return meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
}

// TestReconcileRetriesUnwiredVRF guards issue #614: a VRF whose kernel wiring
// failed on the first Apply must be retried on a later reconcile even though
// the config hash no longer changes, and its BGPVRFInstance must read
// Ready=False until the runtime reports it wired.
func TestReconcileRetriesUnwiredVRF(t *testing.T) {
	failed := model.VRFStatus{
		Name: testVRFName, State: model.VRFStateFailed,
		Reason: model.VRFReasonKernelVRFUnresolved, Message: "could not find VRF ID for interface",
	}
	rm := &fakeRuntimeManager{
		status: model.RuntimeStatus{Healthy: true, VRFs: []model.VRFStatus{failed}},
		onApply: func(n int, rs *model.RuntimeStatus) {
			// The second attempt resolves the VRF.
			if n == 2 {
				rs.VRFs = []model.VRFStatus{{Name: testVRFName, State: model.VRFStateApplied}}
			}
		},
	}
	r, c := newVRFStatusTestReconciler(t, rm)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testVRFRouterName}}
	ctx := context.Background()

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if rm.applies != 1 {
		t.Fatalf("reconcile 1: applies = %d, want 1", rm.applies)
	}
	if cond := vrfReady(t, c); cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != failed.Reason {
		t.Errorf("reconcile 1: Ready = %+v, want False/%s", cond, failed.Reason)
	}

	// The config hash is now persisted and unchanged, so only the VRF's
	// failed state can send this reconcile back through Apply.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if rm.applies != 2 {
		t.Fatalf("reconcile 2: applies = %d, want 2 (failed VRF not retried)", rm.applies)
	}
	if cond := vrfReady(t, c); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("reconcile 2: Ready = %+v, want True once the runtime reports the VRF wired", cond)
	}

	// Everything is wired: a true no-op.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile 3: %v", err)
	}
	if rm.applies != 2 {
		t.Errorf("reconcile 3: applies = %d, want 2 (no-op once every VRF is wired)", rm.applies)
	}
}

func TestVRFReadyCondition(t *testing.T) {
	tests := []struct {
		name       string
		vs         model.VRFStatus
		ok         bool
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{name: "no runtime outcome", ok: false, wantStatus: metav1.ConditionUnknown, wantReason: "Pending"},
		{
			name: "applied", ok: true, vs: model.VRFStatus{State: model.VRFStateApplied},
			wantStatus: metav1.ConditionTrue, wantReason: reasonAccepted,
		},
		{
			name: "not in router netns", ok: true,
			vs:         model.VRFStatus{State: model.VRFStateNotInNetns, Reason: model.VRFReasonNotInRouterNetns},
			wantStatus: metav1.ConditionTrue, wantReason: model.VRFReasonNotInRouterNetns,
		},
		{
			name: "probe failed", ok: true,
			vs: model.VRFStatus{
				State: model.VRFStateFailed, Reason: model.VRFReasonDatapathProbeFailed, Message: "boom",
			},
			wantStatus: metav1.ConditionFalse, wantReason: model.VRFReasonDatapathProbeFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vrfReadyCondition(tt.vs, tt.ok)
			if got.Status != tt.wantStatus || got.Reason != tt.wantReason {
				t.Errorf("vrfReadyCondition() = %s/%s, want %s/%s", got.Status, got.Reason, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

func TestAllDesiredVRFsApplied(t *testing.T) {
	vrfs := []model.DesiredVRFInstance{{Name: "a"}, {Name: "b"}}
	tests := []struct {
		name string
		rs   model.RuntimeStatus
		want bool
	}{
		{name: "all applied", want: true, rs: model.RuntimeStatus{VRFs: []model.VRFStatus{
			{Name: "a", State: model.VRFStateApplied}, {Name: "b", State: model.VRFStateApplied},
		}}},
		{name: "one failed", want: false, rs: model.RuntimeStatus{VRFs: []model.VRFStatus{
			{Name: "a", State: model.VRFStateApplied}, {Name: "b", State: model.VRFStateFailed},
		}}},
		{name: "one not in netns", want: false, rs: model.RuntimeStatus{VRFs: []model.VRFStatus{
			{Name: "a", State: model.VRFStateApplied}, {Name: "b", State: model.VRFStateNotInNetns},
		}}},
		{name: "one unreported", want: false, rs: model.RuntimeStatus{VRFs: []model.VRFStatus{
			{Name: "a", State: model.VRFStateApplied},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allDesiredVRFsApplied(vrfs, tt.rs); got != tt.want {
				t.Errorf("allDesiredVRFsApplied() = %v, want %v", got, tt.want)
			}
		})
	}
}
