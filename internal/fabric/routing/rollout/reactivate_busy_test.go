// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestReactivationDoesNotPromoteOverAStaleSurvey: a re-activation release
// that has already promoted its deployment can re-read it from a lagging
// cache, see the pre-promotion state, and promote the same deployment
// again — an epoch nobody runs, so the release never completes. The
// promotion decision must use the API server's state, which shows the
// promotion the release just made.
func TestReactivationDoesNotPromoteOverAStaleSurvey(t *testing.T) {
	ctx := context.Background()
	f := newFakeFleetWith(t, map[string]string{"a1": "a"}, nil)
	base := f.deployment("a1")
	now := metav1.Now()

	// What the API server holds: the re-activation promoted the revision
	// at epoch 3 and the router committed it.
	live := base.DeepCopy()
	live.Spec.ActivationEpoch = 3
	live.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: relName, UID: relUID}
	live.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: f.rev.Name}
	live.Spec.ActivationDependencyDigest = digestA
	if err := f.c.Update(ctx, live); err != nil {
		t.Fatal(err)
	}
	live.Status.AppliedEpoch = 3
	live.Status.AppliedRevision = f.rev.Name
	live.Status.AppliedDigest = digestA
	live.Status.HeartbeatTime = &now
	live.Status.Epochs = []networkv1alpha1.FabricEpochStatus{
		{Epoch: 3, Revision: f.rev.Name, Stage: networkv1alpha1.FabricStageCommitted},
	}
	if err := f.c.Status().Update(ctx, live); err != nil {
		t.Fatal(err)
	}

	// What the lagging cache still serves: committed on the revision under
	// an earlier release, with no promotion of ours.
	stale := base.DeepCopy()
	stale.Spec.ActivationEpoch = 1
	stale.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: earlierName, UID: "prior-uid"}
	stale.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: f.rev.Name}
	stale.Spec.ActivationDependencyDigest = digestA
	stale.Status.AppliedEpoch = 1
	stale.Status.AppliedRevision = f.rev.Name
	stale.Status.AppliedDigest = digestA
	stale.Status.HeartbeatTime = &now
	stale.Status.Epochs = []networkv1alpha1.FabricEpochStatus{
		{Epoch: 1, Revision: f.rev.Name, Stage: networkv1alpha1.FabricStageCommitted},
	}
	stale.SetResourceVersion(f.deployment("a1").GetResourceVersion())

	// The cache lags the API server.
	f.r.APIReader = f.c
	f.r.Client = interceptor.NewClient(f.c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption) error {
			if d, ok := obj.(*networkv1alpha1.FabricRouterDeployment); ok && key.Name == "a1" {
				stale.DeepCopyInto(d)
				return nil
			}
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
			opts ...client.ListOption) error {
			if l, ok := list.(*networkv1alpha1.FabricRouterDeploymentList); ok {
				l.Items = []networkv1alpha1.FabricRouterDeployment{*stale.DeepCopy()}
				return nil
			}
			return c.List(ctx, list, opts...)
		},
	})

	// A re-activation release, already started and targeting a1.
	f.release(relName, networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	rel := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(ctx, types.NamespacedName{Namespace: testNS, Name: relName}, rel); err != nil {
		t.Fatal(err)
	}
	rel.Spec.Deployments[0].Reactivate = true
	if err := f.c.Update(ctx, rel); err != nil {
		t.Fatal(err)
	}
	rel.Status.Phase = networkv1alpha1.FabricReleasePhaseStarted
	rel.Status.StartedAt = &now
	if err := f.c.Status().Update(ctx, rel); err != nil {
		t.Fatal(err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: relName}}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	if got := f.deployment("a1"); got.Spec.ActivationEpoch != 3 {
		t.Fatalf("stale survey re-promoted an activating epoch: epoch %d, want 3", got.Spec.ActivationEpoch)
	}
}
