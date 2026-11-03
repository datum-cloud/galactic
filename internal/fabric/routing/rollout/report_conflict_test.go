// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// conflictOnceClient fails the first status update with a conflict, the way a
// controller writing the same deployment while the agent reports makes the
// fleet observe one, and delegates every later write.
type conflictOnceClient struct {
	client.Client
	updates int
}

func (c *conflictOnceClient) Status() client.SubResourceWriter {
	return &conflictOnceStatus{SubResourceWriter: c.Client.Status(), parent: c}
}

type conflictOnceStatus struct {
	client.SubResourceWriter
	parent *conflictOnceClient
}

func (s *conflictOnceStatus) Update(ctx context.Context, obj client.Object,
	opts ...client.SubResourceUpdateOption) error {
	s.parent.updates++
	if s.parent.updates == 1 {
		if dep, ok := obj.(*networkv1alpha1.FabricRouterDeployment); ok {
			return apierrors.NewConflict(
				schema.GroupResource{Group: "galactic.datumapis.com", Resource: "fabricrouterdeployments"},
				dep.Name, nil)
		}
	}
	return s.SubResourceWriter.Update(ctx, obj, opts...)
}

// TestReportRetriesOnConflict keeps the reporting helper honest: a controller
// writing the deployment between the agent's read and its status update must
// not fail the agent's report.
func TestReportRetriesOnConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = networkv1alpha1.AddToScheme(scheme)
	dep := &networkv1alpha1.FabricRouterDeployment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testNode}}
	dep.Spec.ActivationEpoch = 2
	dep.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "rev2"}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep).
		WithStatusSubresource(dep).Build()
	c := &conflictOnceClient{Client: base}

	report(t, c, networkv1alpha1.FabricStageCommitted, nil)

	if c.updates != 2 {
		t.Fatalf("status updates = %d, want 2 (one conflict, one success)", c.updates)
	}
	got := getDeployment(t, c)
	if len(got.Status.Epochs) != 1 || got.Status.Epochs[0].Epoch != 2 ||
		got.Status.Epochs[0].Revision != "rev2" ||
		got.Status.Epochs[0].Stage != networkv1alpha1.FabricStageCommitted {
		t.Fatalf("reported epochs = %+v", got.Status.Epochs)
	}
}
