// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestBuildDesiredRouterSkipsClassedRouter: a router naming a class is
// skipped on its own node before any peer or policy lookup, so GoBGP never
// programs the fabric underlay's sessions.
func TestBuildDesiredRouterSkipsClassedRouter(t *testing.T) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "fabric", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:       bgpv1alpha1.TargetRef{Name: "node-a"},
			RouterClassName: ptrString("fabric-frr"),
		},
	}
	// No field indexes: reaching a peer or advertisement lookup would fail.
	r := New(fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build(), "node-a", "")
	got, err := r.BuildDesiredRouter(context.Background(), router)
	if err != nil || got != nil {
		t.Errorf("BuildDesiredRouter = %v, %v; want a silent skip", got, err)
	}
}
