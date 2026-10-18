// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestRoutersForNodeSkipsFabricRouter: GC and datapath repair never treat a
// fabric-class router on the node as tenant state.
func TestRoutersForNodeSkipsFabricRouter(t *testing.T) {
	fabric := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "fabric", Namespace: "galactic-system"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Name: "node-a"}, RouterClassName: ptr.To("fabric-frr"),
		},
	}
	galactic := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "galactic", Namespace: "galactic-system"},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: "node-a"}},
	}
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(fabric, galactic).Build()
	routers, err := routersForNode(context.Background(), k8s, "galactic-system", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routers["galactic"]; !ok || len(routers) != 1 {
		t.Errorf("routersForNode = %v, want only the Galactic router", routers)
	}
}
