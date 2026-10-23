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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/reconcile"
)

const edgeOpen = "edge-open"

// openNamed opens the edge advertisements it names.
type openNamed map[string]bool

func (o openNamed) Open(adv *bgpv1alpha1.BGPAdvertisement) bool { return o[adv.Name] }

// TestEdgeAdvertisementStatus: a Galactic Edge route's advertisement left
// out because its gate is closed is reported GateClosed, and one the runtime
// holds Advertised. One whose gate is open but which the runtime does not
// hold, as after a failed apply, and an ordinary advertisement the runtime
// does not hold, keep what they had.
func TestEdgeAdvertisementStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &bgpv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "bgp"}}
	adv := func(name string, edge bool) *bgpv1alpha1.BGPAdvertisement {
		a := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: router.Namespace, Generation: 1},
			Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router.Name}},
		}
		if edge {
			a.Labels = map[string]string{crdnames.LabelEdgeRoute: "uid-" + name}
		}
		return a
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(adv(edgeOpen, true), adv("edge-closed", true), adv("edge-unapplied", true),
			adv("workload", false)).
		WithStatusSubresource(&bgpv1alpha1.BGPAdvertisement{}).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, BGPAdvByRouterName, func(o client.Object) []string {
			return []string{o.(*bgpv1alpha1.BGPAdvertisement).Spec.RouterRef.Name}
		}).Build()
	rec := reconcile.New(c, "node-a", "2001:db8::1")
	rec.SetEdgeGate(openNamed{edgeOpen: true, "edge-unapplied": true})
	r := &BGPRouterReconciler{Client: c, Reconciler: rec}
	r.updateAdvertisementStatuses(context.Background(), router, model.RuntimeStatus{
		Advertisements: []model.AdvertisementStatus{{Name: edgeOpen, AdvertisedPrefixes: 1}},
	})
	want := map[string]string{edgeOpen: reasonAdvertised, "edge-closed": ReasonGateClosed, "edge-unapplied": "",
		"workload": ""}
	for name, want := range want {
		var got bgpv1alpha1.BGPAdvertisement
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: router.Namespace, Name: name}, &got); err != nil {
			t.Fatal(err)
		}
		cond := meta.FindStatusCondition(got.Status.Conditions, ConditionAdvertised)
		switch {
		case want == "" && cond != nil:
			t.Errorf("%s: Advertised %+v, want none", name, cond)
		case want != "" && (cond == nil || cond.Reason != want):
			t.Errorf("%s: Advertised %+v, want reason %s", name, cond, want)
		case want == ReasonGateClosed && cond.Status != metav1.ConditionFalse:
			t.Errorf("%s: Advertised %s with its gate closed", name, cond.Status)
		}
	}
}
