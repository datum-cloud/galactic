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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/hash"
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

// TestNoOpReconcileReportsClosedGate: an edge advertisement published while
// its gate is closed leaves the desired router, and so its hash, unchanged.
// The reconcile that sees it skips Apply and still reports it GateClosed.
func TestNoOpReconcileReportsClosedGate(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: testVRFRouterName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: testVRFRouterNode},
			LocalASN: 65000, RouterID: "192.0.2.10"},
	}
	b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).
		WithStatusSubresource(&bgpv1alpha1.BGPRouter{}, &bgpv1alpha1.BGPAdvertisement{})
	for _, obj := range []client.Object{
		&bgpv1alpha1.BGPAdvertisement{}, &bgpv1alpha1.BGPVRFInstance{},
		&bgpv1alpha1.BGPPeer{}, &bgpv1alpha1.BGPPolicy{},
	} {
		b = b.WithIndex(obj, ".spec.routerRef.name", routerRefIndex)
	}
	c := b.Build()
	rec := reconcile.New(c, testVRFRouterNode, "2001:db8::1")
	rec.SetEdgeGate(openNamed{})
	rm := &fakeRuntimeManager{status: model.RuntimeStatus{Healthy: true}}
	r := &BGPRouterReconciler{Client: c, Scheme: scheme, Reconciler: rec, RuntimeManager: rm,
		Hasher: hash.DesiredRouter, NodeName: testVRFRouterNode}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(router)}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-closed", Namespace: testNamespace,
			Labels: map[string]string{crdnames.LabelEdgeRoute: "uid"}},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: testVRFRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{"fd00:10::/64"}},
	}
	if err := c.Create(ctx, adv); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if rm.applies != 1 {
		t.Fatalf("applies = %d, want 1: a closed-gate advertisement moved the hash", rm.applies)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(adv), adv); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(adv.Status.Conditions, ConditionAdvertised)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != ReasonGateClosed {
		t.Fatalf("Advertised after a no-op reconcile = %+v, want False/%s", cond, ReasonGateClosed)
	}
}
