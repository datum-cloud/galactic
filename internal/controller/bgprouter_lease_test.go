// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"slices"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/reconcile"
)

const leaseLegacyName = "lease-legacy"

type leaseRuntimeManager struct {
	fakeRuntimeManager
	desired model.DesiredRouter
}

func (m *leaseRuntimeManager) Apply(_ context.Context, _ types.NamespacedName, desired model.DesiredRouter) error {
	m.applies++
	m.desired = desired
	m.status.Healthy = true
	m.status.Advertisements = nil
	for _, adv := range desired.Advertisements {
		m.status.Advertisements = append(m.status.Advertisements, model.AdvertisementStatus{
			Name: adv.Name, AdvertisedPrefixes: int32(len(adv.Prefixes)),
		})
	}
	return nil
}

type leaseRouterFixture struct {
	r      *BGPRouterReconciler
	c      client.Client
	router *bgpv1alpha1.BGPRouter
	leased *bgpv1alpha1.BGPAdvertisement
	rm     *leaseRuntimeManager
}

func newLeaseRouterFixture(t *testing.T) *leaseRouterFixture {
	t.Helper()
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: testVRFRouterName, Namespace: testNamespace, Generation: 7},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: testVRFRouterNode}},
	}
	future := metav1.NewTime(time.Now().Add(time.Minute))
	leased := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "leased", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: router.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIUnicast},
			Prefixes:      []bgpv1alpha1.Prefix{"2001:db8:1::abc/128"}, ExpiresAt: &future,
		},
	}
	legacy := leased.DeepCopy()
	legacy.Name = leaseLegacyName
	legacy.Spec.ExpiresAt = nil
	b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, leased, legacy).
		WithStatusSubresource(router, leased)
	for _, o := range []client.Object{
		&bgpv1alpha1.BGPAdvertisement{}, &bgpv1alpha1.BGPVRFInstance{},
		&bgpv1alpha1.BGPPeer{}, &bgpv1alpha1.BGPPolicy{},
	} {
		b = b.WithIndex(o, ".spec.routerRef.name", routerRefIndex)
	}
	c := b.Build()
	rm := &leaseRuntimeManager{}
	r := &BGPRouterReconciler{
		Client: c, Scheme: scheme, Reconciler: reconcile.New(c, testVRFRouterNode, "2001:db8::2"),
		RuntimeManager: rm, Hasher: hash.DesiredRouter, NodeName: testVRFRouterNode,
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(router)}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != advertisementLeaseRequeue {
		t.Fatalf("lease requeue = %v", result.RequeueAfter)
	}
	if err := c.Get(ctx, req.NamespacedName, router); err != nil {
		t.Fatal(err)
	}
	if !router.Status.SupportsAdvertisementLeases || router.Status.ObservedGeneration != 7 ||
		router.Status.LastSuccessfulReconcileTime == nil {
		t.Fatalf("lease capability not current: %+v", router.Status)
	}
	return &leaseRouterFixture{r: r, c: c, router: router, leased: leased, rm: rm}
}

func TestRouterAdvertisementLeaseRenewalDoesNotFlap(t *testing.T) {
	f := newLeaseRouterFixture(t)
	r, c, leased, rm := f.r, f.c, f.leased, f.rm
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}
	for i := range 3 {
		if err := c.Get(ctx, client.ObjectKeyFromObject(leased), leased); err != nil {
			t.Fatal(err)
		}
		deadline := metav1.NewTime(time.Now().Add(time.Duration(i+2) * time.Minute))
		leased.Spec.ExpiresAt = &deadline
		if err := c.Update(ctx, leased); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if rm.applies != 1 || len(rm.desired.Advertisements) != 2 {
		t.Fatalf("renewal changed installed routes: applies=%d desired=%+v", rm.applies, rm.desired.Advertisements)
	}
}

func TestRouterAdvertisementLeaseExpiryAndStartup(t *testing.T) {
	f := newLeaseRouterFixture(t)
	r, c, leased, rm := f.r, f.c, f.leased, f.rm
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}
	if err := c.Get(ctx, client.ObjectKeyFromObject(leased), leased); err != nil {
		t.Fatal(err)
	}
	past := metav1.NewTime(time.Now().Add(-time.Minute))
	leased.Spec.ExpiresAt = &past
	if err := c.Update(ctx, leased); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if rm.applies != 2 || len(rm.desired.Advertisements) != 1 || rm.desired.Advertisements[0].Name != leaseLegacyName {
		t.Fatalf("expiry did not withdraw only leased route: %+v", rm.desired.Advertisements)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(leased), leased); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(leased.Status.Conditions, ConditionAdvertised)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != "LeaseExpired" || leased.Status.AdvertisedPrefixes != 0 {
		t.Fatalf("expired status = %+v", leased.Status)
	}
	rm.status.Advertisements = append(
		rm.status.Advertisements,
		model.AdvertisementStatus{Name: leased.Name, AdvertisedPrefixes: 1},
	)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if rm.applies != 3 || len(rm.status.Advertisements) != 1 {
		t.Fatal("no-op hash retained a stale leased route")
	}
	restarted := &leaseRuntimeManager{}
	r.RuntimeManager = restarted
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if len(restarted.desired.Advertisements) != 1 || restarted.desired.Advertisements[0].Name != leaseLegacyName {
		t.Fatal("startup resurrected expired lease")
	}
}

func TestRouterAdvertisementLeaseTimer(t *testing.T) {
	f := newLeaseRouterFixture(t)
	r, c, leased, router := f.r, f.c, f.leased, f.router
	ctx := context.Background()
	if err := c.Get(ctx, client.ObjectKeyFromObject(leased), leased); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	deadline := metav1.NewTime(now.Add(time.Second))
	leased.Spec.ExpiresAt = &deadline
	if err := c.Update(ctx, leased); err != nil {
		t.Fatal(err)
	}
	delay, err := r.advertisementRequeueAfter(ctx, router, now)
	if err != nil {
		t.Fatal(err)
	}
	if delay != time.Second {
		t.Fatalf("nearest expiry delay = %v", delay)
	}
	if err := c.Delete(ctx, leased); err != nil {
		t.Fatal(err)
	}
	delay, err = r.advertisementRequeueAfter(ctx, router, now)
	if err != nil {
		t.Fatal(err)
	}
	if delay != peerStatusRequeue {
		t.Fatalf("legacy requeue = %v", delay)
	}
}

func TestCoordinatedAdvertisementAuthorityAndWithdrawalFinalizer(t *testing.T) {
	f := newLeaseRouterFixture(t)
	ctx := context.Background()
	r, c, ad := f.r, f.c, f.leased
	address, _ := sharedAddressFixture()
	if err := c.Create(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), ad); err != nil {
		t.Fatal(err)
	}
	ad.Labels = map[string]string{serviceAddressLabel: address.Name, serviceAddressNamespaceLabel: address.Namespace,
		serviceAddressUIDLabel: string(address.UID), gatewayNodeLabel: gatewayNodeLabelValue(testVRFRouterNode)}
	if err := c.Update(ctx, ad); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), ad); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ad.Finalizers, reconcile.CoordinatedAdvertisementFinalizer) {
		t.Fatal("route consumed without cleanup guard")
	}
	if err := c.Delete(ctx, ad); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), ad); err != nil {
		t.Fatal("route guard removed before confirmed withdrawal", err)
	}
	for _, installed := range f.rm.status.Advertisements {
		if installed.Name == ad.Name {
			t.Fatal("deleting advertisement still installed")
		}
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), ad); !apierrors.IsNotFound(err) {
		t.Fatalf("withdrawn ad retained: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	address.Spec.Retired = true
	address.Generation++
	if err := c.Update(ctx, address); err != nil {
		t.Fatal(err)
	}
	late := f.leased.DeepCopy()
	late.Name = "late-create"
	late.ResourceVersion = ""
	late.UID = ""
	late.Finalizers = nil
	late.DeletionTimestamp = nil
	if err := c.Create(ctx, late); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	for _, installed := range f.rm.status.Advertisements {
		if installed.Name == late.Name {
			t.Fatal("late advertisement reopened retired allocation")
		}
	}
	if len(f.rm.status.Advertisements) != 1 || f.rm.status.Advertisements[0].Name != leaseLegacyName {
		t.Fatal("legacy advertisement disturbed")
	}
}

func TestRouterStopReleasesOnlyOwnCoordinatedAdvertisementGuards(t *testing.T) {
	f := newLeaseRouterFixture(t)
	ctx := context.Background()
	address, _ := sharedAddressFixture()
	own := f.leased.DeepCopy()
	own.Name = "own"
	own.ResourceVersion = ""
	own.Finalizers = []string{reconcile.CoordinatedAdvertisementFinalizer}
	own.Labels = map[string]string{
		serviceAddressLabel: address.Name,
		gatewayNodeLabel:    gatewayNodeLabelValue(testVRFRouterNode),
	}
	foreign := own.DeepCopy()
	foreign.Name = "foreign"
	foreign.Labels = map[string]string{serviceAddressLabel: address.Name, gatewayNodeLabel: "other-node"}
	for _, ad := range []*bgpv1alpha1.BGPAdvertisement{own, foreign} {
		if err := f.c.Create(ctx, ad); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.c.Delete(ctx, f.router); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(own), own); !apierrors.IsNotFound(err) {
		t.Fatalf("own guard retained after stop: %v", err)
	}
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(foreign), foreign); err != nil {
		t.Fatal("foreign router guard changed", err)
	}
}
