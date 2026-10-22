// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	tenantNS    = "tenant"
	serviceName = "edge"
)

func apiProvider() *galacticv1alpha1.EdgeProvider {
	return &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: connectIP},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{contractV1},
			Capabilities:     []galacticv1alpha1.EdgeCapability{{Name: packetAccess, Version: "v1"}},
			ServiceAccounts:  []galacticv1alpha1.ServiceAccountReference{{Namespace: providerNS, Name: providerSA}},
			Configuration:    galacticv1alpha1.ConfigurationKind{Group: configGroup, Kind: configKind},
		},
		Status: galacticv1alpha1.EdgeProviderStatus{Approved: true},
	}
}

func apiService() *galacticv1alpha1.EdgeService {
	until := metav1.NewTime(epoch.Add(time.Hour))
	return &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: tenantNS, UID: grantUID, Generation: 3},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: connectIP},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: "prod", UID: prodVPC},
			Capabilities: []string{packetAccess},
			Prefixes:     []string{"fd00:5::/48"},
			ValidUntil:   &until,
		},
	}
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

func TestSourcesLoadTheAPI(t *testing.T) {
	ctx := context.Background()
	c := newFakeClient(t, apiProvider(), apiService())
	a, _ := newTestAuthority(t)
	a.DeleteProvider(connectIP)
	a.DeleteGrant(grantUID)
	ps := &ProviderSource{Reader: c, Authority: a}
	gs := &GrantSource{Reader: c, Authority: a}
	svcKey := types.NamespacedName{Namespace: tenantNS, Name: serviceName}

	if d := a.Admit(request()); d.Admitted {
		t.Fatal("admitted before the API was loaded")
	}
	mustReconcile(t, ps, types.NamespacedName{Name: connectIP})
	mustReconcile(t, gs, svcKey)
	z := admitted(t, a, request())

	// Editing the service bumps its generation and revokes what was
	// admitted under the old one.
	svc := &galacticv1alpha1.EdgeService{}
	if err := c.Get(ctx, svcKey, svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.Prefixes = []string{"fd00:5::/56"}
	svc.Generation++
	if err := c.Update(ctx, svc); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, gs, svcKey)
	if !ended(z) || z.Reason() != StaleGrant {
		t.Fatalf("after a grant edit, ended %t with %q", ended(z), z.Reason())
	}

	// Deleting the service revokes the grant.
	req := request()
	req.Grant.Generation = svc.Generation
	z = admitted(t, a, req)
	if err := c.Delete(ctx, svc); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, gs, svcKey)
	if !ended(z) || z.Reason() != GrantRevoked {
		t.Fatalf("after a grant delete, ended %t with %q", ended(z), z.Reason())
	}
}

func TestGrantSourceRecreatedService(t *testing.T) {
	ctx := context.Background()
	c := newFakeClient(t, apiProvider(), apiService())
	a, _ := newTestAuthority(t)
	gs := &GrantSource{Reader: c, Authority: a}
	key := types.NamespacedName{Namespace: tenantNS, Name: serviceName}
	mustReconcile(t, gs, key)
	z := admitted(t, a, request())

	// The same name with a new UID is a new grant; the old one is gone
	// even though no reconcile ever saw it missing.
	if err := c.Delete(ctx, apiService()); err != nil {
		t.Fatal(err)
	}
	recreated := apiService()
	recreated.UID = "grant-uid-new"
	if err := c.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, gs, key)
	if !ended(z) || z.Reason() != GrantRevoked {
		t.Fatalf("after recreation, ended %t with %q", ended(z), z.Reason())
	}
}

func TestGrantSourceRefusesAMalformedPrefix(t *testing.T) {
	bad := apiService()
	bad.Spec.Prefixes = []string{"fd00:5::1/48"}
	c := newFakeClient(t, apiProvider(), bad)
	a, _ := newTestAuthority(t)
	z := admitted(t, a, request())
	gs := &GrantSource{Reader: c, Authority: a}
	_, err := gs.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: tenantNS, Name: serviceName}})
	if err == nil {
		t.Fatal("Reconcile accepted a prefix with host bits")
	}
	if !ended(z) || z.Reason() != GrantRevoked {
		t.Fatalf("after a malformed grant, ended %t with %q", ended(z), z.Reason())
	}
}

func TestProviderSourceDeletion(t *testing.T) {
	c := newFakeClient(t)
	a, _ := newTestAuthority(t)
	z := admitted(t, a, request())
	mustReconcile(t, &ProviderSource{Reader: c, Authority: a}, types.NamespacedName{Name: connectIP})
	if !ended(z) || z.Reason() != UnknownProvider {
		t.Fatalf("after provider deletion, ended %t with %q", ended(z), z.Reason())
	}
}

func TestProviderFromAPI(t *testing.T) {
	got := ProviderFromAPI(apiProvider())
	want := registry()[connectIP]
	if got.Name != want.Name || got.Approved != want.Approved || got.ConfigGroup != want.ConfigGroup ||
		got.ConfigKind != want.ConfigKind || len(got.Capabilities) != 1 || got.Capabilities[0] != packetV1 ||
		len(got.ServiceAccounts) != 1 || got.ServiceAccounts[0] != callerA.ServiceAccount ||
		len(got.ContractVersions) != 1 || got.ContractVersions[0] != contractV1 {
		t.Fatalf("ProviderFromAPI = %+v, want %+v", got, want)
	}
}

func mustReconcile(t *testing.T, r reconcile.Reconciler, key types.NamespacedName) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
}
