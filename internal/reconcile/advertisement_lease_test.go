// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/hash"
)

func TestAdvertisementLeaseExpiryAndRenewal(t *testing.T) {
	const thisNode = "lease-node"
	ctx := context.Background()
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: testNamespace},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: thisNode}},
	}
	future := metav1.NewTime(time.Now().Add(time.Minute))
	leased := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "leased", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: router.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIUnicast},
			Prefixes:      []bgpv1alpha1.Prefix{"2001:db8::1/128"}, ExpiresAt: &future,
		},
	}
	legacy := leased.DeepCopy()
	legacy.Name = "legacy"
	legacy.Spec.ExpiresAt = nil
	c := indexedFakeClient(t, router, leased, legacy)
	r := New(c, thisNode, "2001:db8::2")
	first, err := r.BuildDesiredRouter(ctx, router)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Advertisements) != 2 {
		t.Fatalf("active advertisements = %d", len(first.Advertisements))
	}
	originalHash, err := hash.DesiredRouter(*first)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := c.Get(ctx, client.ObjectKeyFromObject(leased), leased); err != nil {
			t.Fatal(err)
		}
		deadline := metav1.NewTime(time.Now().Add(time.Duration(i+2) * time.Minute))
		leased.Spec.ExpiresAt = &deadline
		if err := c.Update(ctx, leased); err != nil {
			t.Fatal(err)
		}
		renewed, err := r.BuildDesiredRouter(ctx, router)
		if err != nil {
			t.Fatal(err)
		}
		renewedHash, err := hash.DesiredRouter(*renewed)
		if err != nil {
			t.Fatal(err)
		}
		if renewedHash != originalHash {
			t.Fatal("lease renewal changed desired route hash")
		}
	}
	past := metav1.NewTime(time.Now().Add(-time.Minute))
	leased.Spec.ExpiresAt = &past
	if err := c.Update(ctx, leased); err != nil {
		t.Fatal(err)
	}
	restored := New(c, thisNode, "2001:db8::2")
	desired, err := restored.BuildDesiredRouter(ctx, router)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.Advertisements) != 1 || desired.Advertisements[0].Name != "legacy" {
		t.Fatalf("expired lease restored: %+v", desired.Advertisements)
	}
	if !AdvertisementLeaseExpired(leased, past.Time) {
		t.Fatal("lease is live at its deadline")
	}
	if AdvertisementLeaseExpired(legacy, past.Time) {
		t.Fatal("legacy advertisement expired")
	}
}
