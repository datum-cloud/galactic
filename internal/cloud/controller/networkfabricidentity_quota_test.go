/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"testing"

	ipamv1alpha1 "go.miloapis.com/ipam/pkg/apis/ipam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Every network claims its identity in the platform's one project, under that
// project's quota on claims. A claim kept after its network is gone holds a
// unit forever, so the quota can only fill, and then no new network anywhere
// gets an identity.
func TestAGoneNetworkGivesItsQuotaUnitBack(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.ipam.limit = 1
	f.reconcile()

	f.deleteNetwork()
	f.reconcile()

	f.addNetwork("next", "us-central-1")
	if err := f.reconcileNamed("next"); err != nil {
		t.Fatalf("a new network must get an identity once the old one is gone: %v", err)
	}
	if n := f.liveClaims(); n != 1 {
		t.Fatalf("only the new network may hold a claim, got %d", n)
	}
}

// Giving the quota unit back must not give the identity back. The block stays
// retained under the network's name, so a network of that name returns to the
// same identity and no other network can ever be handed it.
func TestAReturningNetworkAdoptsTheBlockItGaveUp(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.ipam.limit = 1
	f.reconcile()

	before, ok := f.published()
	if !ok {
		t.Fatal("expected an identity to start from")
	}

	f.deleteNetwork()
	f.reconcile()
	f.createNetwork()
	f.reconcile()

	after, ok := f.published()
	if !ok {
		t.Fatal("the identity must be republished when the network comes back")
	}
	if after.Spec.Identity != before.Spec.Identity {
		t.Fatalf("a returning network must adopt its retained block, got %d then %d",
			before.Spec.Identity, after.Spec.Identity)
	}
}

func (f *identityFixture) reconcileNamed(name string) error {
	f.t.Helper()
	_, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: name},
	})
	return err
}

func (f *identityFixture) liveClaims() int {
	f.t.Helper()
	var live ipamv1alpha1.IPClaimList
	if err := f.ipam.client.List(f.ctx, &live, client.InNamespace("default")); err != nil {
		f.t.Fatalf("list the claims: %v", err)
	}
	return len(live.Items)
}

// A release refused once, by an identity not yet granted delete on claims, is
// retried by the next reconcile of the same network, although the identity it
// would start from is already gone.
func TestARefusedReleaseIsRetriedByTheNextReconcile(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	f.deleteNetwork()
	f.ipam.refuseDelete = true
	if err := f.reconcileNamed(testNetworkName); err == nil {
		t.Fatal("a refused release must fail the reconcile, so it is retried")
	}
	if _, ok := f.published(); ok {
		t.Fatal("the identity is collected before the release is tried")
	}

	f.ipam.refuseDelete = false
	if err := f.reconcileNamed(testNetworkName); err != nil {
		t.Fatalf("the retry must release the claim: %v", err)
	}
	if n := f.liveClaims(); n != 0 {
		t.Fatalf("the retry must leave no claim, got %d", n)
	}
}

// The network is read from the hub's cache. A network deleted and recreated
// under the same name can still read as gone there, while it lives. Its claim
// must not be released on that read, or the network would hold its block with
// no claim, uncounted by the quota for as long as it lives.
func TestALiveNetworkThatReadsGoneKeepsItsClaim(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	f.reconciler.Networks = staleGetter{Client: f.networks}
	if err := f.reconcileNamed(testNetworkName); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := f.liveClaims(); n != 1 {
		t.Fatalf("a network that lives must keep its claim, got %d claims", n)
	}

	f.reconciler.Networks = f.networks
	f.reconcile()
	if _, ok := f.published(); !ok {
		t.Fatal("the next reconcile must publish the identity again")
	}
}

// staleGetter stands in for a cache that has not seen a network come back:
// every network reads as gone.
type staleGetter struct {
	client.Client
}

func (staleGetter) Get(_ context.Context, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "networking.datumapis.com", Resource: "networks"}, key.Name)
}

// A direct read that fails cannot confirm the network is gone, so the claim is
// kept and the reconcile fails, to be retried.
func TestAnUnconfirmedGoneNetworkKeepsItsClaim(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	f.reconciler.Networks = staleGetter{Client: f.networks}
	f.reconciler.NetworkReader = failingGetter{Client: f.networks}
	if err := f.reconcileNamed(testNetworkName); err == nil {
		t.Fatal("a release that cannot confirm the network is gone must fail the reconcile")
	}
	if n := f.liveClaims(); n != 1 {
		t.Fatalf("an unconfirmed release must keep the claim, got %d claims", n)
	}
}
