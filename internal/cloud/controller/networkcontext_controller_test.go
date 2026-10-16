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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// A location's Subnet arrives by propagation, which carries spec and never
// status, so the allocated range has to be readable from either.
func TestSubnetRangePrefersStatusAndFallsBackToSpec(t *testing.T) {
	start := "fd00::"
	var length int32 = 48

	withStatus := &networkingv1alpha.Subnet{
		Spec:   networkingv1alpha.SubnetSpec{StartAddress: "fd20::", PrefixLength: 64},
		Status: networkingv1alpha.SubnetStatus{StartAddress: &start, PrefixLength: &length},
	}
	gotStart, gotLength, ok := subnetRange(withStatus)
	if !ok || gotStart != "fd00::" || gotLength != 48 {
		t.Fatalf("status should win when present, got %q/%d ok=%v", gotStart, gotLength, ok)
	}

	specOnly := &networkingv1alpha.Subnet{
		Spec: networkingv1alpha.SubnetSpec{StartAddress: "fd20::", PrefixLength: 64},
	}
	gotStart, gotLength, ok = subnetRange(specOnly)
	if !ok || gotStart != "fd20::" || gotLength != 64 {
		t.Fatalf("a propagated copy carries spec only, got %q/%d ok=%v", gotStart, gotLength, ok)
	}

	if _, _, ok := subnetRange(&networkingv1alpha.Subnet{}); ok {
		t.Fatal("an unallocated subnet should yield nothing")
	}
}

const (
	vpcTestNamespace = "ns-project"
	vpcTestNetwork   = "prod"
	vpcTestLocation  = "us-central-1"

	// The identity the fabric knows the test network by, and the identifier a
	// VPC derives from it.
	vpcTestIdentity   = 16
	vpcTestIdentifier = "g"
)

type vpcFixture struct {
	t          *testing.T
	ctx        context.Context
	client     client.Client
	reconciler *NetworkContextReconciler
}

// newVPCFixture stands up one network present at one location, with the subnet
// that gives the VPC an address space to be created for.
func newVPCFixture(t *testing.T, objects ...client.Object) *vpcFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := networkingv1alpha.AddToScheme(scheme); err != nil {
		t.Fatalf("build the networking scheme: %v", err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the cloud scheme: %v", err)
	}

	presence := &networkingv1alpha.NetworkContext{}
	presence.Namespace = vpcTestNamespace
	presence.Name = vpcTestNetwork + "-" + vpcTestLocation
	presence.Spec.Network = networkingv1alpha.LocalNetworkRef{Name: vpcTestNetwork}
	presence.Spec.Location = networkingv1alpha.LocationReference{Name: vpcTestLocation}

	subnet := &networkingv1alpha.Subnet{}
	subnet.Namespace = vpcTestNamespace
	subnet.Name = presence.Name
	subnet.Spec.NetworkContext = networkingv1alpha.LocalNetworkContextRef{Name: presence.Name}
	subnet.Spec.StartAddress = "fd00::"
	subnet.Spec.PrefixLength = 48

	all := append([]client.Object{presence, subnet}, objects...)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&cloudv1alpha1.VPC{}).
		WithObjects(all...).Build()

	return &vpcFixture{
		t:          t,
		ctx:        context.Background(),
		client:     fakeClient,
		reconciler: &NetworkContextReconciler{Client: fakeClient, Scheme: scheme},
	}
}

func (f *vpcFixture) reconcile() ctrl.Result {
	f.t.Helper()
	result, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: vpcTestNamespace,
		Name:      vpcTestNetwork + "-" + vpcTestLocation,
	}})
	if err != nil {
		f.t.Fatalf("reconcile: %v", err)
	}
	return result
}

func (f *vpcFixture) vpc() *cloudv1alpha1.VPC {
	f.t.Helper()
	vpc := &cloudv1alpha1.VPC{}
	key := types.NamespacedName{Namespace: vpcTestNamespace, Name: vpcTestNetwork + "-" + vpcTestLocation}
	if err := f.client.Get(f.ctx, key, vpc); err != nil {
		f.t.Fatalf("read the VPC: %v", err)
	}
	return vpc
}

func fabricIdentityObject() *cloudv1alpha1.NetworkFabricIdentity {
	object := &cloudv1alpha1.NetworkFabricIdentity{}
	object.Namespace = vpcTestNamespace
	object.Name = vpcTestNetwork
	object.Spec.Identity = vpcTestIdentity
	object.Spec.NetworkRef = cloudv1alpha1.NetworkFabricIdentityNetworkRef{Name: vpcTestNetwork}
	return object
}

// The whole point: every location of one network reaches the same identifier,
// because every one of them reads the same centrally allocated identity.
func TestVPCTakesItsIdentifierFromTheNetworksFabricIdentity(t *testing.T) {
	fixture := newVPCFixture(t, fabricIdentityObject())

	fixture.reconcile()

	vpc := fixture.vpc()
	if vpc.Status.VPC != vpcTestIdentifier {
		t.Fatalf("VPC identifier: got %q, want %q", vpc.Status.VPC, vpcTestIdentifier)
	}
	if condition := meta.FindStatusCondition(vpc.Status.Conditions, cloudv1alpha1.ConditionTypeReady); condition == nil ||
		condition.Status != metav1.ConditionTrue {
		t.Fatalf("a VPC with an identifier should be ready, got %+v", condition)
	}
}

// A network whose identity has not reached this cell yet waits, and writes
// nothing. The identifier is immutable, so a value taken while waiting is
// permanent, and locations that disagree bind no VRF at all.
func TestVPCWaitsForAnIdentityThatHasNotArrived(t *testing.T) {
	fixture := newVPCFixture(t)

	if result := fixture.reconcile(); result.RequeueAfter != 0 {
		t.Fatalf("the identity's arrival is the trigger, not a poll, got %v", result)
	}

	vpc := fixture.vpc()
	if vpc.Status.VPC != "" {
		t.Fatalf("no identifier should be written while waiting, got %q", vpc.Status.VPC)
	}
	condition := meta.FindStatusCondition(vpc.Status.Conditions, cloudv1alpha1.ConditionTypeReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != "AwaitingFabricIdentity" {
		t.Fatalf("the wait should be visible on the VPC, got %+v", condition)
	}
}

// The identity landing is what ends the wait, and the identifier that follows
// is the derived one rather than a random draw.
func TestVPCTakesTheIdentityOnceItArrives(t *testing.T) {
	fixture := newVPCFixture(t)

	fixture.reconcile()
	if got := fixture.vpc().Status.VPC; got != "" {
		t.Fatalf("no identifier should be written while waiting, got %q", got)
	}

	if err := fixture.client.Create(fixture.ctx, fabricIdentityObject()); err != nil {
		t.Fatalf("publish the identity: %v", err)
	}
	fixture.reconcile()

	if got := fixture.vpc().Status.VPC; got != vpcTestIdentifier {
		t.Fatalf("VPC identifier: got %q, want %q", got, vpcTestIdentifier)
	}
}

// Renumbering a live VPC would rename its VRF device and change its Route
// Target under running traffic, so an identifier already written stays written
// even when it disagrees with the identity that later arrived.
func TestVPCKeepsAnIdentifierItAlreadyHas(t *testing.T) {
	existing := &cloudv1alpha1.VPC{}
	existing.Namespace = vpcTestNamespace
	existing.Name = vpcTestNetwork + "-" + vpcTestLocation
	existing.Status.VPC = "R2POk4jT"

	fixture := newVPCFixture(t, existing, fabricIdentityObject())

	fixture.reconcile()

	if got := fixture.vpc().Status.VPC; got != "R2POk4jT" {
		t.Fatalf("an allocated VPC must keep its identifier, got %q", got)
	}
}

// An identity reaching the cell has to wake the presences waiting on it, or a
// VPC would sit out its poll interval for a value already there.
func TestFabricIdentityWakesTheNetworksPresences(t *testing.T) {
	fixture := newVPCFixture(t)

	requests := fixture.reconciler.contextsForFabricIdentity(fixture.ctx, fabricIdentityObject())

	if len(requests) != 1 || requests[0].Name != vpcTestNetwork+"-"+vpcTestLocation {
		t.Fatalf("the network's presence should be enqueued, got %v", requests)
	}

	other := fabricIdentityObject()
	other.Name = "unrelated"
	if requests := fixture.reconciler.contextsForFabricIdentity(fixture.ctx, other); len(requests) != 0 {
		t.Fatalf("another network's identity should enqueue nothing, got %v", requests)
	}
}
