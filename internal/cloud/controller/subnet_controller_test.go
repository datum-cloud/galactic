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

// propagatedSubnet is the copy of a project's subnet a cell is handed: spec
// only, with the upstream generation the operator stamped on it.
func propagatedSubnet(upstreamGeneration string) *networkingv1alpha.Subnet {
	subnet := &networkingv1alpha.Subnet{}
	subnet.Namespace = vpcTestNamespace
	subnet.Name = vpcTestNetwork + "-" + vpcTestLocation + "-ipv6"
	subnet.Generation = 7
	if upstreamGeneration != "" {
		subnet.Annotations = map[string]string{upstreamGenerationAnnotation: upstreamGeneration}
	}
	subnet.Spec.NetworkContext = networkingv1alpha.LocalNetworkContextRef{Name: vpcTestNetwork + "-" + vpcTestLocation}
	subnet.Spec.StartAddress = "fd00::"
	subnet.Spec.PrefixLength = 48
	return subnet
}

func vpcFor(networks []cloudv1alpha1.Network, ready bool) *cloudv1alpha1.VPC {
	vpc := &cloudv1alpha1.VPC{}
	vpc.Namespace = vpcTestNamespace
	vpc.Name = vpcTestNetwork + "-" + vpcTestLocation
	vpc.Spec.Networks = networks
	if ready {
		vpc.Status.VPC = vpcTestIdentifier
		vpc.Status.Conditions = []metav1.Condition{{
			Type: cloudv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue, Reason: "IdentifierAllocated",
		}}
	} else {
		vpc.Status.Conditions = []metav1.Condition{{
			Type: cloudv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse, Reason: "AwaitingFabricIdentity",
			Message: "Waiting for the identity the fabric knows this network by",
		}}
	}
	return vpc
}

func reconcileSubnet(t *testing.T, objects ...client.Object) *networkingv1alpha.Subnet {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := networkingv1alpha.AddToScheme(scheme); err != nil {
		t.Fatalf("build the networking scheme: %v", err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the cloud scheme: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&networkingv1alpha.Subnet{}).
		WithObjects(objects...).Build()

	reconciler := &SubnetReconciler{Client: cl, Scheme: scheme}
	key := types.NamespacedName{Namespace: vpcTestNamespace, Name: vpcTestNetwork + "-" + vpcTestLocation + "-ipv6"}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	subnet := &networkingv1alpha.Subnet{}
	if err := cl.Get(context.Background(), key, subnet); err != nil {
		t.Fatalf("read the subnet: %v", err)
	}
	return subnet
}

func programmedOf(t *testing.T, subnet *networkingv1alpha.Subnet) metav1.Condition {
	t.Helper()
	condition := meta.FindStatusCondition(subnet.Status.Conditions, networkingv1alpha.SubnetProgrammed)
	if condition == nil {
		t.Fatalf("the cell should have reported on the subnet, got %+v", subnet.Status.Conditions)
	}
	return *condition
}

// The signal: a range is in place once the VPC built for its network context
// carries it and is routed by the fabric. The report is made against the
// generation the project knows, not the copy's own.
func TestSubnetIsProgrammedWhenAReadyVPCCarriesItsRange(t *testing.T) {
	subnet := reconcileSubnet(t, propagatedSubnet("3"), vpcFor([]cloudv1alpha1.Network{"fd00::/48"}, true))

	condition := programmedOf(t, subnet)
	if condition.Status != metav1.ConditionTrue || condition.Reason != networkingv1alpha.SubnetProgrammedReasonProgrammed {
		t.Fatalf("a ready VPC carrying the range should read as programmed, got %+v", condition)
	}
	if condition.ObservedGeneration != 3 {
		t.Fatalf("the report is about the project's generation 3, got %d", condition.ObservedGeneration)
	}
}

// A VPC that carries the range but has no identity yet is on its way, and
// says so, rather than claiming the range is routed.
func TestSubnetWaitsForTheVPCToBecomeReady(t *testing.T) {
	subnet := reconcileSubnet(t, propagatedSubnet("3"), vpcFor([]cloudv1alpha1.Network{"fd00::/48"}, false))

	condition := programmedOf(t, subnet)
	if condition.Status != metav1.ConditionFalse || condition.Reason != networkingv1alpha.SubnetProgrammedReasonProgrammingInProgress {
		t.Fatalf("a VPC awaiting its identity should read as in progress, got %+v", condition)
	}
}

// No VPC yet is the same wait: the network context reconciler builds it once
// the subnet it reads from is there.
func TestSubnetWaitsForTheVPCToBeBuilt(t *testing.T) {
	subnet := reconcileSubnet(t, propagatedSubnet("3"))

	condition := programmedOf(t, subnet)
	if condition.Status != metav1.ConditionFalse || condition.Reason != networkingv1alpha.SubnetProgrammedReasonProgrammingInProgress {
		t.Fatalf("a VPC not built yet should read as in progress, got %+v", condition)
	}
}

// A VPC's address space is fixed when it is built. A range it was built
// without is not routed by it, and that is a verdict, not a wait.
func TestSubnetIsNotProgrammedWhenTheVPCWasBuiltWithoutIt(t *testing.T) {
	subnet := reconcileSubnet(t, propagatedSubnet("3"), vpcFor([]cloudv1alpha1.Network{"fd00:1::/48"}, true))

	condition := programmedOf(t, subnet)
	if condition.Status != metav1.ConditionFalse || condition.Reason != networkingv1alpha.SubnetProgrammedReasonNotProgrammed {
		t.Fatalf("a range the VPC was built without should read as not programmed, got %+v", condition)
	}
}

// A copy with no upstream generation stamped on it reports against its own,
// so a project running an older operator still sees a report.
func TestSubnetReportFallsBackToTheCopysOwnGeneration(t *testing.T) {
	subnet := reconcileSubnet(t, propagatedSubnet(""), vpcFor([]cloudv1alpha1.Network{"fd00::/48"}, true))

	if got := programmedOf(t, subnet).ObservedGeneration; got != 7 {
		t.Fatalf("an unstamped copy reports against its own generation 7, got %d", got)
	}
}
