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

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

func TestReconcileNADTakesOverLegacyAttachment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := nadv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	controller := true
	old := &nadv1.NetworkAttachmentDefinition{ObjectMeta: metav1.ObjectMeta{
		Name: "nic", Namespace: "tenant",
		Labels:          map[string]string{legacyLabelVPC: "1", legacyLabelVPCAttachment: "2"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "cloud.datumapis.com/v1alpha1", Kind: "VPCAttachment", Name: "nic", UID: types.UID("old"), Controller: &controller}},
	}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(old).Build()
	r := &NetworkInterfaceReconciler{Client: cl, APIReader: cl, Scheme: scheme}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant", UID: types.UID("new")}}
	attachment.Spec.Interface.Mode = cloudv1alpha1.VPCAttachmentInterfaceModeNetns
	vpc := &cloudv1alpha1.VPC{}
	vpc.Status.VPC = "1"
	iface := &networkingv1alpha.NetworkInterface{}
	iface.Spec.MTU = 1500
	got, err := r.reconcileNAD(context.Background(), attachment, vpc, iface)
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels[LabelVPCAttachment] != "2" {
		t.Fatalf("attachment ID changed: %q", got.Labels[LabelVPCAttachment])
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].APIVersion != cloudv1alpha1.GroupVersion.String() || got.OwnerReferences[0].UID != attachment.UID {
		t.Fatalf("owner references = %#v", got.OwnerReferences)
	}
}

func TestPublishToInterfaceReprogramsNSOAttachmentGroup(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkingv1alpha.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	iface := &networkingv1alpha.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	iface.Spec.ClaimRef = &networkingv1alpha.NetworkInterfaceClaimRef{Name: "claim"}
	claim := &networkingv1alpha.NetworkInterfaceClaim{ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "tenant"}}
	claim.Status.Conditions = []metav1.Condition{
		{Type: networkingv1alpha.NetworkInterfaceClaimProgrammed, Status: metav1.ConditionTrue, Reason: "OldGroupProgrammed", LastTransitionTime: metav1.Now()},
		{Type: networkingv1alpha.NetworkInterfaceClaimReady, Status: metav1.ConditionTrue, Reason: "OldGroupReady", LastTransitionTime: metav1.Now()},
	}
	iface.Status.AttachmentRef = &networkingv1alpha.NetworkInterfaceAttachmentRef{
		APIGroup: "cloud.datumapis.com", Kind: "VPCAttachment", Name: "nic",
	}
	iface.Status.Conditions = []metav1.Condition{{
		Type:   networkingv1alpha.NetworkInterfaceProgrammed,
		Status: metav1.ConditionTrue, Reason: "OldGroupProgrammed", LastTransitionTime: metav1.Now(),
	}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(iface, claim).WithObjects(iface, claim).Build()
	r := &NetworkInterfaceReconciler{Client: cl}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	vpc := &cloudv1alpha1.VPC{}
	vpc.Status.VPC = "vpc-1"
	if err := r.publishToInterface(context.Background(), iface, attachment, vpc); err != nil {
		t.Fatal(err)
	}
	var got networkingv1alpha.NetworkInterface
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(iface), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AttachmentRef == nil || got.Status.AttachmentRef.APIGroup != "galactic.datumapis.com" {
		t.Fatalf("attachment reference = %#v, want Galactic API group", got.Status.AttachmentRef)
	}
	condition := apimeta.FindStatusCondition(got.Status.Conditions, networkingv1alpha.NetworkInterfaceProgrammed)
	if condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "APIGroupMigration" {
		t.Fatalf("Programmed condition = %#v, want Unknown/APIGroupMigration", condition)
	}
	var gotClaim networkingv1alpha.NetworkInterfaceClaim
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(claim), &gotClaim); err != nil {
		t.Fatal(err)
	}
	for _, conditionType := range []string{networkingv1alpha.NetworkInterfaceClaimProgrammed, networkingv1alpha.NetworkInterfaceClaimReady} {
		condition := apimeta.FindStatusCondition(gotClaim.Status.Conditions, conditionType)
		if condition == nil || condition.Status != metav1.ConditionUnknown {
			t.Fatalf("claim %s condition = %#v, want Unknown during migration", conditionType, condition)
		}
	}
}

func TestMasterPlugin(t *testing.T) {
	tests := []struct {
		mode cloudv1alpha1.VPCAttachmentInterfaceMode
		want string
	}{
		{cloudv1alpha1.VPCAttachmentInterfaceModeNetns, galactic.PluginVeth},
		{cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor, galactic.PluginTap},
		{cloudv1alpha1.VPCAttachmentInterfaceModeHypervisorDeclared, galactic.PluginTap},
	}
	for _, test := range tests {
		t.Run(string(test.mode), func(t *testing.T) {
			if got := masterPlugin(test.mode); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestClaimFulfilled(t *testing.T) {
	newInterface := func(phase networkingv1alpha.NetworkInterfacePhase, allocated metav1.ConditionStatus,
		contextRef *networkingv1alpha.LocalNetworkContextRef) *networkingv1alpha.NetworkInterface {
		return &networkingv1alpha.NetworkInterface{
			Status: networkingv1alpha.NetworkInterfaceStatus{
				Phase:             phase,
				NetworkContextRef: contextRef,
				Conditions: []metav1.Condition{{
					Type:   networkingv1alpha.NetworkInterfaceAllocated,
					Status: allocated,
					Reason: "Test",
				}},
			},
		}
	}
	contextRef := &networkingv1alpha.LocalNetworkContextRef{Name: "default-us-central-1"}

	tests := []struct {
		name             string
		networkInterface *networkingv1alpha.NetworkInterface
		want             bool
	}{
		{"bound and allocated", newInterface(
			networkingv1alpha.NetworkInterfacePhaseBound, metav1.ConditionTrue, contextRef), true},
		{"available", newInterface(
			networkingv1alpha.NetworkInterfacePhaseAvailable, metav1.ConditionTrue, contextRef), false},
		{"not allocated", newInterface(
			networkingv1alpha.NetworkInterfacePhaseBound, metav1.ConditionFalse, contextRef), false},
		{"no network context", newInterface(
			networkingv1alpha.NetworkInterfacePhaseBound, metav1.ConditionTrue, nil), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := claimFulfilled(test.networkInterface); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}

// The cell-wide mode is the only signal every attachment written until now
// carries, so it has to keep deciding for all of them. An interface that
// states its own mode is the exception.
func TestAttachmentModeFallsBackToTheCell(t *testing.T) {
	r := &NetworkInterfaceReconciler{
		AttachmentMode: cloudv1alpha1.VPCAttachmentInterfaceModeNetns,
	}

	tests := []struct {
		name  string
		iface networkingv1alpha.NetworkInterfaceAttachmentMode
		want  cloudv1alpha1.VPCAttachmentInterfaceMode
	}{
		{"unset", "", cloudv1alpha1.VPCAttachmentInterfaceModeNetns},
		{"netns", networkingv1alpha.NetworkInterfaceAttachmentModeNetns,
			cloudv1alpha1.VPCAttachmentInterfaceModeNetns},
		{"hypervisor", networkingv1alpha.NetworkInterfaceAttachmentModeHypervisor,
			cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor},
		{"declared", networkingv1alpha.NetworkInterfaceAttachmentModeHypervisorDeclared,
			cloudv1alpha1.VPCAttachmentInterfaceModeHypervisorDeclared},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			networkInterface := &networkingv1alpha.NetworkInterface{
				Spec: networkingv1alpha.NetworkInterfaceSpec{AttachmentMode: test.iface},
			}
			if got := r.attachmentMode(networkInterface); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// Only the declared mode asks the tap plugin to describe the device.
// TestHostInterfaceAnnotationKey pins the annotation key this controller writes
// on the NAD. The key is a contract with the data plane: galactic writes the
// same one during CNI ADD, and a runtime reads it to learn its host device.
// Renaming it here alone would leave that runtime with nothing to read, and
// nothing else in this repository would fail.
func TestHostInterfaceAnnotationKey(t *testing.T) {
	const want = "k8s.v1.cni.cncf.io/host-interface"
	if AnnotationHostInterface != want {
		t.Errorf("AnnotationHostInterface = %q, want %q", AnnotationHostInterface, want)
	}
}

func TestDeclaresDevice(t *testing.T) {
	if declaresDevice(cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor) {
		t.Error("a discovered hypervisor attachment must not ask for a description")
	}
	if !declaresDevice(cloudv1alpha1.VPCAttachmentInterfaceModeHypervisorDeclared) {
		t.Error("a declared hypervisor attachment must ask for a description")
	}
}
