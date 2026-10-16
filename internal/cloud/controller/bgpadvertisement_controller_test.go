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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

func TestAdvertisementReprogramsGalacticInterfaceAndClaim(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := networkingv1alpha.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	attachment.Spec.InterfaceRef = &cloudv1alpha1.NetworkInterfaceRef{Name: "nic"}
	attachment.Status.VPC = "1n"
	attachment.Status.VPCAttachment = "bQy"
	identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)
	first := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-a", Namespace: "galactic-system"}}
	second := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-b", Namespace: "galactic-system"}}
	unrelated := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: "11-22-node-c", Namespace: "galactic-system"}}
	iface := &networkingv1alpha.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	iface.Spec.ClaimRef = &networkingv1alpha.NetworkInterfaceClaimRef{Name: "claim"}
	iface.Status.AttachmentRef = &networkingv1alpha.NetworkInterfaceAttachmentRef{
		APIGroup: cloudv1alpha1.GroupVersion.Group, Kind: "VPCAttachment", Name: "nic",
	}
	claim := &networkingv1alpha.NetworkInterfaceClaim{ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "tenant"}}
	meta.SetStatusCondition(&claim.Status.Conditions, metav1.Condition{
		Type: networkingv1alpha.NetworkInterfaceClaimProgrammed, Status: metav1.ConditionUnknown, Reason: "APIGroupMigration",
	})
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(iface, claim, attachment).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, IndexBGPAdvertisementIdentity, BGPAdvertisementIdentity).
		WithObjects(iface, claim, attachment, first, second, unrelated).Build()
	r := &BGPAdvertisementReconciler{Client: cl}
	programmed := metav1.Condition{Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue, Reason: "Advertised"}
	legacy := iface.DeepCopy()
	legacy.Status.AttachmentRef.APIGroup = "cloud.datumapis.com"
	if err := cl.Status().Update(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if err := r.projectOntoInterface(ctx, attachment, programmed); err != nil {
		t.Fatal(err)
	}
	var before networkingv1alpha.NetworkInterfaceClaim
	if err := cl.Get(ctx, client.ObjectKeyFromObject(claim), &before); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(before.Status.Conditions, networkingv1alpha.NetworkInterfaceClaimProgrammed); condition == nil || condition.Status != metav1.ConditionUnknown {
		t.Fatalf("legacy claim Programmed = %#v, want Unknown", condition)
	}
	legacy.Status.AttachmentRef.APIGroup = cloudv1alpha1.GroupVersion.Group
	if err := cl.Status().Update(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	requests := r.advertisementForInterface(ctx, iface)
	if len(requests) != 2 || requests[0].Namespace != "galactic-system" || requests[0].Name != first.Name ||
		requests[1].Namespace != "galactic-system" || requests[1].Name != second.Name {
		t.Fatalf("advertisement replay requests = %#v", requests)
	}
	if err := r.projectOntoInterface(ctx, attachment, programmed); err != nil {
		t.Fatal(err)
	}
	var got networkingv1alpha.NetworkInterface
	if err := cl.Get(ctx, client.ObjectKeyFromObject(iface), &got); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, networkingv1alpha.NetworkInterfaceProgrammed); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("interface Programmed = %#v, want True", condition)
	}
	var gotClaim networkingv1alpha.NetworkInterfaceClaim
	if err := cl.Get(ctx, client.ObjectKeyFromObject(claim), &gotClaim); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(gotClaim.Status.Conditions, networkingv1alpha.NetworkInterfaceClaimProgrammed); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("claim Programmed = %#v, want True", condition)
	}
}
