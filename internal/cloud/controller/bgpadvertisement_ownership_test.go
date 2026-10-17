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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const bgpNamespace = "galactic-system"

// ownershipFixture holds one tenant attachment with its interface and claim,
// a Galactic router and a fabric-class router on the same node, and one
// advertisement per router whose names both decode to the attachment.
type ownershipFixture struct {
	client     client.Client
	reconciler *BGPAdvertisementReconciler
	attachment *cloudv1alpha1.VPCAttachment
	iface      *networkingv1alpha.NetworkInterface
	tenantAdv  *bgpv1alpha1.BGPAdvertisement
	fabricAdv  *bgpv1alpha1.BGPAdvertisement
}

func newOwnershipFixture(t *testing.T, fabricFirst bool) *ownershipFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		cloudv1alpha1.AddToScheme, bgpv1alpha1.AddToScheme, networkingv1alpha.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	attachment.Spec.InterfaceRef = &cloudv1alpha1.NetworkInterfaceRef{Name: "nic"}
	attachment.Status.VPC = "1n"
	attachment.Status.VPCAttachment = "bQy"
	identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)

	// Router names are chosen so the fabric one sorts first or last.
	galacticName, fabricName := "zz-overlay", "aa-underlay"
	if !fabricFirst {
		galacticName, fabricName = "aa-overlay", "zz-underlay"
	}
	galacticRouter := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: galacticName, Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: "node-a"}},
	}
	fabricRouter := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: fabricName, Namespace: bgpNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:       bgpv1alpha1.TargetRef{Kind: "Node", Name: "node-a"},
			RouterClassName: ptr.To("fabric-frr"),
			Plane:           ptr.To(bgpv1alpha1.BGPRoutingPlaneUnderlay),
		},
	}
	advertised := metav1.Condition{Type: galactic.ConditionAdvertised, Status: metav1.ConditionTrue, Reason: "Advertised"}
	tenantAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-a", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: galacticName}},
	}
	meta.SetStatusCondition(&tenantAdv.Status.Conditions, advertised)
	// The fabric advertisement's name is built the same way, so only the
	// router's class can keep it out of the projection.
	fabricAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-b", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: fabricName}},
	}
	meta.SetStatusCondition(&fabricAdv.Status.Conditions, advertised)

	iface := &networkingv1alpha.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	iface.Spec.ClaimRef = &networkingv1alpha.NetworkInterfaceClaimRef{Name: "claim"}
	iface.Status.AttachmentRef = &networkingv1alpha.NetworkInterfaceAttachmentRef{
		APIGroup: cloudv1alpha1.GroupVersion.Group, Kind: "VPCAttachment", Name: "nic",
	}
	claim := &networkingv1alpha.NetworkInterfaceClaim{ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "tenant"}}

	objects := []client.Object{attachment, iface, claim, galacticRouter, fabricRouter, tenantAdv, fabricAdv}
	if fabricFirst {
		objects = []client.Object{attachment, iface, claim, fabricRouter, galacticRouter, fabricAdv, tenantAdv}
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(attachment, iface, claim, tenantAdv, fabricAdv).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, IndexBGPAdvertisementIdentity, BGPAdvertisementIdentity).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, IndexVPCAttachmentIdentity, func(obj client.Object) []string {
			a := obj.(*cloudv1alpha1.VPCAttachment)
			return []string{galactic.AdvertisementName(a.Status.VPC, a.Status.VPCAttachment)}
		}).
		WithObjects(objects...).Build()
	return &ownershipFixture{
		client: cl, reconciler: &BGPAdvertisementReconciler{Client: cl},
		attachment: attachment, iface: iface, tenantAdv: tenantAdv, fabricAdv: fabricAdv,
	}
}

func (f *ownershipFixture) reconcile(t *testing.T, adv *bgpv1alpha1.BGPAdvertisement) {
	t.Helper()
	if _, err := f.reconciler.Reconcile(context.Background(), ctrlreconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: adv.Namespace, Name: adv.Name},
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *ownershipFixture) attachmentStatus(t *testing.T) cloudv1alpha1.VPCAttachmentStatus {
	t.Helper()
	var got cloudv1alpha1.VPCAttachment
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.attachment), &got); err != nil {
		t.Fatal(err)
	}
	return got.Status
}

// TestFabricAdvertisementNeverProjects: an advertisement on a fabric-class
// router whose name decodes to a tenant attachment writes nothing to the
// attachment, interface or claim, whatever the router and object order.
func TestFabricAdvertisementNeverProjects(t *testing.T) {
	for _, fabricFirst := range []bool{true, false} {
		f := newOwnershipFixture(t, fabricFirst)
		f.reconcile(t, f.fabricAdv)
		status := f.attachmentStatus(t)
		if status.Node != "" || meta.FindStatusCondition(status.Conditions, cloudv1alpha1.ConditionTypeProgrammed) != nil {
			t.Errorf("fabricFirst=%v: fabric advertisement projected onto the attachment: %+v", fabricFirst, status)
		}
		var iface networkingv1alpha.NetworkInterface
		if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.iface), &iface); err != nil {
			t.Fatal(err)
		}
		if c := meta.FindStatusCondition(iface.Status.Conditions, networkingv1alpha.NetworkInterfaceProgrammed); c != nil {
			t.Errorf("fabricFirst=%v: fabric advertisement certified the interface: %+v", fabricFirst, c)
		}
	}
}

// TestTenantAdvertisementStillProjects: a tenant advertisement on the
// Galactic router next to a fabric router on the same node projects as
// before, with the Galactic router's node.
func TestTenantAdvertisementStillProjects(t *testing.T) {
	for _, fabricFirst := range []bool{true, false} {
		f := newOwnershipFixture(t, fabricFirst)
		f.reconcile(t, f.tenantAdv)
		status := f.attachmentStatus(t)
		if status.Node != "node-a" {
			t.Errorf("fabricFirst=%v: attachment node = %q, want node-a", fabricFirst, status.Node)
		}
		c := meta.FindStatusCondition(status.Conditions, cloudv1alpha1.ConditionTypeProgrammed)
		if c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("fabricFirst=%v: attachment Programmed = %+v, want True", fabricFirst, c)
		}
	}
}

// TestReplayExcludesFabricAdvertisements: the replay on an interface
// switching to the Galactic group enqueues the tenant advertisement only.
func TestReplayExcludesFabricAdvertisements(t *testing.T) {
	for _, fabricFirst := range []bool{true, false} {
		f := newOwnershipFixture(t, fabricFirst)
		requests := f.reconciler.advertisementForInterface(context.Background(), f.iface)
		if len(requests) != 1 || requests[0].Name != f.tenantAdv.Name {
			t.Errorf("fabricFirst=%v: replay requests = %+v, want only %s", fabricFirst, requests, f.tenantAdv.Name)
		}
	}
}
