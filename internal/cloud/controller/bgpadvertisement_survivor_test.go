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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

// TestWithdrawnNodeHandsStatusToSurvivor: when the advertisement the
// attachment's status names is withdrawn while another node's remains, the
// survivor projects at once instead of leaving the status on a node with no
// advertisement.
func TestWithdrawnNodeHandsStatusToSurvivor(t *testing.T) {
	f := newOwnershipFixture(t, false)
	ctx := context.Background()
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "node-c-overlay", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: "node-c"}},
	}
	if err := f.client.Create(ctx, router); err != nil {
		t.Fatal(err)
	}
	identity := galactic.AdvertisementName(f.attachment.Status.VPC, f.attachment.Status.VPCAttachment)
	other := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-c", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router.Name}},
		Status:     f.tenantAdv.Status,
	}
	if err := f.client.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, other)
	f.reconcile(t, f.tenantAdv)
	if got := f.attachmentStatus(t).Node; got != "node-a" {
		t.Fatalf("attachment node = %q, want node-a", got)
	}
	if err := f.client.Delete(ctx, f.tenantAdv); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, f.tenantAdv)
	if got := f.attachmentStatus(t).Node; got != "node-c" {
		t.Fatalf("attachment node = %q, want node-c", got)
	}
}
