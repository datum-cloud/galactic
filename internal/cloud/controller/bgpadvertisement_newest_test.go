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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

func (f *ownershipFixture) setCreated(t *testing.T, adv *bgpv1alpha1.BGPAdvertisement, ts metav1.Time) {
	t.Helper()
	var live bgpv1alpha1.BGPAdvertisement
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(adv), &live); err != nil {
		t.Fatal(err)
	}
	live.CreationTimestamp = ts
	if err := f.client.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
}

func (f *ownershipFixture) addSibling(
	t *testing.T, node string, created metav1.Time,
) *bgpv1alpha1.BGPAdvertisement {
	t.Helper()
	ctx := context.Background()
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: node + "-overlay", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: node}},
	}
	if err := f.client.Create(ctx, router); err != nil {
		t.Fatal(err)
	}
	identity := galactic.AdvertisementName(f.attachment.Status.VPC, f.attachment.Status.VPCAttachment)
	sibling := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: identity + "-" + node, Namespace: bgpNamespace, CreationTimestamp: created},
		Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router.Name}},
		Status:     f.tenantAdv.Status,
	}
	if err := f.client.Create(ctx, sibling); err != nil {
		t.Fatal(err)
	}
	return sibling
}

// TestCoexistingAdvertisementsProjectNewest: while two nodes advertise one
// attachment, its status names the newer advertisement's node whichever
// order they reconcile in.
func TestCoexistingAdvertisementsProjectNewest(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC))
	for _, c := range []struct {
		name        string
		tenantAt    metav1.Time
		siblingAt   metav1.Time
		siblingNode string
		want        string
	}{
		{"sibling newer", t0, metav1.NewTime(t0.Add(time.Minute)), "node-c", "node-c"},
		{"sibling older", metav1.NewTime(t0.Add(time.Minute)), t0, "node-c", "node-a"},
		{"same second, name decides", t0, t0, "node-0", "node-a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, siblingFirst := range []bool{true, false} {
				f := newOwnershipFixture(t, false)
				f.setCreated(t, f.tenantAdv, c.tenantAt)
				sibling := f.addSibling(t, c.siblingNode, c.siblingAt)
				order := []*bgpv1alpha1.BGPAdvertisement{f.tenantAdv, sibling}
				if siblingFirst {
					order = []*bgpv1alpha1.BGPAdvertisement{sibling, f.tenantAdv}
				}
				for _, adv := range order {
					f.reconcile(t, adv)
					f.reconcile(t, adv)
				}
				for _, adv := range order {
					f.reconcile(t, adv)
				}
				if got := f.attachmentStatus(t).Node; got != c.want {
					t.Errorf("siblingFirst=%v: attachment node = %q, want %q", siblingFirst, got, c.want)
				}
			}
		})
	}
}

// TestFabricSiblingNeverSupersedes: a newer advertisement on a fabric-class
// router never keeps a tenant advertisement from projecting.
func TestFabricSiblingNeverSupersedes(t *testing.T) {
	f := newOwnershipFixture(t, false)
	t0 := metav1.NewTime(time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC))
	f.setCreated(t, f.tenantAdv, t0)
	f.setCreated(t, f.fabricAdv, metav1.NewTime(t0.Add(time.Minute)))
	f.reconcile(t, f.tenantAdv)
	if got := f.attachmentStatus(t).Node; got != "node-a" {
		t.Fatalf("attachment node = %q, want node-a", got)
	}
}
