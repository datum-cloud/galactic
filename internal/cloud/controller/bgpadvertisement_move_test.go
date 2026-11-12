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
	"go.datum.net/galactic/internal/crdnames"
)

// movedFixture adds a second Galactic router on node-c and an advertisement
// there for the same attachment, as a recreated instance that moved from
// node-a leaves until node-a's teardown withdraws the old one.
func movedFixture(t *testing.T, oldAdd, newAdd time.Time) (*ownershipFixture, *bgpv1alpha1.BGPAdvertisement) {
	t.Helper()
	f := newOwnershipFixture(t, false)
	ctx := context.Background()
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "node-c-overlay", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: "node-c"}},
	}
	if err := f.client.Create(ctx, router); err != nil {
		t.Fatal(err)
	}
	stampLastAdd(t, f, f.tenantAdv, oldAdd)
	identity := galactic.AdvertisementName(f.attachment.Status.VPC, f.attachment.Status.VPCAttachment)
	moved := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: identity + "-node-c", Namespace: bgpNamespace,
			Annotations: map[string]string{galactic.AnnotationLastAdd: newAdd.UTC().Format(time.RFC3339Nano)},
		},
		Spec:   bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router.Name}},
		Status: f.tenantAdv.Status,
	}
	if err := f.client.Create(ctx, moved); err != nil {
		t.Fatal(err)
	}
	return f, moved
}

func stampLastAdd(t *testing.T, f *ownershipFixture, adv *bgpv1alpha1.BGPAdvertisement, at time.Time) {
	t.Helper()
	var live bgpv1alpha1.BGPAdvertisement
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(adv), &live); err != nil {
		t.Fatal(err)
	}
	if live.Annotations == nil {
		live.Annotations = map[string]string{}
	}
	live.Annotations[galactic.AnnotationLastAdd] = at.UTC().Format(time.RFC3339Nano)
	if err := f.client.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
}

// TestMovedInstanceStatusFollowsNewestAdvertisement: while both nodes hold an
// advertisement for a moved instance, the attachment keeps the node of the
// one published last, whichever order they are reconciled in, so its routes
// stop flipping between nodes.
func TestMovedInstanceStatusFollowsNewestAdvertisement(t *testing.T) {
	now := time.Now()
	f, moved := movedFixture(t, now.Add(-time.Minute), now)
	for range 3 {
		for _, adv := range []*bgpv1alpha1.BGPAdvertisement{moved, f.tenantAdv} {
			f.reconcile(t, adv)
			if got := f.attachmentStatus(t).Node; got != "node-c" {
				t.Fatalf("after reconciling %s, attachment node = %q, want node-c", adv.Name, got)
			}
		}
	}
}

// TestInstanceMovedBackRetakesStatus: a new ADD on the old node makes its
// advertisement the newest again, so the instance moving back is followed.
func TestInstanceMovedBackRetakesStatus(t *testing.T) {
	now := time.Now()
	f, moved := movedFixture(t, now.Add(-time.Minute), now)
	f.reconcile(t, moved)
	stampLastAdd(t, f, f.tenantAdv, now.Add(time.Minute))
	f.reconcile(t, moved)
	f.reconcile(t, f.tenantAdv)
	if got := f.attachmentStatus(t).Node; got != "node-a" {
		t.Fatalf("attachment node = %q, want node-a", got)
	}
}

// TestWithdrawnNewestHandsStatusToSurvivor: when the newest advertisement is
// withdrawn while an older one remains, the survivor projects at once instead
// of leaving the attachment on a node with no advertisement.
func TestWithdrawnNewestHandsStatusToSurvivor(t *testing.T) {
	now := time.Now()
	f, moved := movedFixture(t, now.Add(-time.Minute), now)
	f.reconcile(t, moved)
	if err := f.client.Delete(context.Background(), moved); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, moved)
	if got := f.attachmentStatus(t).Node; got != "node-a" {
		t.Fatalf("attachment node = %q, want node-a", got)
	}
}

// TestNewerAdvertisementOrdering covers the order between advertisements the
// fixture cannot build: one being deleted, and ones published before
// AnnotationLastAdd existed.
func TestNewerAdvertisementOrdering(t *testing.T) {
	if crdnames.AnnotationLastAdd != galactic.AnnotationLastAdd {
		t.Fatalf("CNI writes %q but the controller reads %q", crdnames.AnnotationLastAdd, galactic.AnnotationLastAdd)
	}
	at := func(name string, created time.Time, add string) *bgpv1alpha1.BGPAdvertisement {
		adv := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
			Name: name, CreationTimestamp: metav1.NewTime(created),
		}}
		if add != "" {
			adv.Annotations = map[string]string{galactic.AnnotationLastAdd: add}
		}
		return adv
	}
	t0 := time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Second)
	cases := []struct {
		name string
		a, b *bgpv1alpha1.BGPAdvertisement
		want bool
	}{
		{"later ADD wins", at("x", t0, t1.Format(time.RFC3339Nano)), at("y", t1, t0.Format(time.RFC3339Nano)), true},
		{"earlier ADD loses", at("x", t1, t0.Format(time.RFC3339Nano)), at("y", t0, t1.Format(time.RFC3339Nano)), false},
		{"no annotation falls back to creation", at("x", t1, ""), at("y", t0, ""), true},
		{"unparsable annotation counts as unstamped", at("x", t0, "garbage"), at("y", t1, ""), false},
		{"tie broken by name", at("y", t0, ""), at("x", t0, ""), true},
		{"stamped beats unstamped created later", at("x", t0, t0.Format(time.RFC3339Nano)), at("y", t1, ""), true},
		{"unstamped loses to stamped", at("x", t1, ""), at("y", t0, t0.Format(time.RFC3339Nano)), false},
	}
	for _, tc := range cases {
		if got := newerAdvertisement(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: newerAdvertisement = %v, want %v", tc.name, got, tc.want)
		}
	}
	deleting := at("x", t1, t1.Format(time.RFC3339Nano))
	deleting.DeletionTimestamp = ptrTime(t1)
	live := at("y", t0, t0.Format(time.RFC3339Nano))
	if newerAdvertisement(deleting, live) || !newerAdvertisement(live, deleting) {
		t.Error("an advertisement being deleted must lose to a live one")
	}
}

func ptrTime(t time.Time) *metav1.Time {
	v := metav1.NewTime(t)
	return &v
}
