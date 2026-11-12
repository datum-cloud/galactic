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
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	"go.datum.net/galactic/internal/crdnames"
)

// movedFixture adds a Galactic router on node-c and an advertisement there
// for the same attachment, as an instance recreated on node-c leaves while
// node-a's advertisement waits for node-a's GC.
func movedFixture(t *testing.T) (*ownershipFixture, *bgpv1alpha1.BGPAdvertisement) {
	t.Helper()
	if crdnames.AnnotationReplacedBy != galactic.AnnotationReplacedBy {
		t.Fatalf("CNI writes %q but the controller reads %q", crdnames.AnnotationReplacedBy, galactic.AnnotationReplacedBy)
	}
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
	moved := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: identity + "-node-c", Namespace: bgpNamespace},
		Spec:       bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router.Name}},
		Status:     f.tenantAdv.Status,
	}
	if err := f.client.Create(ctx, moved); err != nil {
		t.Fatal(err)
	}
	return f, moved
}

// setReplacedBy marks adv replaced by node, or clears the mark when node is
// empty, as a CNI ADD does.
func setReplacedBy(t *testing.T, f *ownershipFixture, adv *bgpv1alpha1.BGPAdvertisement, node string) {
	t.Helper()
	var live bgpv1alpha1.BGPAdvertisement
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(adv), &live); err != nil {
		t.Fatal(err)
	}
	if live.Annotations == nil {
		live.Annotations = map[string]string{}
	}
	if node == "" {
		delete(live.Annotations, galactic.AnnotationReplacedBy)
	} else {
		live.Annotations[galactic.AnnotationReplacedBy] = node
	}
	if err := f.client.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
}

func wantNode(t *testing.T, f *ownershipFixture, want string) {
	t.Helper()
	if got := f.attachmentStatus(t).Node; got != want {
		t.Fatalf("attachment node = %q, want %q", got, want)
	}
}

// TestReplacedAdvertisementNeverProjects: once node-c's ADD marks node-a's
// advertisement replaced, the attachment stays on node-c whatever order the
// two are reconciled in, so its routes stop flipping between nodes.
func TestReplacedAdvertisementNeverProjects(t *testing.T) {
	f, moved := movedFixture(t)
	setReplacedBy(t, f, f.tenantAdv, "node-c")
	for range 3 {
		for _, adv := range []*bgpv1alpha1.BGPAdvertisement{moved, f.tenantAdv} {
			f.reconcile(t, adv)
			wantNode(t, f, "node-c")
		}
	}
}

// TestMarkAfterOldWriteHandsOver: node-a's advertisement wrote last before
// the mark landed, so its own next pass hands the attachment to node-c.
func TestMarkAfterOldWriteHandsOver(t *testing.T) {
	f, moved := movedFixture(t)
	f.reconcile(t, moved)
	f.reconcile(t, f.tenantAdv)
	wantNode(t, f, "node-a")
	setReplacedBy(t, f, f.tenantAdv, "node-c")
	f.reconcile(t, f.tenantAdv)
	wantNode(t, f, "node-c")
}

// TestInstanceMovedBackRetakesStatus: an ADD back on node-a clears its own
// mark and marks node-c's, so the attachment follows it back.
func TestInstanceMovedBackRetakesStatus(t *testing.T) {
	f, moved := movedFixture(t)
	setReplacedBy(t, f, f.tenantAdv, "node-c")
	f.reconcile(t, moved)
	setReplacedBy(t, f, f.tenantAdv, "")
	setReplacedBy(t, f, moved, "node-a")
	f.reconcile(t, moved)
	f.reconcile(t, f.tenantAdv)
	wantNode(t, f, "node-a")
}

// TestWithdrawnCurrentWithOnlyReplacedLeftClears: when the current
// advertisement is withdrawn and only a replaced one remains, as when the
// instance stopped after moving off a node that is down, the status is
// cleared rather than handed back to the node the instance left.
func TestWithdrawnCurrentWithOnlyReplacedLeftClears(t *testing.T) {
	f, moved := movedFixture(t)
	setReplacedBy(t, f, f.tenantAdv, "node-c")
	f.reconcile(t, moved)
	wantNode(t, f, "node-c")
	if err := f.client.Delete(context.Background(), moved); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, moved)
	wantNode(t, f, "")
}

// TestHandOverWithoutOldRouter: the replaced advertisement wrote last and its
// node's router is gone; its next pass still hands the attachment over.
func TestHandOverWithoutOldRouter(t *testing.T) {
	f, moved := movedFixture(t)
	f.reconcile(t, moved)
	f.reconcile(t, f.tenantAdv)
	wantNode(t, f, "node-a")
	var router bgpv1alpha1.BGPRouter
	if err := f.client.Get(context.Background(),
		client.ObjectKey{Namespace: bgpNamespace, Name: f.tenantAdv.Spec.RouterRef.Name}, &router); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(context.Background(), &router); err != nil {
		t.Fatal(err)
	}
	setReplacedBy(t, f, f.tenantAdv, "node-c")
	f.reconcile(t, f.tenantAdv)
	wantNode(t, f, "node-c")
}

// TestWithdrawnCurrentHandsOverToUnreplaced: a withdrawn current
// advertisement hands the attachment to a remaining one that was not
// replaced, at once.
func TestWithdrawnCurrentHandsOverToUnreplaced(t *testing.T) {
	f, moved := movedFixture(t)
	f.reconcile(t, moved)
	if err := f.client.Delete(context.Background(), moved); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, moved)
	wantNode(t, f, "node-a")
}
