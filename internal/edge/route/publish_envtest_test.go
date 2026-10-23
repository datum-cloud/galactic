// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	"go.datum.net/galactic/internal/crdnames"
)

// TestPublication: an accepted route is published into its VPC's VRF on the
// holder's node, names the holder's host link and address for the node's
// gate check, follows a takeover in place, and is withdrawn when its holder
// may no longer forward or the route is gone. Published reports the
// router's own report on the advertisement, and the attachment's Published
// follows its routes.
func TestPublication(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.vrf(nodeA, "router-a", 5)
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.expectAccepted("r", a, 1)
	if reason := f.published("r"); reason != ReasonNotProgrammed {
		t.Fatalf("published before the node reported the host link: %s", reason)
	}

	f.hostLink(a, "gea")
	f.reconcile("r")
	adv := f.advertisement("r")
	if adv == nil {
		t.Fatal("accepted route not published")
	}
	if adv.Spec.RouterRef.Name != "router-a" || *adv.Spec.VRFID != 5 || len(adv.Spec.Prefixes) != 1 ||
		string(adv.Spec.Prefixes[0]) != prefixA || string(adv.Spec.Communities[0]) != "65000:171" ||
		adv.Labels[crdnames.LabelEdgeEpoch] != "1" || adv.Annotations[crdnames.AnnotationEdgeHostLink] != "gea" ||
		adv.Annotations[crdnames.AnnotationEdgeAddress] != "fd00:10:0:e::1" {
		t.Fatalf("published advertisement %+v %+v %+v", adv.Labels, adv.Annotations, adv.Spec)
	}
	if reason := f.published("r"); reason != ReasonAwaitingRouter {
		t.Fatalf("published before the router reported: %s", reason)
	}
	f.routerReports(adv, metav1.ConditionFalse, "GateClosed")
	f.reconcile("r")
	if reason := f.published("r"); reason != "GateClosed" {
		t.Fatalf("published with the gate closed: %s", reason)
	}
	f.routerReports(f.advertisement("r"), metav1.ConditionTrue, "Advertised")
	f.reconcile("r")
	if reason := f.published("r"); reason != ReasonPublished {
		t.Fatalf("router advertises: %s", reason)
	}
	pub := &PublicationReconciler{Client: f.admin}
	f.reconcilePublication(pub, a)
	f.expectAttachmentPublished(a, metav1.ConditionTrue)

	// An unrelated route's advertisement, and one left by an earlier
	// object of r's name, are told apart.
	f.newRoute("u", "fd00:10:0:f:1::/80")
	f.claim("u", a)
	f.reconcile("u")
	unrelated := f.advertisement("u")
	if unrelated == nil || f.published("u") != ReasonAwaitingRouter {
		t.Fatalf("second route not published: %s", f.published("u"))
	}
	stale := adv.DeepCopy()
	stale.ObjectMeta = metav1.ObjectMeta{Name: crdnames.EdgeAdvertisementName("00000000-0000-0000-0000-000000000000"),
		Namespace: bgpNamespace, Labels: adv.Labels, Annotations: adv.Annotations}
	stale.Status = bgpv1alpha1.BGPAdvertisementStatus{}
	f.create(stale)
	f.reconcile("r")
	if f.exists(stale.Name) {
		t.Fatal("an earlier object's advertisement survived")
	}

	// Takeover: the advertisement follows the new holder to its node, in
	// place.
	f.hostLink(b, "geb")
	f.vrf(nodeB, "router-b", 7)
	f.release("r")
	f.reconcile("r")
	if f.exists(adv.Name) {
		t.Fatal("released route still published")
	}
	f.closeEpoch("r")
	f.claim("r", b)
	f.reconcile("r")
	f.expectAccepted("r", b, 2)
	adv = f.advertisement("r")
	if adv == nil || adv.Spec.RouterRef.Name != "router-b" || *adv.Spec.VRFID != 7 ||
		adv.Labels[crdnames.LabelEdgeEpoch] != "2" || adv.Annotations[crdnames.AnnotationEdgeHostLink] != "geb" {
		t.Fatalf("advertisement after takeover %+v", adv)
	}
	f.reconcilePublication(pub, a)
	f.reconcilePublication(pub, b)
	f.expectAttachmentPublished(b, metav1.ConditionFalse)

	// Revocation withdraws; the unrelated route is untouched.
	f.update(f.svc, func(s *galacticv1alpha1.EdgeService) { s.Spec.Prefixes = []string{"fd00:10:0:f:1::/80"} })
	f.reconcile("r")
	if f.exists(adv.Name) {
		t.Fatal("revoked route still published")
	}
	if !f.exists(unrelated.Name) {
		t.Fatal("another route's advertisement withdrawn")
	}

	// A deleted route has its advertisement withdrawn.
	if err := f.admin.Delete(ctx, f.route("u")); err != nil {
		t.Fatal(err)
	}
	f.reconcile("u")
	if f.exists(unrelated.Name) {
		t.Fatal("deleted route still published")
	}

	// A pass that found the route gone, running after it was recreated,
	// leaves the new object's advertisement to the new object's pass.
	f.newRoute("u", "fd00:10:0:f:1::/80")
	recreated := unrelated.DeepCopy()
	recreated.ObjectMeta = metav1.ObjectMeta{Name: crdnames.EdgeAdvertisementName(string(f.route("u").UID)),
		Namespace: bgpNamespace, Annotations: unrelated.Annotations,
		Labels: map[string]string{crdnames.LabelEdgeRoute: string(f.route("u").UID)}}
	recreated.Status = bgpv1alpha1.BGPAdvertisementStatus{}
	f.create(recreated)
	leftover := recreated.DeepCopy()
	leftover.ObjectMeta = metav1.ObjectMeta{Name: unrelated.Name, Namespace: bgpNamespace,
		Annotations: unrelated.Annotations, Labels: unrelated.Labels}
	f.create(leftover)
	if err := f.routes.withdrawGone(ctx, client.ObjectKey{Namespace: providerNS, Name: "u"}); err != nil {
		t.Fatal(err)
	}
	if !f.exists(recreated.Name) || f.exists(leftover.Name) {
		t.Fatalf("withdrawing a gone route: recreated route's kept %t, earlier object's kept %t",
			f.exists(recreated.Name), f.exists(leftover.Name))
	}
}

// vrf creates the VPC's BGPVRFInstance on node, as the node's CNI does.
func (f *fixture) vrf(node, router string, vrfID int32) {
	f.t.Helper()
	rt := []bgpv1alpha1.RouteTarget{{Value: "65000:171"}}
	f.create(&bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(vpcID, node), Namespace: bgpNamespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: router}},
			VRFID:        vrfID, ImportRouteTargets: rt, ExportRouteTargets: rt,
		},
	})
}

// hostLink reports the attachment's host link, as galactic-edge does once it
// programmed it.
func (f *fixture) hostLink(h *podHolder, link string) {
	f.t.Helper()
	ctx := context.Background()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := f.admin.Get(ctx, client.ObjectKeyFromObject(h.att), h.att); err != nil {
			return err
		}
		h.att.Status.HostLink = link
		return f.admin.Status().Update(ctx, h.att)
	}); err != nil {
		f.t.Fatal(err)
	}
}

// routerReports writes the advertisement's Advertised condition as its
// router does.
func (f *fixture) routerReports(adv *bgpv1alpha1.BGPAdvertisement, status metav1.ConditionStatus, reason string) {
	f.t.Helper()
	adv.Status.ObservedGeneration = adv.Generation
	meta.SetStatusCondition(&adv.Status.Conditions, metav1.Condition{Type: galactic.ConditionAdvertised,
		Status: status, Reason: reason, Message: reason})
	if err := f.admin.Status().Update(context.Background(), adv); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) advertisement(route string) *bgpv1alpha1.BGPAdvertisement {
	f.t.Helper()
	rt := f.route(route)
	var adv bgpv1alpha1.BGPAdvertisement
	err := f.admin.Get(context.Background(),
		client.ObjectKey{Namespace: bgpNamespace, Name: crdnames.EdgeAdvertisementName(string(rt.UID))}, &adv)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &adv
}

func (f *fixture) exists(name string) bool {
	f.t.Helper()
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: bgpNamespace, Name: name},
		&bgpv1alpha1.BGPAdvertisement{})
	if err != nil && !apierrors.IsNotFound(err) {
		f.t.Fatal(err)
	}
	return err == nil
}

// published returns the reason of the route's Published condition.
func (f *fixture) published(name string) string {
	f.t.Helper()
	c := meta.FindStatusCondition(f.route(name).Status.Conditions, galacticv1alpha1.EdgeRoutePublished)
	if c == nil {
		return ""
	}
	return c.Reason
}

func (f *fixture) reconcilePublication(pub *PublicationReconciler, h *podHolder) {
	f.t.Helper()
	if _, err := pub.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: client.ObjectKeyFromObject(h.att)}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) expectAttachmentPublished(h *podHolder, status metav1.ConditionStatus) {
	f.t.Helper()
	if err := f.admin.Get(context.Background(), client.ObjectKeyFromObject(h.att), h.att); err != nil {
		f.t.Fatal(err)
	}
	c := meta.FindStatusCondition(h.att.Status.Conditions, galacticv1alpha1.EdgeAttachmentPublished)
	if c == nil || c.Status != status {
		f.t.Fatalf("attachment %s Published = %+v, want %s", h.att.Name, c, status)
	}
}
