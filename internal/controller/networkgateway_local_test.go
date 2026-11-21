// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/gateway/localhandoff"
)

type fakeLocalHandoff struct {
	set  []localhandoff.Backend
	snap localhandoff.Snapshot
}

func (f *fakeLocalHandoff) SetBackends(b []localhandoff.Backend) { f.set = b }
func (f *fakeLocalHandoff) Snapshot() localhandoff.Snapshot      { return f.snap }

// TestLocalBackendsTakesOwnNodeOnce: only this node's backends are handed to
// the Local handoff, once each however many rules name them.
func TestLocalBackendsTakesOwnNodeOnce(t *testing.T) {
	own := gateway.PlacedBackend{Node: testNodeGWA, AttachmentUID: "a", VPC: "v", Slot: 7,
		USID: netip.MustParseAddr("2001:db8::7")}
	other := gateway.PlacedBackend{Node: testNodeGWB, AttachmentUID: "b", VPC: "v", Slot: 8,
		USID: netip.MustParseAddr("2001:db8::8")}
	desired := gateway.EngineState{Rules: map[string]gateway.DesiredRule{
		"ns/r1": {PlacedBackends: []gateway.PlacedBackend{own, other}},
		"ns/r2": {PlacedBackends: []gateway.PlacedBackend{own}},
	}}
	got := localBackends(testNodeGWA, desired)
	if len(got) != 1 || got[0] != (localhandoff.Backend{AttachmentUID: "a", VPC: "v", Slot: 7, USID: own.USID}) {
		t.Errorf("local backends = %+v, want only node %s's, once", got, testNodeGWA)
	}
}

// TestStampStatusPublishesLocalBackends: the gateway publishes each local
// backend's readiness and a LocalHandoff condition naming the ones not ready.
func TestStampStatusPublishesLocalBackends(t *testing.T) {
	scheme := newRuleTestScheme(t)
	r := newGatewayReconciler(newIndexedClientBuilder(scheme).Build(), scheme, nil, testNodeGWA)
	lh := &fakeLocalHandoff{snap: localhandoff.Snapshot{SessionUp: true, Attachments: []localhandoff.AttachmentState{
		{AttachmentUID: "a", Ready: true, Reason: bgpv1alpha1.LocalBackendReasonReady},
		{AttachmentUID: "b", Ready: false, Reason: "HandoffHookMissing"},
	}}}
	r.LocalHandoff = lh
	gw := &bgpv1alpha1.NetworkGateway{}
	r.stampStatus(gw)
	if len(gw.Status.LocalBackends) != 2 || !gw.Status.LocalBackends[0].Ready || gw.Status.LocalBackends[1].Ready ||
		gw.Status.LocalBackends[1].Reason != "HandoffHookMissing" {
		t.Errorf("localBackends = %+v", gw.Status.LocalBackends)
	}
	c := meta.FindStatusCondition(gw.Status.Conditions, ConditionTypeLocalHandoff)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonLocalHandoffNotReady ||
		!strings.Contains(c.Message, "b (HandoffHookMissing)") {
		t.Errorf("LocalHandoff condition = %+v", c)
	}

	lh.snap.Attachments = lh.snap.Attachments[:1]
	r.stampStatus(gw)
	if c := meta.FindStatusCondition(gw.Status.Conditions, ConditionTypeLocalHandoff); c == nil ||
		c.Status != metav1.ConditionTrue || c.Reason != reasonLocalHandoffReady {
		t.Errorf("LocalHandoff condition = %+v, want Ready", c)
	}

	r.LocalHandoff = nil
	r.stampStatus(gw)
	if gw.Status.LocalBackends != nil {
		t.Errorf("localBackends = %+v, want none without the Worker integration", gw.Status.LocalBackends)
	}
}

// TestApplyBGPAdvertisements_WithdrawsUncoveredFamily (D44): a family the
// public path does not cover is withdrawn from this node, the other family
// stays advertised, and coverage coming back advertises it again.
func TestApplyBGPAdvertisements_WithdrawsUncoveredFamily(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	rule.UID = testRuleUID
	v6 := newNodeAdvertisement(testRuleName, testNodeGWA, "v6")
	v4 := newNodeAdvertisement(testRuleName, testNodeGWA, "v4")
	c := newIndexedClientBuilder(scheme).WithObjects(rule, v6, v4).Build()
	ctx := context.Background()
	r := newGatewayReconciler(c, scheme, nil, testNodeGWA)
	pp := PublicPathState{IPv6: "bond member eth3 has no XDP coverage"}
	r.PublicPath = func() PublicPathState { return pp }
	desired := gateway.DesiredRule{VIPAddresses: []netip.Addr{netip.MustParseAddr(testVIP),
		netip.MustParseAddr(testVIP4)}}

	if err := r.applyBGPAdvertisements(ctx, testNamespace, rule, desired, testRouterName, true); err != nil {
		t.Fatalf("applyBGPAdvertisements: %v", err)
	}
	if err := c.Get(ctx, testRuleKey(v6.Name), &bgpv1alpha1.BGPAdvertisement{}); !apierrors.IsNotFound(err) {
		t.Errorf("-v6 advertisement: err = %v, want withdrawn", err)
	}
	if err := c.Get(ctx, testRuleKey(v4.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("-v4 advertisement: %v, want kept", err)
	}
	if pending, err := r.uninstalledAdvertisements(ctx, testNamespace, rule, desired, true); err != nil ||
		len(pending) != 1 || pending[0] != v4.Name {
		t.Errorf("pending = %v, %v; want only the -v4 one awaited", pending, err)
	}

	pp = PublicPathState{IPv4: "no public uplink row"}
	if err := r.applyBGPAdvertisements(ctx, testNamespace, rule, desired, testRouterName, true); err != nil {
		t.Fatalf("applyBGPAdvertisements: %v", err)
	}
	if err := c.Get(ctx, testRuleKey(v6.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("-v6 advertisement: %v, want advertised again", err)
	}
	if err := c.Get(ctx, testRuleKey(v4.Name), &bgpv1alpha1.BGPAdvertisement{}); !apierrors.IsNotFound(err) {
		t.Errorf("-v4 advertisement: err = %v, want withdrawn", err)
	}
}

// TestWithdrawnFamiliesCondition: the Advertised condition says which family
// is withdrawn, is False when every family is, and reports a covering
// aggregate without suppressing it.
func TestWithdrawnFamiliesCondition(t *testing.T) {
	advertised := metav1.Condition{Status: metav1.ConditionTrue, Reason: reasonAdvertised, Message: "advertised"}
	dual := []netip.Addr{netip.MustParseAddr(testVIP), netip.MustParseAddr(testVIP4)}

	got := withdrawnFamilies(advertised, testNodeGWA, dual, PublicPathState{IPv6: "uncovered"}, nil)
	if got.Status != metav1.ConditionTrue || !strings.Contains(got.Message, "IPv6 (uncovered)") {
		t.Errorf("one family withdrawn: %+v", got)
	}
	got = withdrawnFamilies(advertised, testNodeGWA, dual, PublicPathState{IPv6: "x", IPv4: "y"}, nil)
	if got.Status != metav1.ConditionFalse || got.Reason != ReasonFamilyWithdrawn {
		t.Errorf("every family withdrawn: %+v", got)
	}
	got = withdrawnFamilies(advertised, testNodeGWA, dual[:1], PublicPathState{IPv6: "x"}, []string{"agg"})
	if got.Status != metav1.ConditionFalse || got.Reason != ReasonAggregateStillAttracts ||
		!strings.Contains(got.Message, "agg") {
		t.Errorf("aggregate: %+v", got)
	}
	if got := withdrawnFamilies(advertised, testNodeGWA, dual[:1], PublicPathState{IPv4: "y"}, nil); got != advertised {
		t.Errorf("a family the rule lacks changed the condition: %+v", got)
	}
}

// TestCoveringAggregates finds an aggregate of this node's router covering a
// withdrawn VIP, and ignores host routes, rule advertisements, other routers
// and covered families.
func TestCoveringAggregates(t *testing.T) {
	scheme := newRuleTestScheme(t)
	mk := func(name, router string, prefixes ...string) *bgpv1alpha1.BGPAdvertisement {
		a := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router}}}
		for _, p := range prefixes {
			a.Spec.Prefixes = append(a.Spec.Prefixes, bgpv1alpha1.Prefix(p))
		}
		return a
	}
	ruleAdv := newNodeAdvertisement(testRuleName, testNodeGWA, "v6")
	ruleAdv.Spec.RouterRef.Name = testRouterName
	ruleAdv.Spec.Prefixes = []bgpv1alpha1.Prefix{"2001:db8:5::/48"}
	c := newIndexedClientBuilder(scheme).WithObjects(
		mk("agg", testRouterName, "2001:db8:5::/48"),
		mk("host", testRouterName, testVIP+"/128"),
		mk("other-router", "router-b", "2001:db8::/32"),
		mk("v4-agg", testRouterName, "203.0.113.0/24"),
		ruleAdv,
	).Build()
	r := newGatewayReconciler(c, scheme, nil, testNodeGWA)
	vips := []netip.Addr{netip.MustParseAddr(testVIP)}

	got, err := r.coveringAggregates(context.Background(), testNamespace, testRouterName, vips,
		PublicPathState{IPv6: "x"})
	if err != nil || len(got) != 1 || got[0] != "agg" {
		t.Errorf("aggregates = %v, %v; want [agg]", got, err)
	}
	if got, _ := r.coveringAggregates(context.Background(), testNamespace, testRouterName, vips,
		PublicPathState{IPv4: "x"}); len(got) != 0 {
		t.Errorf("aggregates for a covered family = %v, want none", got)
	}
}
