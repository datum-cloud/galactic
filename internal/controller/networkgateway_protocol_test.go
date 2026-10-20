// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestNetworkGatewayReconciler_RefusesUnservedRule covers a rule admission
// would refuse but a controller can still read, for example one stored under
// a schema that admitted it: a protocol the datapath does not serve, or an
// unset port. A rule that was serving is unloaded and withdrawn, never loaded
// on port 0, and its Programmed condition says why.
func TestNetworkGatewayReconciler_RefusesUnservedRule(t *testing.T) {
	tests := []struct {
		name        string
		edit        func(*bgpv1alpha1.NetworkService)
		wantReason  string
		wantMessage string
	}{
		{
			name: "portless protocol",
			edit: func(rule *bgpv1alpha1.NetworkService) {
				rule.Spec.Protocol = bgpv1alpha1.NetworkServiceProtocolESP
				rule.Spec.Port, rule.Spec.BackendPort = 0, 0
			},
			wantReason:  reasonUnservedProtocol,
			wantMessage: `protocol "esp" is not served`,
		},
		{
			name: "protocol with ports",
			edit: func(rule *bgpv1alpha1.NetworkService) {
				rule.Spec.Protocol = bgpv1alpha1.NetworkServiceProtocolSCTP
			},
			wantReason:  reasonUnservedProtocol,
			wantMessage: `protocol "sctp" is not served`,
		},
		{
			name: "unrecognised protocol",
			edit: func(rule *bgpv1alpha1.NetworkService) {
				rule.Spec.Protocol = "quic"
			},
			wantReason:  reasonUnservedProtocol,
			wantMessage: `protocol "quic" is not served`,
		},
		{
			name:        "unset port",
			edit:        func(rule *bgpv1alpha1.NetworkService) { rule.Spec.Port = 0 },
			wantReason:  reasonInvalidRule,
			wantMessage: "port 0 is outside 1-65535",
		},
		{
			name:        "unset backend port",
			edit:        func(rule *bgpv1alpha1.NetworkService) { rule.Spec.BackendPort = 0 },
			wantReason:  reasonInvalidRule,
			wantMessage: "backendPort 0 is outside 1-65535",
		},
		{
			name:        "backend port out of range",
			edit:        func(rule *bgpv1alpha1.NetworkService) { rule.Spec.BackendPort = 70000 },
			wantReason:  reasonInvalidRule,
			wantMessage: "backendPort 70000 is outside 1-65535",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
			rule := newTestRule(testRuleName, "vpc-1", testVIP)
			acceptRule(rule)
			fakeClient := newIndexedClientBuilder(scheme).
				WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
				WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
					newBackendAttachment("vpc-1"), rule).
				Build()
			ctx := context.Background()
			engine := newFakeGatewayEngine()
			r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
			reconcile := func() {
				t.Helper()
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
					t.Fatalf("Reconcile: %v", err)
				}
			}

			reconcile()
			if _, loaded := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]; !loaded {
				t.Fatal("valid rule not loaded")
			}
			if err := fakeClient.Get(ctx, testRuleKey(testRuleAdv), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
				t.Fatalf("valid rule's advertisement: %v", err)
			}

			current := &bgpv1alpha1.NetworkService{}
			if err := fakeClient.Get(ctx, testRuleKey(testRuleName), current); err != nil {
				t.Fatal(err)
			}
			tt.edit(current)
			if err := fakeClient.Update(ctx, current); err != nil {
				t.Fatalf("update rule: %v", err)
			}
			reconcile()

			if desired, loaded := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]; loaded {
				t.Errorf("rule loaded as %+v, want it unloaded", desired)
			}
			err := fakeClient.Get(ctx, testRuleKey(testRuleAdv), &bgpv1alpha1.BGPAdvertisement{})
			if !apierrors.IsNotFound(err) {
				t.Errorf("advertisement: err = %v, want NotFound", err)
			}
			got := &bgpv1alpha1.NetworkService{}
			if err := fakeClient.Get(ctx, testRuleKey(testRuleName), got); err != nil {
				t.Fatal(err)
			}
			programmed := meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWA))
			if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != tt.wantReason ||
				!strings.Contains(programmed.Message, tt.wantMessage) {
				t.Errorf("Programmed = %+v, want False/%s naming %q", programmed, tt.wantReason, tt.wantMessage)
			}
		})
	}
}
