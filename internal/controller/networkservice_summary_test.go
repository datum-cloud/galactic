// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// summaryGen is the rule generation the summary tests report against.
const summaryGen = 3

// testBackendNode is the backend node whose BackendsBound condition the
// summary tests write.
const testBackendNode = "compute-1"

// cond returns a condition of condType at summaryGen.
func cond(condType string, status metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: condType, Status: status, Reason: reason, ObservedGeneration: summaryGen}
}

// servingConditions returns the conditions of a rule every node in nodes
// loads and advertises, with its backends bound on testBackendNode.
func servingConditions(nodes ...string) []metav1.Condition {
	conds := make([]metav1.Condition, 0, 2+2*len(nodes))
	conds = append(conds,
		cond(bgpv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, reasonGatewayNodesRegistered),
		cond(backendsBoundConditionType(testBackendNode), metav1.ConditionTrue, reasonBindingsBound))
	for _, n := range nodes {
		conds = append(conds,
			cond(programmedConditionType(n), metav1.ConditionTrue, reasonProgrammed),
			cond(advertisedConditionType(n), metav1.ConditionTrue, reasonAdvertised))
	}
	return conds
}

// with returns conds with c set over any condition of the same type.
func with(conds []metav1.Condition, c ...metav1.Condition) []metav1.Condition {
	out := append([]metav1.Condition(nil), conds...)
	for _, x := range c {
		meta.SetStatusCondition(&out, x)
	}
	return out
}

// without returns conds without the condition of condType.
func without(conds []metav1.Condition, condType string) []metav1.Condition {
	out := append([]metav1.Condition(nil), conds...)
	meta.RemoveStatusCondition(&out, condType)
	return out
}

// TestSummaryConditions covers the rule-wide conditions a client reads to tell
// whether a rule serves, without reading NetworkGateway (#708).
func TestSummaryConditions(t *testing.T) {
	nodes := []string{testNodeGWA, testNodeGWB}
	serving := servingConditions(testNodeGWA, testNodeGWB)

	type want struct {
		status metav1.ConditionStatus
		reason string
	}
	dualStack := vipFamilies{ipv4: true, ipv6: true}
	ipv4Only := vipFamilies{ipv4: true}
	tests := []struct {
		name         string
		conditions   []metav1.Condition
		families     vipFamilies
		gatewayNodes []string
		want         map[string]want
	}{
		{
			name: "every node serves", conditions: serving, gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
				conditionTypeAdvertised:             {metav1.ConditionTrue, reasonAdvertised},
				conditionTypeBackendsReady:          {metav1.ConditionTrue, reasonBackendsReady},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionTrue, reasonReady},
			},
		},
		{
			name: "no gateway nodes", conditions: serving, gatewayNodes: nil,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionFalse, reasonNoGatewayNodes},
				conditionTypeAdvertised:             {metav1.ConditionFalse, reasonNotProgrammed},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionFalse, reasonNoGatewayNodes},
			},
		},
		{
			name: "one node refuses the rule",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWB), metav1.ConditionFalse, reasonLoadFailed)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionFalse, reasonLoadFailed},
				// The node that loaded it still advertises it.
				conditionTypeAdvertised:        {metav1.ConditionTrue, reasonAdvertised},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonLoadFailed},
			},
		},
		{
			name: "nodes disagree on why",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionFalse, reasonInvalidRule),
				cond(programmedConditionType(testNodeGWB), metav1.ConditionFalse, reasonLoadFailed)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionFalse, reasonNotProgrammed},
				conditionTypeAdvertised:             {metav1.ConditionFalse, reasonNotProgrammed},
			},
		},
		{
			name: "every node refuses an unserved protocol",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionFalse, reasonUnservedProtocol),
				cond(programmedConditionType(testNodeGWB), metav1.ConditionFalse, reasonUnservedProtocol)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionFalse, reasonUnservedProtocol},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionFalse, reasonUnservedProtocol},
			},
		},
		{
			// A node that has not reported, such as one whose datapath is
			// turned off, advertises nothing, so it carries no traffic.
			name:         "a node that has not reported does not count",
			conditions:   servingConditions(testNodeGWA),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionTrue, reasonReady},
			},
		},
		{
			name: "every node is a generation behind",
			conditions: with(serving,
				metav1.Condition{Type: programmedConditionType(testNodeGWA), Status: metav1.ConditionTrue,
					Reason: reasonProgrammed, ObservedGeneration: summaryGen - 1},
				metav1.Condition{Type: programmedConditionType(testNodeGWB), Status: metav1.ConditionTrue,
					Reason: reasonProgrammed, ObservedGeneration: summaryGen - 1}),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionFalse, reasonPending},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			name: "a departed node's leftover condition is ignored",
			conditions: with(serving,
				cond(programmedConditionType("gw-gone"), metav1.ConditionFalse, reasonLoadFailed)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
			},
		},
		{
			name: "advertisement fails on one node",
			conditions: with(serving,
				cond(advertisedConditionType(testNodeGWB), metav1.ConditionFalse, reasonAdvertisementFailed)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
				conditionTypeAdvertised:             {metav1.ConditionFalse, reasonAdvertisementFailed},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionFalse, reasonAdvertisementFailed},
			},
		},
		{
			name:         "a loaded rule's advertisement has not been reported",
			conditions:   without(serving, advertisedConditionType(testNodeGWB)),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeAdvertised: {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			// The IPv6 VIP serves, so the rule is Ready and only IPv4Served
			// says the IPv4 VIP does not.
			name: "IPv4 VIP turned off on a dual-stack rule",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionFalse, reasonIPv4Unsupported),
				cond(ipv4ServedConditionType(testNodeGWB), metav1.ConditionFalse, reasonIPv4Unsupported)),
			families:     dualStack,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeAdvertised:        {metav1.ConditionTrue, reasonAdvertised},
				conditionTypeIPv4Served:        {metav1.ConditionFalse, reasonIPv4Unsupported},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionTrue, reasonReady},
			},
		},
		{
			name: "IPv4 VIP served",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionTrue, reasonIPv4Advertised),
				cond(ipv4ServedConditionType(testNodeGWB), metav1.ConditionTrue, reasonIPv4Advertised)),
			families:     dualStack,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeIPv4Served:        {metav1.ConditionTrue, reasonIPv4Advertised},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionTrue, reasonReady},
			},
		},
		{
			name: "IPv4 VIP unbound on an IPv4-only rule",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionFalse, reasonIPv4BindingsNotBound),
				cond(ipv4ServedConditionType(testNodeGWB), metav1.ConditionTrue, reasonIPv4Advertised)),
			families:     ipv4Only,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeIPv4Served:        {metav1.ConditionFalse, reasonIPv4BindingsNotBound},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonIPv4BindingsNotBound},
			},
		},
		{
			name: "an IPv4Served condition from an older generation is pending",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionTrue, reasonIPv4Advertised),
				metav1.Condition{Type: ipv4ServedConditionType(testNodeGWB), Status: metav1.ConditionTrue,
					Reason: reasonIPv4Advertised, ObservedGeneration: summaryGen - 1}),
			families:     ipv4Only,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeIPv4Served: {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			// #957: a node that cannot turn on IPv4 forwarding keeps serving
			// IPv6, so only the IPv4 VIP's condition says so.
			name: "IPv4 forwarding fails on a dual-stack rule",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionFalse, reasonIPv4ForwardingFailed),
				cond(ipv4ServedConditionType(testNodeGWB), metav1.ConditionFalse, reasonIPv4ForwardingFailed)),
			families:     dualStack,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeIPv4Served:        {metav1.ConditionFalse, reasonIPv4ForwardingFailed},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionTrue, reasonReady},
			},
		},
		{
			name: "IPv4 forwarding fails on an IPv4-only rule",
			conditions: with(serving,
				cond(ipv4ServedConditionType(testNodeGWA), metav1.ConditionFalse, reasonIPv4ForwardingFailed),
				cond(ipv4ServedConditionType(testNodeGWB), metav1.ConditionTrue, reasonIPv4Advertised)),
			families:     ipv4Only,
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeIPv4Served:        {metav1.ConditionFalse, reasonIPv4ForwardingFailed},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonIPv4ForwardingFailed},
			},
		},
		{
			name:         "a node named by two NetworkGateways counts once",
			conditions:   servingConditions(testNodeGWA),
			gatewayNodes: []string{testNodeGWA, testNodeGWA},
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
			},
		},
		{
			name: "Accepted from an older generation is pending",
			conditions: with(serving,
				metav1.Condition{Type: bgpv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionTrue,
					Reason: reasonGatewayNodesRegistered, ObservedGeneration: summaryGen - 1}),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			name: "a backend is claimed by another rule",
			conditions: with(serving,
				cond(backendsBoundConditionType(testBackendNode), metav1.ConditionFalse, reasonBindingsClaimed)),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeBackendsReady:     {metav1.ConditionFalse, reasonBindingsClaimed},
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonBindingsClaimed},
			},
		},
		{
			name: "a gateway node left backends out",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionTrue, reasonBackendsUnresolved)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
				conditionTypeBackendsReady:          {metav1.ConditionFalse, reasonBackendsUnresolved},
			},
		},
		{
			name: "a gateway node left Unhealthy backends out",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionTrue, reasonBackendsUnhealthy)),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeProgrammed: {metav1.ConditionTrue, reasonProgrammed},
				conditionTypeBackendsReady:          {metav1.ConditionFalse, reasonBackendsUnhealthy},
				bgpv1alpha1.ConditionTypeReady:      {metav1.ConditionFalse, reasonBackendsUnhealthy},
			},
		},
		{
			name: "every backend is Unhealthy",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionTrue, reasonNoHealthyBackends)),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeBackendsReady: {metav1.ConditionFalse, reasonNoHealthyBackends},
			},
		},
		{
			name: "a gateway node cannot apply health checks",
			conditions: with(serving,
				cond(programmedConditionType(testNodeGWA), metav1.ConditionTrue, reasonHealthChecksNotApplied)),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeBackendsReady: {metav1.ConditionFalse, reasonHealthChecksNotApplied},
			},
		},
		{
			name:         "no backend node has reported",
			conditions:   without(serving, backendsBoundConditionType(testBackendNode)),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeBackendsReady: {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			name: "a backend node is a generation behind",
			conditions: with(serving,
				metav1.Condition{Type: backendsBoundConditionType(testBackendNode), Status: metav1.ConditionTrue,
					Reason: reasonBindingsBound, ObservedGeneration: summaryGen - 1}),
			gatewayNodes: nodes,
			want: map[string]want{
				conditionTypeBackendsReady: {metav1.ConditionFalse, reasonPending},
			},
		},
		{
			name:         "not accepted",
			conditions:   without(serving, bgpv1alpha1.ConditionTypeAccepted),
			gatewayNodes: nodes,
			want: map[string]want{
				bgpv1alpha1.ConditionTypeReady: {metav1.ConditionFalse, reasonPending},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			families := tt.families
			if families == (vipFamilies{}) {
				families.ipv6 = true
			}
			got := summaryConditions(tt.conditions, summaryGen, families, tt.gatewayNodes)
			wantLen := 4
			if families.ipv4 {
				wantLen = 5
			}
			if len(got) != wantLen {
				t.Fatalf("summaryConditions returned %d conditions, want %d", len(got), wantLen)
			}
			for condType, w := range tt.want {
				c := meta.FindStatusCondition(got, condType)
				if c == nil {
					t.Fatalf("no %s condition in %v", condType, got)
				}
				if c.Status != w.status || c.Reason != w.reason {
					t.Errorf("%s = %s/%s (%q), want %s/%s", condType, c.Status, c.Reason, c.Message, w.status, w.reason)
				}
				if c.ObservedGeneration != summaryGen {
					t.Errorf("%s observedGeneration = %d, want %d", condType, c.ObservedGeneration, summaryGen)
				}
			}
		})
	}
}

// TestSummaryConditions_MessageNamesFailingNodes checks a partial failure's
// message names each failing node and its reason.
func TestSummaryConditions_MessageNamesFailingNodes(t *testing.T) {
	conds := with(servingConditions(testNodeGWA, testNodeGWB),
		cond(programmedConditionType(testNodeGWB), metav1.ConditionFalse, reasonLoadFailed))
	got := meta.FindStatusCondition(summaryConditions(conds, summaryGen, vipFamilies{ipv6: true},
		[]string{testNodeGWB, testNodeGWA, "gw-new"}), bgpv1alpha1.ConditionTypeProgrammed)
	want := "loaded on 1 of 2 reporting gateway nodes; 1 of 3 registered gateway nodes have not reported; " +
		"not loaded on " + testNodeGWB + " (" + reasonLoadFailed + ")"
	if got.Message != want {
		t.Errorf("Programmed message = %q, want %q", got.Message, want)
	}
}

// TestAdvertisedCondition covers each per-node Advertised outcome.
func TestAdvertisedCondition(t *testing.T) {
	errPublish := errors.New("apply failed")
	tests := []struct {
		name       string
		programmed bool
		router     string
		err        error
		pending    []string
		status     metav1.ConditionStatus
		reason     string
	}{
		{"installed", true, testRouterName, nil, nil, metav1.ConditionTrue, reasonAdvertised},
		{"not loaded", false, testRouterName, nil, nil, metav1.ConditionFalse, reasonNotProgrammed},
		{"no router", true, "", nil, nil, metav1.ConditionFalse, reasonNoRouter},
		{"publish failed", true, testRouterName, errPublish, nil, metav1.ConditionFalse, reasonAdvertisementFailed},
		{"published, not installed", true, testRouterName, nil, []string{testRuleAdv}, metav1.ConditionFalse,
			reasonAdvertisementPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := advertisedCondition(testNodeGWA, tt.programmed, tt.router, tt.err, tt.pending)
			if c.Type != advertisedConditionType(testNodeGWA) {
				t.Errorf("type = %q, want %q", c.Type, advertisedConditionType(testNodeGWA))
			}
			if c.Status != tt.status || c.Reason != tt.reason {
				t.Errorf("Advertised = %s/%s, want %s/%s", c.Status, c.Reason, tt.status, tt.reason)
			}
			if tt.err != nil && !strings.Contains(c.Message, tt.err.Error()) {
				t.Errorf("message %q does not carry the publish error", c.Message)
			}
		})
	}
}

// TestNetworkServiceReconciler_WritesSummaryConditions checks the reconciler
// writes the summary, and that a second pass with nothing changed writes
// nothing.
func TestNetworkServiceReconciler_WritesSummaryConditions(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Generation = summaryGen
	rule.Status.Conditions = servingConditions(testNodeGWA)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkService{}).
		WithObjects(newTestGateway(testNodeGWA), rule).
		Build()

	r := &NetworkServiceReconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	for _, condType := range []string{bgpv1alpha1.ConditionTypeProgrammed, conditionTypeAdvertised,
		conditionTypeBackendsReady, bgpv1alpha1.ConditionTypeReady} {
		if !meta.IsStatusConditionTrue(got.Status.Conditions, condType) {
			t.Errorf("%s is not True: %v", condType, meta.FindStatusCondition(got.Status.Conditions, condType))
		}
	}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	again := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, again); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if again.ResourceVersion != got.ResourceVersion {
		t.Errorf("an unchanged summary was written again (resourceVersion %s -> %s)",
			got.ResourceVersion, again.ResourceVersion)
	}
}

// TestClearNodeRuleConditions_RefreshesSummary covers the last gateway node
// leaving: no reconciler is left to recompute the summary, so the clear does.
func TestClearNodeRuleConditions_RefreshesSummary(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Generation = summaryGen
	rule.Status.Conditions = servingConditions(testNodeGWA)
	applySummaryConditions(rule, []string{testNodeGWA})

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkService{}).
		WithObjects(rule).
		Build()

	if err := clearNodeRuleConditions(context.Background(), fakeClient, testNamespace, testNodeGWA); err != nil {
		t.Fatalf("clearNodeRuleConditions: %v", err)
	}
	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, advertisedConditionType(testNodeGWA)); c != nil {
		t.Errorf("node %s's Advertised condition was not cleared", testNodeGWA)
	}
	ready := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != reasonNoGatewayNodes {
		t.Errorf("Ready = %v, want False/%s once the last gateway node left", ready, reasonNoGatewayNodes)
	}
}

// TestApplySummaryConditions_DropsIPv4ServedWithTheIPv4VIP checks the
// rule-wide IPv4Served goes once the rule no longer has an IPv4 VIP.
func TestApplySummaryConditions_DropsIPv4ServedWithTheIPv4VIP(t *testing.T) {
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	rule.Generation = summaryGen
	rule.Status.Conditions = servingConditions(testNodeGWA)
	applySummaryConditions(rule, []string{testNodeGWA})
	if meta.FindStatusCondition(rule.Status.Conditions, conditionTypeIPv4Served) == nil {
		t.Fatal("a rule with an IPv4 VIP has no rule-wide IPv4Served condition")
	}

	rule.Spec.VIPAddresses = []string{testVIP}
	if !applySummaryConditions(rule, []string{testNodeGWA}) {
		t.Error("dropping the IPv4 VIP reported no change")
	}
	if meta.FindStatusCondition(rule.Status.Conditions, conditionTypeIPv4Served) != nil {
		t.Error("the rule-wide IPv4Served condition outlived the rule's IPv4 VIP")
	}
}

// TestSummaryConditions_SilentNodesAreNamed checks a summary that is True
// still says how many registered gateway nodes have not reported, and that a
// backend node left at an older generation is named in BackendsReady.
func TestSummaryConditions_SilentNodesAreNamed(t *testing.T) {
	conds := servingConditions(testNodeGWA)
	got := summaryConditions(conds, summaryGen, vipFamilies{ipv6: true}, []string{testNodeGWA, testNodeGWB})
	ready := meta.FindStatusCondition(got, bgpv1alpha1.ConditionTypeReady)
	if ready.Status != metav1.ConditionTrue || !strings.Contains(ready.Message, "1 of 2 registered gateway nodes") {
		t.Errorf("Ready = %s %q, want True naming the gateway node that has not reported", ready.Status, ready.Message)
	}

	conds = with(conds, metav1.Condition{Type: backendsBoundConditionType("compute-2"),
		Status: metav1.ConditionTrue, Reason: reasonBindingsBound, ObservedGeneration: summaryGen - 1})
	got = summaryConditions(conds, summaryGen, vipFamilies{ipv6: true}, []string{testNodeGWA})
	backends := meta.FindStatusCondition(got, conditionTypeBackendsReady)
	want := "backends not ready on compute-2 (" + reasonPending + ")"
	if backends.Status != metav1.ConditionFalse || backends.Message != want {
		t.Errorf("BackendsReady = %s %q, want False %q", backends.Status, backends.Message, want)
	}
}
