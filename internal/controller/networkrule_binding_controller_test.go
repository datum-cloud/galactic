// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// testBindingVIP is the IPv6 VIP the binding writer's rules use: the backend
// nodes translate IPv6 VIPs only.
const testBindingVIP = "2001:db8:100::32"

// newBindingTestRule returns an accepted rule with one IPv6 and one IPv4 VIP,
// selecting newBackendAttachment's attachments in testVPCRef.
func newBindingTestRule() *bgpv1alpha1.NetworkRule {
	rule := newTestRule(testRuleName, testVPCRef, testBindingVIP, testVIP)
	rule.UID = "rule-uid"
	acceptRule(rule)
	return rule
}

// newBindingWriter returns a NetworkRuleBindingReconciler for
// testComputeNodeName over a fake client holding objs.
func newBindingWriter(t *testing.T, objs ...client.Object) (*NetworkRuleBindingReconciler, client.Client) {
	t.Helper()
	scheme := newRuleTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}, &bgpv1alpha1.ServiceVIPBinding{}, &cloudv1alpha1.VPCAttachment{}).
		WithObjects(objs...).
		Build()
	return &NetworkRuleBindingReconciler{Client: c, Scheme: scheme, NodeName: testComputeNodeName}, c
}

func reconcileBindings(t *testing.T, r *NetworkRuleBindingReconciler) {
	t.Helper()
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: testNamespace, Name: testRuleName}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

// listBindings returns every ServiceVIPBinding in the test namespace, sorted
// by backend address.
func listBindings(t *testing.T, c client.Client) []bgpv1alpha1.ServiceVIPBinding {
	t.Helper()
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := c.List(context.Background(), list, client.InNamespace(testNamespace)); err != nil {
		t.Fatalf("list ServiceVIPBindings: %v", err)
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].Spec.BackendAddress < list.Items[j].Spec.BackendAddress
	})
	return list.Items
}

func backendAddresses(bindings []bgpv1alpha1.ServiceVIPBinding) []string {
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, b.Spec.BackendAddress)
	}
	return out
}

func getBindingRule(t *testing.T, c client.Client) *bgpv1alpha1.NetworkRule {
	t.Helper()
	rule := &bgpv1alpha1.NetworkRule{}
	key := client.ObjectKey{Namespace: testNamespace, Name: testRuleName}
	if err := c.Get(context.Background(), key, rule); err != nil {
		t.Fatalf("get NetworkRule: %v", err)
	}
	return rule
}

// TestNetworkRuleBindingReconciler_WritesBindingForLocalBackend is #799's
// regression test: applying only a NetworkRule produces a working binding on
// the backend's node, with nothing written by hand.
func TestNetworkRuleBindingReconciler_WritesBindingForLocalBackend(t *testing.T) {
	rule := newBindingTestRule()
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))

	reconcileBindings(t, r)

	bindings := listBindings(t, c)
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1 (one IPv6 VIP, one backend; the IPv4 VIP gets none)", len(bindings))
	}
	b := bindings[0]
	want := bgpv1alpha1.ServiceVIPBindingSpec{
		TargetRef:      bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: testComputeNodeName},
		VPCRef:         testVPCRef,
		VIPAddress:     testBindingVIP,
		Port:           443,
		Protocol:       bgpv1alpha1.NetworkRuleProtocolTCP,
		BackendAddress: testBackendAddr,
		BackendPort:    testBackendPort,
		EgressKind:     bgpv1alpha1.ServiceVIPBindingEgressKindVeth,
	}
	if b.Spec != want {
		t.Errorf("binding spec = %+v, want %+v", b.Spec, want)
	}
	if wantName := crdnames.ServiceVIPBindingName(
		testRuleName, testComputeNodeName, testBindingVIP, testBackendAddr, testBackendPort); b.Name != wantName {
		t.Errorf("binding name = %q, want %q", b.Name, wantName)
	}
	if b.Labels[bindingManagedByLabel] != bindingManagedByValue || b.Labels[networkRuleLabel] != testRuleName ||
		b.Labels[bindingNodeLabel] != gatewayNodeLabelValue(testComputeNodeName) {
		t.Errorf("binding labels = %v, want managed-by, rule and node labels", b.Labels)
	}
	owners := b.OwnerReferences
	if len(owners) != 1 || owners[0].Kind != "NetworkRule" || owners[0].Name != testRuleName {
		t.Errorf("binding owner references = %+v, want the NetworkRule", b.OwnerReferences)
	}
}

// TestNetworkRuleBindingReconciler_SameNodeBackendsGetOwnBindings covers two
// backends of one VIP on one node: each gets its own binding, which the
// per-backend slot lets the node program side by side.
func TestNetworkRuleBindingReconciler_SameNodeBackendsGetOwnBindings(t *testing.T) {
	rule := newBindingTestRule()
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef, testBackendAddr, "fd00:10::2"))

	reconcileBindings(t, r)

	got := backendAddresses(listBindings(t, c))
	if strings.Join(got, ",") != testBackendAddr+",fd00:10::2" {
		t.Errorf("binding backends = %v, want both %s and fd00:10::2", got, testBackendAddr)
	}
}

// TestNetworkRuleBindingReconciler_OnlyThisNodesBackends covers a backend on
// another node and one in another VPC carrying the selected label: neither
// gets a binding here.
func TestNetworkRuleBindingReconciler_OnlyThisNodesBackends(t *testing.T) {
	rule := newBindingTestRule()
	elsewhere := newBackendAttachment(testVPCRef, "fd00:10::7")
	elsewhere.Name = "elsewhere"
	elsewhere.Status.Node = testOtherNode
	otherVPC := newBackendAttachment("vpc-2", "fd00:10::8")
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef), elsewhere, otherVPC)

	reconcileBindings(t, r)

	if got := backendAddresses(listBindings(t, c)); len(got) != 1 || got[0] != testBackendAddr {
		t.Errorf("binding backends = %v, want only %s", got, testBackendAddr)
	}
}

// TestNetworkRuleBindingReconciler_FollowsBackend covers a backend moving to
// another node, changing address, and leaving the selector: each time the
// stale binding goes and, where the backend is still local, a new one comes.
func TestNetworkRuleBindingReconciler_FollowsBackend(t *testing.T) {
	tests := []struct {
		name   string
		change func(*cloudv1alpha1.VPCAttachment)
		want   []string
	}{
		{
			name:   "moves to another node",
			change: func(a *cloudv1alpha1.VPCAttachment) { a.Status.Node = testOtherNode },
		},
		{
			name: "changes address",
			change: func(a *cloudv1alpha1.VPCAttachment) {
				a.Spec.Interface.Addresses = []cloudv1alpha1.IPAddress{"fd00:10::9/64"}
			},
			want: []string{"fd00:10::9"},
		},
		{
			name:   "leaves the selector",
			change: func(a *cloudv1alpha1.VPCAttachment) { a.Labels = map[string]string{testBackendLabel: "other"} },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attachment := newBackendAttachment(testVPCRef)
			r, c := newBindingWriter(t, newBindingTestRule(), attachment)
			reconcileBindings(t, r)
			if got := listBindings(t, c); len(got) != 1 {
				t.Fatalf("bindings before the change = %d, want 1", len(got))
			}

			current := &cloudv1alpha1.VPCAttachment{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(attachment), current); err != nil {
				t.Fatalf("get attachment: %v", err)
			}
			// Spec and status are written separately, and each write reads
			// the other half back from the server, so the change is applied
			// before each.
			tt.change(current)
			if err := c.Update(context.Background(), current); err != nil {
				t.Fatalf("update attachment: %v", err)
			}
			tt.change(current)
			if err := c.Status().Update(context.Background(), current); err != nil {
				t.Fatalf("update attachment status: %v", err)
			}
			reconcileBindings(t, r)

			got := backendAddresses(listBindings(t, c))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("binding backends after the change = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNetworkRuleBindingReconciler_KeepsBindingsWhileUnaccepted covers a rule
// that loses Accepted, as it does whenever the namespace briefly has no
// NetworkGateway: its bindings stay, so the backend nodes keep their
// vip_xlat_table rows for when the gateways come back.
func TestNetworkRuleBindingReconciler_KeepsBindingsWhileUnaccepted(t *testing.T) {
	rule := newBindingTestRule()
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))
	reconcileBindings(t, r)

	current := getBindingRule(t, c)
	meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionFalse, Reason: "NoGatewayNodes",
	})
	if err := c.Status().Update(context.Background(), current); err != nil {
		t.Fatalf("update rule status: %v", err)
	}
	reconcileBindings(t, r)

	if got := listBindings(t, c); len(got) != 1 {
		t.Errorf("bindings = %d, want the 1 written while accepted kept", len(got))
	}
}

// TestNetworkRuleBindingReconciler_NeverAcceptedRuleHasNoBindings covers a
// rule the gateways have not accepted yet: nothing is written for it.
func TestNetworkRuleBindingReconciler_NeverAcceptedRuleHasNoBindings(t *testing.T) {
	rule := newBindingTestRule()
	rule.Status.Conditions = nil
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))

	reconcileBindings(t, r)

	if got := listBindings(t, c); len(got) != 0 {
		t.Errorf("bindings = %d, want 0 for a rule that was never accepted", len(got))
	}
}

// TestNetworkRuleBindingReconciler_RefusesSecondIPv6VIP covers a rule with two
// IPv6 VIPs: a backend's reply can be rewritten to only one VIP, so the rule
// gets no bindings and says why, rather than a binding per VIP of which all
// but one could only report Conflict.
func TestNetworkRuleBindingReconciler_RefusesSecondIPv6VIP(t *testing.T) {
	rule := newBindingTestRule()
	rule.Spec.VIPAddresses = append(rule.Spec.VIPAddresses, "2001:db8:100::33")
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))

	reconcileBindings(t, r)

	if got := listBindings(t, c); len(got) != 0 {
		t.Errorf("bindings = %d, want 0 for a rule with two IPv6 VIPs", len(got))
	}
	condType := backendsBoundConditionType(testComputeNodeName)
	cond := meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions, condType)
	if cond == nil || cond.Reason != reasonBindingsInvalid || !strings.Contains(cond.Message, "2 IPv6 VIPs") {
		t.Errorf("BackendsBound = %+v, want False/%s naming the 2 IPv6 VIPs", cond, reasonBindingsInvalid)
	}
}

// TestNetworkRuleBindingReconciler_LeavesOtherBindingsAlone covers bindings
// this node did not write: one written by hand, and one another node
// generated for the same rule. Neither is deleted.
func TestNetworkRuleBindingReconciler_LeavesOtherBindingsAlone(t *testing.T) {
	rule := newBindingTestRule()
	handWritten := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindVeth, testComputeNodeName)
	handWritten.Labels = map[string]string{networkRuleLabel: testRuleName}
	otherNode := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindVeth, testOtherNode)
	otherNode.Name = "other-node-binding"
	otherNode.Labels = map[string]string{
		networkRuleLabel:      testRuleName,
		bindingNodeLabel:      gatewayNodeLabelValue(testOtherNode),
		bindingManagedByLabel: bindingManagedByValue,
	}
	r, c := newBindingWriter(t, rule, handWritten, otherNode)

	reconcileBindings(t, r)

	names := map[string]bool{}
	for _, b := range listBindings(t, c) {
		names[b.Name] = true
	}
	if !names[handWritten.Name] || !names[otherNode.Name] {
		t.Errorf("bindings = %v, want the hand-written and other node's bindings kept", names)
	}
}

// TestNetworkRuleBindingReconciler_TapBackend covers a VM backend: its
// attachment's Hypervisor mode selects the tap mechanism.
func TestNetworkRuleBindingReconciler_TapBackend(t *testing.T) {
	attachment := newBackendAttachment(testVPCRef)
	attachment.Spec.Interface.Mode = cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor
	r, c := newBindingWriter(t, newBindingTestRule(), attachment)

	reconcileBindings(t, r)

	bindings := listBindings(t, c)
	if len(bindings) != 1 || bindings[0].Spec.EgressKind != bgpv1alpha1.ServiceVIPBindingEgressKindTap {
		t.Errorf("bindings = %+v, want one tap-kind binding", bindings)
	}
}

// TestNetworkRuleBindingReconciler_BackendsBoundCondition covers the rule's
// per-node summary: False naming each binding not yet Bound, then True once
// every binding reports Bound for its current generation.
func TestNetworkRuleBindingReconciler_BackendsBoundCondition(t *testing.T) {
	r, c := newBindingWriter(t, newBindingTestRule(), newBackendAttachment(testVPCRef))
	condType := backendsBoundConditionType(testComputeNodeName)

	reconcileBindings(t, r)
	cond := meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions, condType)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonBindingsPending {
		t.Fatalf("BackendsBound before the binding is bound = %+v, want False/%s", cond, reasonBindingsPending)
	}
	if !strings.Contains(cond.Message, "[fd00:10::1]:8443") {
		t.Errorf("BackendsBound message = %q, want it to name the unbound backend", cond.Message)
	}

	binding := listBindings(t, c)[0]
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeBound, Status: metav1.ConditionTrue, Reason: "Bound",
		ObservedGeneration: binding.Generation,
	})
	if err := c.Status().Update(context.Background(), &binding); err != nil {
		t.Fatalf("update binding status: %v", err)
	}

	reconcileBindings(t, r)
	cond = meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions, condType)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonBindingsBound {
		t.Errorf("BackendsBound once bound = %+v, want True/%s", cond, reasonBindingsBound)
	}
}

// TestNetworkRuleBindingReconciler_InvalidSelector covers a selector the
// writer cannot parse: no bindings, and the rule says why.
func TestNetworkRuleBindingReconciler_InvalidSelector(t *testing.T) {
	rule := newBindingTestRule()
	rule.Spec.BackendSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: testBackendLabel, Operator: "Bogus"},
	}}
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))

	reconcileBindings(t, r)

	if got := listBindings(t, c); len(got) != 0 {
		t.Errorf("bindings = %d, want 0 for an invalid selector", len(got))
	}
	condType := backendsBoundConditionType(testComputeNodeName)
	cond := meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions, condType)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonBindingsInvalid {
		t.Errorf("BackendsBound = %+v, want False/%s", cond, reasonBindingsInvalid)
	}
}

// TestNetworkRuleBindingReconciler_BindingRuleRequests covers the watch
// mapping: only this node's generated bindings requeue their rule.
func TestNetworkRuleBindingReconciler_BindingRuleRequests(t *testing.T) {
	r := &NetworkRuleBindingReconciler{NodeName: testComputeNodeName}
	mine := &bgpv1alpha1.ServiceVIPBinding{ObjectMeta: metav1.ObjectMeta{
		Namespace: testNamespace,
		Labels: map[string]string{
			networkRuleLabel:      testRuleName,
			bindingNodeLabel:      gatewayNodeLabelValue(testComputeNodeName),
			bindingManagedByLabel: bindingManagedByValue,
		},
	}}
	if reqs := r.bindingRuleRequests(mine); len(reqs) != 1 || reqs[0].Name != testRuleName {
		t.Errorf("requests for this node's binding = %v, want its rule", reqs)
	}

	other := mine.DeepCopy()
	other.Labels[bindingNodeLabel] = gatewayNodeLabelValue(testOtherNode)
	handWritten := mine.DeepCopy()
	delete(handWritten.Labels, bindingManagedByLabel)
	for name, obj := range map[string]*bgpv1alpha1.ServiceVIPBinding{"other node": other, "hand-written": handWritten} {
		if reqs := r.bindingRuleRequests(obj); len(reqs) != 0 {
			t.Errorf("requests for a %s binding = %v, want none", name, reqs)
		}
	}
}
