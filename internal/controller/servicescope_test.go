// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// testTenantNamespace is the project namespace newBackendAttachment puts
// testVPCRef's attachment in, which holds no NetworkGateway.
const testTenantNamespace = "tenant-" + testVPCRef

// newTenantRule returns a NetworkService in testTenantNamespace selecting
// newBackendAttachment(testVPCRef).
func newTenantRule(name string, vips ...string) *bgpv1alpha1.NetworkService {
	rule := newTestRule(name, testVPCRef, vips...)
	rule.Namespace = testTenantNamespace
	rule.UID = types.UID(name + "-uid")
	return rule
}

// newTenantVPC returns a VPC in namespace whose identifier is vpc.
func newTenantVPC(namespace, vpc string) *cloudv1alpha1.VPC {
	return &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "vpc"},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/48"}},
		Status:     cloudv1alpha1.VPCStatus{VPC: vpc},
	}
}

func newTenantClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return newIndexedClientBuilder(newRuleTestScheme(t)).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, VPCAttachmentByVPC, vpcAttachmentVPC).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{},
			&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(objs...).
		Build()
}

func acceptedCondition(t *testing.T, c client.Client, key types.NamespacedName) *metav1.Condition {
	t.Helper()
	rule := &bgpv1alpha1.NetworkService{}
	if err := c.Get(context.Background(), key, rule); err != nil {
		t.Fatalf("get NetworkService %s: %v", key, err)
	}
	return meta.FindStatusCondition(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted)
}

func reconcileService(t *testing.T, c client.Client, key types.NamespacedName) {
	t.Helper()
	r := &NetworkServiceReconciler{Client: c, APIReader: c, Scheme: c.Scheme(), NodeName: testNodeGWA}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile NetworkService %s: %v", key, err)
	}
}

// TestTenantService_ServedFromProjectNamespace covers a NetworkService in a
// project namespace, which holds no NetworkGateway: the gateways in their own
// namespace accept it once a VPC in the project carries its vpcRef, load it,
// and advertise it from their own namespace, beside their BGPRouter.
func TestTenantService_ServedFromProjectNamespace(t *testing.T) {
	ctx := context.Background()
	backendRouter, backendAdv, backendVRF := newBackendFixtures(testVPCRef)
	rule := newTenantRule(testRuleName, testVIP)
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
		newBackendAttachment(testVPCRef), newTenantVPC(testTenantNamespace, testVPCRef), rule)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionTrue ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipVerified {
		t.Fatalf("Accepted = %+v, want True/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipVerified)
	}

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	dr, ok := engine.lastDesired.Rules[key.String()]
	if !ok {
		t.Fatalf("desired rules = %v, want %s", engine.lastDesired.Rules, key)
	}
	if len(dr.Backends) != 1 {
		t.Errorf("backends = %+v, want the project's one", dr.Backends)
	}

	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil {
		t.Fatalf("list advertisements: %v", err)
	}
	if len(advs.Items) != 1 {
		t.Fatalf("advertisements in %s = %d, want 1", testNamespace, len(advs.Items))
	}
	adv := advs.Items[0]
	if adv.Labels[networkRuleNamespaceLabel] != testTenantNamespace || len(adv.OwnerReferences) != 0 {
		t.Errorf("advertisement labels %v owners %v, want the project namespace label and no owner reference",
			adv.Labels, adv.OwnerReferences)
	}
	if !isNodeAdvertisement(&adv, testNodeGWA) {
		t.Errorf("isNodeAdvertisement(%s) = false, want true", adv.Name)
	}
	if adv.Name == ruleAdvertisementName(testRuleName, testNodeGWA, "v6") {
		t.Errorf("advertisement name %s matches a gateway-namespace rule of the same name", adv.Name)
	}
}

// TestTenantService_OwnershipDenied covers a project NetworkService naming a
// VPC its namespace does not hold: it is refused, and a gateway that
// advertised it before withdraws the route.
func TestTenantService_OwnershipDenied(t *testing.T) {
	ctx := context.Background()
	backendRouter, backendAdv, backendVRF := newBackendFixtures(testVPCRef)
	rule := newTenantRule(testRuleName, testVIP)
	acceptRule(rule)
	stale := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Namespace: testNamespace,
		Name:      ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), testNamespace, testNodeGWA, "v6"),
		Labels: map[string]string{
			networkRuleLabel:          testRuleName,
			networkRuleNamespaceLabel: testTenantNamespace,
			gatewayNodeLabel:          testNodeGWA,
		},
	}}
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
		newBackendAttachment(testVPCRef), newTenantVPC(testTenantNamespace, "other-vpc"), rule, stale)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipDenied {
		t.Fatalf("Accepted = %+v, want False/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipDenied)
	}

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	if _, ok := engine.lastDesired.Rules[key.String()]; ok {
		t.Error("refused rule loaded")
	}
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil {
		t.Fatalf("list advertisements: %v", err)
	}
	if len(advs.Items) != 0 {
		t.Errorf("advertisements = %d, want the refused rule's route withdrawn", len(advs.Items))
	}
}

// TestTenantService_BackendsOnlyFromOwnNamespace covers a project selector
// naming another project's VPC: attachments outside its namespace are never
// its backends, so it cannot reach or claim another project's workloads.
func TestTenantService_BackendsOnlyFromOwnNamespace(t *testing.T) {
	attachment := newBackendAttachment(testVPCRef)
	intruder := newTestRule(testRuleName, testVPCRef, testVIP)
	intruder.Namespace = "intruder"

	sel, err := selectRuleBackends(intruder, []*cloudv1alpha1.VPCAttachment{attachment}, nil, familyIPv6,
		testNamespace)
	if err != nil {
		t.Fatalf("selectRuleBackends: %v", err)
	}
	if len(sel.backends) != 0 {
		t.Errorf("backends = %+v, want none from another namespace", sel.backends)
	}
	if owners := ruleBackendOwners([]bgpv1alpha1.NetworkService{*intruder},
		[]*cloudv1alpha1.VPCAttachment{attachment}, testNamespace); len(owners) != 0 {
		t.Errorf("claims = %v, want none", owners)
	}

	own := newTenantRule(testRuleName, testVIP)
	sel, err = selectRuleBackends(own, []*cloudv1alpha1.VPCAttachment{attachment}, nil, familyIPv6, testNamespace)
	if err != nil {
		t.Fatalf("selectRuleBackends: %v", err)
	}
	if len(sel.backends) != 1 {
		t.Errorf("backends = %+v, want the project's own attachment", sel.backends)
	}
}

// TestTenantVIPConflicts covers who keeps a VIP address, protocol and port
// two rules claim: a rule in the gateway namespace always does, and among
// project rules the oldest does.
func TestTenantVIPConflicts(t *testing.T) {
	at := func(rule *bgpv1alpha1.NetworkService, sec int64) bgpv1alpha1.NetworkService {
		rule.CreationTimestamp = metav1.NewTime(time.Unix(sec, 0))
		return *rule
	}
	platform := at(newTestRule("platform", "vpc-p", testVIP), 300)
	older := at(newTenantRule("older", "2001:db8:5::7"), 100)
	newer := at(newTenantRule("newer", "2001:db8:5::7"), 200)
	newer.Namespace = "tenant-other"
	thief := at(newTenantRule("thief", testVIP), 50)
	otherPort := at(newTenantRule("other-port", testVIP), 60)
	otherPort.Spec.Port = 80

	lost := tenantVIPConflicts([]bgpv1alpha1.NetworkService{platform, older, newer, thief, otherPort}, testNamespace)

	want := map[types.NamespacedName]types.NamespacedName{
		client.ObjectKeyFromObject(&thief): client.ObjectKeyFromObject(&platform),
		client.ObjectKeyFromObject(&newer): client.ObjectKeyFromObject(&older),
	}
	if len(lost) != len(want) {
		t.Fatalf("lost = %v, want %v", lost, want)
	}
	for k, v := range want {
		if lost[k] != v {
			t.Errorf("%s lost to %s, want %s", k, lost[k], v)
		}
	}
}

// TestTenantService_VIPClaimed covers a project rule claiming a VIP a
// gateway-namespace rule serves: it is refused.
func TestTenantService_VIPClaimed(t *testing.T) {
	platform := newTestRule("platform", "vpc-p", testVIP)
	rule := newTenantRule(testRuleName, testVIP)
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTenantVPC(testTenantNamespace, testVPCRef),
		platform, rule)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonVIPClaimed {
		t.Fatalf("Accepted = %+v, want False/%s", cond, reasonVIPClaimed)
	}
}

// TestRuleSelector_SameNameInTwoNamespaces covers a project rule named like a
// gateway-namespace rule: each selects only its own generated objects.
func TestRuleSelector_SameNameInTwoNamespaces(t *testing.T) {
	ctx := context.Background()
	local := newTestRule(testRuleName, "vpc-p", testVIP)
	tenant := newTenantRule(testRuleName, "2001:db8:5::9")
	mk := func(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.BGPAdvertisement {
		return &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), testNamespace, testNodeGWA, "v6"),
			Labels:    ruleLabels(rule, testNamespace),
		}}
	}
	c := newTenantClient(t, mk(local), mk(tenant))

	for _, rule := range []*bgpv1alpha1.NetworkService{local, tenant} {
		list := &bgpv1alpha1.BGPAdvertisementList{}
		if err := c.List(ctx, list, ruleSelector(rule, testNamespace)); err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list.Items) != 1 || !generatedFor(&list.Items[0], rule) {
			t.Errorf("rule %s selects %+v, want only its own", client.ObjectKeyFromObject(rule), list.Items)
		}
	}
}

// TestNetworkServiceBindingReconciler_TenantRule covers the backend node's
// side: bindings for a project rule are written in the gateway namespace,
// labelled with the project namespace, and deleted with the rule.
func TestNetworkServiceBindingReconciler_TenantRule(t *testing.T) {
	ctx := context.Background()
	rule := newTenantRule(testRuleName, testVIP)
	acceptRule(rule)
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef))
	r.Namespace = testNamespace
	key := client.ObjectKeyFromObject(rule)

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	bindings := listBindings(t, c)
	if len(bindings) != 1 {
		t.Fatalf("bindings in %s = %d, want 1", testNamespace, len(bindings))
	}
	b := bindings[0]
	if got, _ := ruleKeyFromLabels(&b); got != key || len(b.OwnerReferences) != 0 {
		t.Errorf("binding names rule %s with owners %v, want %s and none", got, b.OwnerReferences, key)
	}
	if reqs := r.bindingRuleRequests(&b); len(reqs) != 1 || reqs[0].NamespacedName != key {
		t.Errorf("binding maps to %v, want %s", reqs, key)
	}

	if err := c.Delete(ctx, rule); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile after delete: %v", err)
	}
	if got := listBindings(t, c); len(got) != 0 {
		t.Errorf("bindings after the rule is deleted = %d, want 0", len(got))
	}
}

// TestServedNetworkServices covers which rules a gateway namespace serves:
// its own and those of every namespace without gateways, not those of
// another gateway namespace.
func TestServedNetworkServices(t *testing.T) {
	otherGW := newTestGateway("gw-other")
	otherGW.Namespace = "other-gateways"
	inOtherGW := newTestRule("elsewhere", "vpc-e", "2001:db8:5::10")
	inOtherGW.Namespace = otherGW.Namespace
	c := newTenantClient(t, newTestGateway(testNodeGWA), otherGW, inOtherGW,
		newTestRule("local", "vpc-p", testVIP), newTenantRule("project", "2001:db8:5::11"))

	served, all, err := listServedNetworkServices(context.Background(), c, testNamespace)
	if err != nil {
		t.Fatalf("listServedNetworkServices: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("all = %d, want 3", len(all))
	}
	got := map[string]bool{}
	for _, s := range served {
		got[s.Name] = true
	}
	if len(got) != 2 || !got["local"] || !got["project"] {
		t.Errorf("served = %v, want local and project", got)
	}
}
