// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// testProjectScope serves project namespaces from testNamespace, allocating
// load balancer addresses from the prefix every test VIP is in.
var testProjectScope = ServiceScope{
	ProjectServices:  true,
	GatewayNamespace: testNamespace,
	VIPPrefixes:      []netip.Prefix{netip.MustParsePrefix("2001:db8:5::/64")},
}

// newProjectGatewayReconciler is newGatewayReconciler serving testProjectScope.
func newProjectGatewayReconciler(c client.Client, engine GatewayEngine) *NetworkGatewayReconciler {
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	r.Scope = testProjectScope
	return r
}

// newTenantRule returns a NetworkService in testTenantNamespace selecting
// newBackendAttachment(testVPCRef).
func newTenantRule(name string, vips ...string) *bgpv1alpha1.NetworkService {
	rule := newTestRule(name, testVPCRef, vips...)
	rule.Namespace = testTenantNamespace
	rule.UID = types.UID(name + "-uid")
	return rule
}

// newTenantVPC returns a VPC in testTenantNamespace whose identifier is vpc.
func newTenantVPC(vpc string) *cloudv1alpha1.VPC {
	return &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Namespace: testTenantNamespace, Name: "vpc"},
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
	reconcileServiceIn(t, c, key, testProjectScope)
}

func reconcileServiceIn(t *testing.T, c client.Client, key types.NamespacedName, scope ServiceScope) {
	t.Helper()
	r := &NetworkServiceReconciler{Client: c, APIReader: c, Scheme: c.Scheme(), NodeName: testNodeGWA, Scope: scope}
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
		newBackendAttachment(testVPCRef), newTenantVPC(testVPCRef), rule)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionTrue ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipVerified {
		t.Fatalf("Accepted = %+v, want True/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipVerified)
	}

	engine := newFakeGatewayEngine()
	r := newProjectGatewayReconciler(c, engine)
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
		newBackendAttachment(testVPCRef), newTenantVPC("other-vpc"), rule, stale)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipDenied {
		t.Fatalf("Accepted = %+v, want False/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipDenied)
	}

	engine := newFakeGatewayEngine()
	r := newProjectGatewayReconciler(c, engine)
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
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTenantVPC(testVPCRef),
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

// TestServedNetworkServices covers which rules a gateway namespace serves.
// With project services off, only its own. With them on, the trusted gateway
// namespace serves every rule, including one in a namespace holding a
// NetworkGateway of its own, and an untrusted gateway namespace serves none.
func TestServedNetworkServices(t *testing.T) {
	otherGW := newTestGateway("gw-other")
	otherGW.Namespace = "other-gateways"
	inOtherGW := newTestRule("elsewhere", "vpc-e", "2001:db8:5::10")
	inOtherGW.Namespace = otherGW.Namespace
	c := newTenantClient(t, newTestGateway(testNodeGWA), otherGW, inOtherGW,
		newTestRule("local", "vpc-p", testVIP), newTenantRule("project", "2001:db8:5::11"))

	names := func(scope ServiceScope, ns string) map[string]bool {
		t.Helper()
		served, all, err := scope.listServedNetworkServices(context.Background(), c, ns)
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
		return got
	}

	if got := names(ServiceScope{}, testNamespace); len(got) != 1 || !got["local"] {
		t.Errorf("project services off: served = %v, want local", got)
	}
	if got := names(testProjectScope, testNamespace); len(got) != 3 {
		t.Errorf("project services on: served = %v, want all three", got)
	}
	if got := names(testProjectScope, otherGW.Namespace); len(got) != 0 {
		t.Errorf("untrusted gateway namespace: served = %v, want none", got)
	}
	offScope := ServiceScope{GatewayNamespace: testNamespace}
	if got := names(offScope, otherGW.Namespace); len(got) != 0 {
		t.Errorf("untrusted gateway namespace, project services off: served = %v, want none", got)
	}
}

// TestTenantService_ProjectServicesOff covers the rollout switch: with
// project services off, a gateway leaves a project rule alone, even one whose
// namespace holds a NetworkGateway of its own, and takes Accepted back from
// one it accepted while they were on.
func TestTenantService_ProjectServicesOff(t *testing.T) {
	rogue := newTestGateway(testNodeGWA)
	rogue.Namespace = testTenantNamespace
	rule := newTenantRule(testRuleName, testVIP)
	accepted := newTenantRule("accepted", "2001:db8:5::7")
	acceptRule(accepted)
	c := newTenantClient(t, newTestGateway(testNodeGWA), rogue, newTenantVPC(testVPCRef), rule, accepted)
	off := ServiceScope{GatewayNamespace: testNamespace}

	key := client.ObjectKeyFromObject(rule)
	reconcileServiceIn(t, c, key, off)
	got := &bgpv1alpha1.NetworkService{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Finalizers) != 0 || len(got.Status.Conditions) != 0 {
		t.Errorf("finalizers %v conditions %v, want the rule untouched", got.Finalizers, got.Status.Conditions)
	}

	key = client.ObjectKeyFromObject(accepted)
	reconcileServiceIn(t, c, key, off)
	if cond := acceptedCondition(t, c, key); cond == nil || cond.Status != metav1.ConditionFalse ||
		cond.Reason != reasonProjectServicesOff {
		t.Errorf("Accepted = %+v, want False/%s", cond, reasonProjectServicesOff)
	}
}

// TestTenantService_VIPOutsidePool covers a project rule claiming an address
// the platform never allocated: it is refused, and a gateway that sees it
// accepted anyway does not load it.
func TestTenantService_VIPOutsidePool(t *testing.T) {
	ctx := context.Background()
	backendRouter, backendAdv, backendVRF := newBackendFixtures(testVPCRef)
	rule := newTenantRule(testRuleName, "2001:db8:6::5")
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
		newBackendAttachment(testVPCRef), newTenantVPC(testVPCRef), rule)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonVIPOutsidePool {
		t.Fatalf("Accepted = %+v, want False/%s", cond, reasonVIPOutsidePool)
	}

	got := &bgpv1alpha1.NetworkService{}
	if err := c.Get(ctx, key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	acceptRule(got)
	if err := c.Status().Update(ctx, got); err != nil {
		t.Fatalf("accept: %v", err)
	}
	engine := newFakeGatewayEngine()
	if _, err := newProjectGatewayReconciler(c, engine).Reconcile(ctx,
		ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	if _, ok := engine.lastDesired.Rules[key.String()]; ok {
		t.Error("rule outside the pool loaded")
	}
}

// TestTenantService_UntrustedGateway covers a NetworkGateway created in a
// project namespace: the project's rules are still checked, and the gateway
// reconciler ignores it, even once it is deleted.
func TestTenantService_UntrustedGateway(t *testing.T) {
	ctx := context.Background()
	rogue := newTestGateway(testNodeGWA)
	rogue.Namespace = testTenantNamespace
	rule := newTenantRule(testRuleName, testVIP)
	c := newTenantClient(t, newTestGateway(testNodeGWA), rogue, newTenantVPC("other-vpc"), rule)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipDenied {
		t.Fatalf("Accepted = %+v, want False/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipDenied)
	}

	engine := newFakeGatewayEngine()
	r := newProjectGatewayReconciler(c, engine)
	if err := c.Delete(ctx, rogue); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rogue)}); err != nil {
		t.Fatalf("Reconcile untrusted NetworkGateway: %v", err)
	}
	if engine.stopped {
		t.Error("engine stopped for an untrusted gateway's deletion")
	}
}

// TestTenantService_VPCDeletedAfterAcceptance covers a project deleting its
// VPC while its rule is served: the rule loses Accepted and the gateway
// withdraws its route.
func TestTenantService_VPCDeletedAfterAcceptance(t *testing.T) {
	ctx := context.Background()
	backendRouter, backendAdv, backendVRF := newBackendFixtures(testVPCRef)
	rule := newTenantRule(testRuleName, testVIP)
	vpc := newTenantVPC(testVPCRef)
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
		newBackendAttachment(testVPCRef), vpc, rule)
	key := client.ObjectKeyFromObject(rule)
	engine := newFakeGatewayEngine()
	r := newProjectGatewayReconciler(c, engine)
	gwReq := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	reconcileService(t, c, key)
	if _, err := r.Reconcile(ctx, gwReq); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 1 {
		t.Fatalf("advertisements before = %d (%v), want 1", len(advs.Items), err)
	}

	if err := c.Delete(ctx, vpc); err != nil {
		t.Fatalf("delete VPC: %v", err)
	}
	reconcileService(t, c, key)
	cond := acceptedCondition(t, c, key)
	if cond == nil || cond.Status != metav1.ConditionFalse ||
		cond.Reason != bgpv1alpha1.AcceptedReasonOwnershipDenied {
		t.Fatalf("Accepted = %+v, want False/%s", cond, bgpv1alpha1.AcceptedReasonOwnershipDenied)
	}
	if _, err := r.Reconcile(ctx, gwReq); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	if _, ok := engine.lastDesired.Rules[key.String()]; ok {
		t.Error("rule still loaded after its VPC was deleted")
	}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 0 {
		t.Errorf("advertisements after = %d (%v), want the route withdrawn", len(advs.Items), err)
	}
}

// deletingTenantRule returns a project rule carrying the teardown finalizer
// and a deletion timestamp, and a BGPAdvertisement a gateway made for it.
func deletingTenantRule() (*bgpv1alpha1.NetworkService, *bgpv1alpha1.BGPAdvertisement) {
	rule := newTenantRule(testRuleName, testVIP)
	acceptRule(rule)
	rule.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	rule.DeletionTimestamp = &now
	adv := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Namespace: testNamespace,
		Name:      ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), testNamespace, testNodeGWA, "v6"),
		Labels: map[string]string{
			networkRuleLabel:          testRuleName,
			networkRuleNamespaceLabel: testTenantNamespace,
			gatewayNodeLabel:          testNodeGWA,
		},
	}}
	return rule, adv
}

// TestTenantService_DeletedMidFlight covers a project being deleted while its
// rule is served: the rule's route is withdrawn and its finalizer released,
// and a reconcile after the rule is gone does nothing.
func TestTenantService_DeletedMidFlight(t *testing.T) {
	ctx := context.Background()
	rule, adv := deletingTenantRule()
	c := newTenantClient(t, newTestGateway(testNodeGWA), rule, adv)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	if err := c.Get(ctx, key, &bgpv1alpha1.NetworkService{}); !apierrors.IsNotFound(err) {
		t.Errorf("get rule after teardown: %v, want it gone with its finalizer", err)
	}
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 0 {
		t.Errorf("advertisements = %d (%v), want the route withdrawn", len(advs.Items), err)
	}
	reconcileService(t, c, key)
}

// TestTenantService_DeletedWithNoGateway covers a project deleted after the
// last NetworkGateway left: no gateway serves the rule, yet its finalizer is
// still released, so the project namespace can finish terminating.
func TestTenantService_DeletedWithNoGateway(t *testing.T) {
	ctx := context.Background()
	rule, adv := deletingTenantRule()
	c := newTenantClient(t, rule, adv)
	key := client.ObjectKeyFromObject(rule)

	reconcileService(t, c, key)
	if err := c.Get(ctx, key, &bgpv1alpha1.NetworkService{}); !apierrors.IsNotFound(err) {
		t.Errorf("get rule: %v, want it gone with its finalizer", err)
	}
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 0 {
		t.Errorf("advertisements = %d (%v), want the route withdrawn", len(advs.Items), err)
	}
}

// TestTenantService_SwitchedOffWithdrawsRoutes covers turning project
// services off while a project rule is served: the gateway stops loading it
// and withdraws its route, though the rule still exists.
func TestTenantService_SwitchedOffWithdrawsRoutes(t *testing.T) {
	ctx := context.Background()
	backendRouter, backendAdv, backendVRF := newBackendFixtures(testVPCRef)
	rule := newTenantRule(testRuleName, testVIP)
	c := newTenantClient(t, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
		newBackendAttachment(testVPCRef), newTenantVPC(testVPCRef), rule)
	key := client.ObjectKeyFromObject(rule)
	gwReq := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	reconcileService(t, c, key)
	if _, err := newProjectGatewayReconciler(c, newFakeGatewayEngine()).Reconcile(ctx, gwReq); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	advs := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 1 {
		t.Fatalf("advertisements with project services on = %d (%v), want 1", len(advs.Items), err)
	}

	engine := newFakeGatewayEngine()
	if _, err := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA).Reconcile(ctx, gwReq); err != nil {
		t.Fatalf("Reconcile NetworkGateway: %v", err)
	}
	if _, ok := engine.lastDesired.Rules[key.String()]; ok {
		t.Error("project rule loaded with project services off")
	}
	if err := c.List(ctx, advs, ruleSelector(rule, testNamespace)); err != nil || len(advs.Items) != 0 {
		t.Errorf("advertisements with project services off = %d (%v), want the route withdrawn", len(advs.Items), err)
	}
}
