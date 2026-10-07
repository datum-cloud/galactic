// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testServiceRouteTenantNamespace = "tenant"
	testServiceRouteName            = "dns"
	testServiceRouteConsumerName    = "consumer"
	testServiceRouteAccessLabel     = "access"
	testServiceRoutePolicyNamespace = "platform"
)

type retryRouteProgrammer struct {
	initializeCalls    int
	applyCalls         int
	cleanupCalls       int
	removeCalls        int
	finalizeCalls      int
	failApply          int
	failRemove         int
	finalizeErr        error
	failAttachment     string
	cleanupErr         error
	staleAuthorization bool
}

func (p *retryRouteProgrammer) Initialize() error {
	p.initializeCalls++
	return nil
}

func (p *retryRouteProgrammer) Apply(intent serviceroute.RouteIntent) error {
	p.applyCalls++
	if intent.Attachment.Name == p.failAttachment || p.applyCalls == p.failApply {
		return errors.New("apply failed")
	}
	return nil
}

func (p *retryRouteProgrammer) Cleanup(serviceroute.RouteIntent) error {
	p.cleanupCalls++
	return p.cleanupErr
}

func (p *retryRouteProgrammer) Remove(serviceroute.RouteIntent) error {
	p.removeCalls++
	if p.removeCalls == p.failRemove {
		return errors.New("remove failed")
	}
	return nil
}

func (p *retryRouteProgrammer) Finalize() error {
	p.finalizeCalls++
	p.staleAuthorization = false
	return p.finalizeErr
}

func TestServiceRouteReplacePolicyResumesPartialApply(t *testing.T) {
	programmer := &retryRouteProgrammer{failApply: 2}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	policy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName}
	intents := []serviceroute.RouteIntent{
		{Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "a"}},
		{Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "b"}},
	}

	if err := reconciler.replacePolicy(policy, intents); err == nil {
		t.Fatal("first replacePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial apply = %d, want 1", got)
	}
	programmer.failApply = 0
	if err := reconciler.replacePolicy(policy, intents); err != nil {
		t.Fatalf("retry replacePolicy: %v", err)
	}
	if programmer.applyCalls != 3 {
		t.Fatalf("Apply calls = %d, want 3 (successful intent was not replayed)", programmer.applyCalls)
	}
	if got := len(reconciler.Applied[policy]); got != 2 {
		t.Fatalf("tracked intents after retry = %d, want 2", got)
	}
}

func TestServiceRouteReplacePolicyReportsUnresolvedApplyRollback(t *testing.T) {
	rollbackFailure := errors.New("rollback failed")
	programmer := &retryRouteProgrammer{failApply: 1, cleanupErr: rollbackFailure}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	err := reconciler.replacePolicy(types.NamespacedName{
		Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName,
	},
		[]serviceroute.RouteIntent{{
			Attachment: types.NamespacedName{
				Namespace: testServiceRouteTenantNamespace,
				Name:      testServiceRouteConsumerName,
			},
		}})
	if err == nil || !errors.Is(err, rollbackFailure) || !isServiceRoutePolicyCleanupError(err) {
		t.Fatalf("replacePolicy error = %v, want unresolved cleanup wrapping %v", err, rollbackFailure)
	}
	if programmer.cleanupCalls != 1 {
		t.Fatalf("Cleanup calls = %d, want 1", programmer.cleanupCalls)
	}
}

func TestServiceRouteRemovePolicyResumesPartialRemove(t *testing.T) {
	programmer := &retryRouteProgrammer{failRemove: 2}
	policy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName}
	reconciler := &ServiceRoutePolicyReconciler{
		Programmer: programmer,
		Applied: map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent{
			policy: {
				{Namespace: testServiceRouteTenantNamespace, Name: "a"}: {
					Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "a"},
				},
				{Namespace: testServiceRouteTenantNamespace, Name: "b"}: {
					Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "b"},
				},
			},
		},
	}

	if err := reconciler.removePolicy(policy); err == nil {
		t.Fatal("first removePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial remove = %d, want 1", got)
	}
	programmer.failRemove = 0
	if err := reconciler.removePolicy(policy); err != nil {
		t.Fatalf("retry removePolicy: %v", err)
	}
	if programmer.removeCalls != 3 {
		t.Fatalf("Remove calls = %d, want 3 (successful removal was not replayed)", programmer.removeCalls)
	}
	if _, ok := reconciler.Applied[policy]; ok {
		t.Fatal("policy remains tracked after successful retry")
	}
}

func TestServiceRouteStartupSyncRemovesOfflineDeletedPolicyBeforeSweep(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	programmer := &retryRouteProgrammer{}
	deletedPolicy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: "deleted-while-offline"}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:     fake.NewClientBuilder().WithScheme(scheme).Build(),
		Programmer: programmer,
		Applied: map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent{
			deletedPolicy: {
				{Namespace: testServiceRouteTenantNamespace, Name: testServiceRouteConsumerName}: {
					Attachment: types.NamespacedName{
						Namespace: testServiceRouteTenantNamespace,
						Name:      testServiceRouteConsumerName,
					},
				},
			},
		},
	}

	if err := reconciler.syncAllPolicies(context.Background()); err != nil {
		t.Fatalf("syncAllPolicies: %v", err)
	}
	if programmer.removeCalls != 1 || programmer.finalizeCalls != 1 {
		t.Fatalf("remove/finalize calls = %d/%d, want 1/1", programmer.removeCalls, programmer.finalizeCalls)
	}
	if len(reconciler.Applied) != 0 {
		t.Fatalf("applied policies after startup sync = %#v, want empty", reconciler.Applied)
	}
}

func TestServiceRouteStartupSyncRemovalFailureKeepsGateClosed(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	programmer := &retryRouteProgrammer{failRemove: 1, staleAuthorization: true}
	deletedPolicy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: "deleted-while-offline"}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:     fake.NewClientBuilder().WithScheme(scheme).Build(),
		Programmer: programmer,
		Applied: map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent{
			deletedPolicy: {
				{Namespace: testServiceRouteTenantNamespace, Name: testServiceRouteConsumerName}: {
					Attachment: types.NamespacedName{
						Namespace: testServiceRouteTenantNamespace,
						Name:      testServiceRouteConsumerName,
					},
				},
			},
		},
	}

	err := reconciler.syncAllPolicies(context.Background())
	if err == nil {
		t.Fatal("syncAllPolicies succeeded, want injected removal failure")
	}
	if !startupSyncNeedsRetry(err) {
		t.Fatalf("startup sync error %v is not retryable", err)
	}
	if programmer.finalizeCalls != 0 || !programmer.staleAuthorization {
		t.Fatalf("Finalize calls/stale authorization after removal failure = %d/%t, want 0/true",
			programmer.finalizeCalls, programmer.staleAuthorization)
	}
}

func TestServiceRouteStartupPermanentApplyFailureDoesNotRetryFinalizedGlobalSync(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	const node = "node-a"
	policy := &networkv1alpha1.ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testServiceRoutePolicyNamespace, Name: "a-bad", UID: "bad-policy-uid",
		},
		Spec: networkv1alpha1.ServiceRoutePolicySpec{
			ServiceRef: networkv1alpha1.ServiceEndpointReference{Name: testServiceRouteName},
			AttachmentSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{testServiceRouteAccessLabel: "bad"},
			},
		},
	}
	goodPolicy := policy.DeepCopy()
	goodPolicy.Name = "z-good"
	goodPolicy.UID = "good-policy-uid"
	goodPolicy.Spec.AttachmentSelector.MatchLabels[testServiceRouteAccessLabel] = "good"
	endpoint := &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName, UID: "endpoint-uid",
		},
		Spec: networkv1alpha1.ServiceEndpointSpec{
			Address: "10.0.0.53", Protocol: networkv1alpha1.NetworkRuleProtocolUDP, Port: 53,
			DeliveryMode:       networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal,
			AttachmentSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"producer": "yes"}},
		},
	}
	readyAttachment := func(namespace, name, host string, labels map[string]string) *cloudv1alpha1.VPCAttachment {
		return &cloudv1alpha1.VPCAttachment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:  namespace,
				Name:       name,
				UID:        types.UID(name + "-uid"),
				Generation: 1,
				Labels:     labels,
			},
			Status: cloudv1alpha1.VPCAttachmentStatus{
				ObservedGeneration: 1, Node: node, VPC: "vpc-a", VPCAttachment: "attachment-" + name,
				HostInterface: host,
				Conditions: []metav1.Condition{
					{Type: cloudv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue},
					{Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue},
				},
			},
		}
	}
	consumer := readyAttachment(
		testServiceRouteTenantNamespace,
		testServiceRouteConsumerName,
		"consumer0",
		map[string]string{testServiceRouteAccessLabel: "bad"},
	)
	goodConsumer := readyAttachment(
		testServiceRouteTenantNamespace,
		"good-consumer",
		"consumer1",
		map[string]string{testServiceRouteAccessLabel: "good"},
	)
	producer := readyAttachment("service", "producer", "producer0", map[string]string{"producer": "yes"})
	programmer := &retryRouteProgrammer{failAttachment: consumer.Name, staleAuthorization: true}
	reconciler := &ServiceRoutePolicyReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			policy, goodPolicy, endpoint, consumer, goodConsumer, producer,
		).Build(),
		NodeName:   node,
		Programmer: programmer,
	}

	if err := reconciler.runStartupSync(context.Background()); err != nil {
		t.Fatalf("runStartupSync: %v", err)
	}
	if programmer.applyCalls != 2 {
		t.Fatalf("Apply calls = %d, want 2 (independent policy was not attempted)", programmer.applyCalls)
	}
	if programmer.finalizeCalls != 1 || programmer.staleAuthorization {
		t.Fatalf("Finalize calls/stale authorization = %d/%t, want 1/false",
			programmer.finalizeCalls, programmer.staleAuthorization)
	}
	if programmer.initializeCalls != 1 {
		t.Fatalf("Initialize calls = %d, want one global sync attempt", programmer.initializeCalls)
	}
	failedPolicyKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
	if _, retained := reconciler.Applied[failedPolicyKey]; retained {
		t.Fatal("failed policy retained desired refs and would be exempt from sweep")
	}
	goodPolicyKey := types.NamespacedName{Namespace: goodPolicy.Namespace, Name: goodPolicy.Name}
	if _, retained := reconciler.Applied[goodPolicyKey]; !retained {
		t.Fatal("independent valid policy was not retained after another policy failed")
	}

	rollbackFailure := errors.New("rollback cleanup failed")
	blockedProgrammer := &retryRouteProgrammer{
		failAttachment: consumer.Name,
		cleanupErr:     rollbackFailure,
	}
	blockedReconciler := &ServiceRoutePolicyReconciler{
		Client:     reconciler.Client,
		NodeName:   node,
		Programmer: blockedProgrammer,
	}
	err := blockedReconciler.syncAllPolicies(context.Background())
	if err == nil || !errors.Is(err, rollbackFailure) || !startupSyncNeedsRetry(err) {
		t.Fatalf("syncAllPolicies error = %v, want retryable rollback failure", err)
	}
	if blockedProgrammer.finalizeCalls != 0 {
		t.Fatalf("Finalize calls with unresolved rollback = %d, want 0", blockedProgrammer.finalizeCalls)
	}
}

func TestServiceRouteSIDResolverUsesConfiguredBGPNamespace(t *testing.T) {
	const (
		bgpNamespace = "routing-system"
		node         = testNAT66NodeB
		vpc          = "vpc-b"
		locator      = "fd00:1234::/48"
		vrfID        = int32(42)
	)
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: "router-b"},
		Spec: networkv1alpha1.BGPRouterSpec{
			TargetRef: networkv1alpha1.TargetRef{Name: node}, SRv6Locator: locator, NodeID: 7,
		},
	}
	vrf := &networkv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: crdnames.BGPVRFInstanceName(vpc, node)},
		Spec: networkv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: router.Name}},
			VRFID:        vrfID,
		},
	}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, vrf).Build(),
		BGPNamespace: bgpNamespace,
	}
	attachment := &cloudv1alpha1.VPCAttachment{Status: cloudv1alpha1.VPCAttachmentStatus{Node: node, VPC: vpc}}
	got, err := reconciler.sidResolver(context.Background())(attachment)
	if err != nil {
		t.Fatalf("resolve SID: %v", err)
	}
	want, err := srv6.ComputeSID(locator, 7, vrfID, networkv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(net.IP(want.AsSlice())) {
		t.Fatalf("SID = %s, want %s", got, want)
	}
}

func TestServiceRouteSIDResolverRejectsWrongRouterNode(t *testing.T) {
	const bgpNamespace = "routing-system"
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: "router-b"},
		Spec: networkv1alpha1.BGPRouterSpec{
			TargetRef: networkv1alpha1.TargetRef{Name: "wrong-node"}, SRv6Locator: "fd00:1234::/48", NodeID: 7,
		},
	}
	vrf := &networkv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: bgpNamespace, Name: crdnames.BGPVRFInstanceName("vpc-b", testNAT66NodeB),
		},
		Spec: networkv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: router.Name}},
			VRFID:        42,
		},
	}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, vrf).Build(),
		BGPNamespace: bgpNamespace,
	}
	attachment := &cloudv1alpha1.VPCAttachment{
		Status: cloudv1alpha1.VPCAttachmentStatus{Node: testNAT66NodeB, VPC: "vpc-b"},
	}
	if _, err := reconciler.sidResolver(context.Background())(attachment); err == nil {
		t.Fatal("resolve SID succeeded for a router targeting the wrong node")
	}
}
