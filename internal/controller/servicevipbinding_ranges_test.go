// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

type fakeRangeVIPTable struct {
	fakeVIPTable
	removed         []rangeContext
	ingress, egress bool
	failEgress      bool
}

func (f *fakeRangeVIPTable) RegisterIngressRange(uint64, uint16, uint16, uint8, net.IP, uint16, uint16, net.IP) error {
	f.ingress = true
	return nil
}
func (f *fakeRangeVIPTable) RegisterEgressRange(uint64, uint16, uint8, net.IP, uint16, uint16, net.IP) error {
	if f.failEgress {
		return errors.New("egress publication failed")
	}
	f.egress = true
	return nil
}

func (f *fakeRangeVIPTable) UnregisterRangeBindingAt(
	block uint64,
	arg, _ uint16,
	_ uint8,
	_ net.IP,
	_, _ uint16,
	_ net.IP,
) error {
	f.removed = append(f.removed, rangeContext{Block: block, Argument: arg})
	f.ingress = false
	f.egress = false
	return nil
}

func (f *fakeRangeVIPTable) RangeBindingPresent(
	uint64,
	uint16,
	uint16,
	uint8,
	net.IP,
	uint16,
	uint16,
	net.IP,
) (bool, error) {
	return f.ingress && f.egress, nil
}
func (f *fakeRangeVIPTable) ListRanges() ([]vipxlatmap.RangeEntry, error) { return nil, nil }

func rangeBindingFixture() *api.ServiceVIPBinding {
	b := newTestServiceVIPBinding(api.ServiceVIPBindingEgressKindTap, testVIPBindingNode)
	b.Spec.Protocol = api.NetworkServiceProtocolUDP
	b.Spec.Port = 0
	b.Spec.BackendPort = 0
	b.Spec.PortRange = &api.PortRange{Start: 20000, End: 20999}
	return b
}

func TestRangeCleanupReceiptSurvivesRestartAndVRFLoss(t *testing.T) {
	ctx := context.Background()
	b := rangeBindingFixture()
	scheme := newRuleTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(b).Build()
	writer := &ServiceVIPBindingReconciler{Client: c, NodeName: testVIPBindingNode}
	if err := writer.rememberRangeContext(ctx, b, 123, 40); err != nil {
		t.Fatal(err)
	}
	if err := writer.rememberRangeContext(ctx, b, 123, 41); err != nil {
		t.Fatal(err)
	}
	persisted := &api.ServiceVIPBinding{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(b), persisted); err != nil {
		t.Fatal(err)
	}
	table := &fakeRangeVIPTable{}
	restarted := &ServiceVIPBindingReconciler{Client: c, NodeName: testVIPBindingNode, VIPTranslationTable: table}
	if err := restarted.unregisterVIPRange(ctx, persisted); err != nil {
		t.Fatal(err)
	}
	if len(table.removed) != 2 || table.removed[0].Argument != 40 || table.removed[1].Argument != 41 {
		t.Fatalf("cleanup did not use persisted VRF contexts: %+v", table.removed)
	}
}

func TestRangeTranslationRollsBackPartialPublication(t *testing.T) {
	table := &fakeRangeVIPTable{failEgress: true}
	r := &ServiceVIPBindingReconciler{VIPTranslationTable: table}
	rows, err := parseVIPBindingRows(rangeBindingFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.registerVIPRange(rows.at(123, 40)); err == nil {
		t.Fatal("partial publication succeeded")
	}
	if table.ingress || len(table.removed) != 1 {
		t.Fatal("partial ingress row survived rollback")
	}
}

func TestRangeBindingReadinessIncludesRangeAndGeneration(t *testing.T) {
	_, rule := sharedAddressFixture()
	rule.Spec.Protocol = api.NetworkServiceProtocolUDP
	rule.Spec.Port = 0
	rule.Spec.BackendPort = 0
	rule.Spec.PortRange = &api.PortRange{Start: 20000, End: 20999}
	backend := ruleBackend{node: testVIPBindingNode, port: 20000}
	backend.addr = netip.MustParseAddr(testVIPBindingBackendAddr)
	vip := netip.MustParseAddr(rule.Spec.VIPAddresses[0])
	binding := generatedBinding(rule, testNamespace, backend.node, vip, backend)
	binding.Generation = 2
	binding.Status.ObservedGeneration = 1
	binding.Status.Conditions = []metav1.Condition{
		{Type: api.ConditionTypeBound, Status: metav1.ConditionTrue, ObservedGeneration: 1},
	}
	bindings := serviceBindings{binding.Name: binding}
	if bindings.unbound(rule, testNamespace, vip, backend) == "" {
		t.Fatal("stale Bound admitted range")
	}
	binding.Status.ObservedGeneration = 2
	binding.Status.Conditions[0].ObservedGeneration = 2
	if bindings.unbound(rule, testNamespace, vip, backend) == "" {
		t.Fatal("old backend writer admitted coordinated binding")
	}
	binding.Status.SourceAuthorityEnforced = true
	if reason := bindings.unbound(rule, testNamespace, vip, backend); reason != "" {
		t.Fatal(reason)
	}
	binding.Spec.PortRange = nil
	if bindings.unbound(rule, testNamespace, vip, backend) == "" {
		t.Fatal("old schema pruned range admitted")
	}
}
