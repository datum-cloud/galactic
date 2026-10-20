// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// markIPv4Loaded records on rule that gateway node testNodeGWA has its IPv4
// VIP loaded, the signal the binding writer waits for.
func markIPv4Loaded(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.NetworkService {
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type: ipv4ServedConditionType(testNodeGWA), Status: metav1.ConditionFalse, Reason: reasonIPv4NotAdvertised,
	})
	return rule
}

// bindingsByVIP returns rule's bindings in the test namespace keyed by VIP.
func bindingsByVIP(t *testing.T, c client.Client, rule string) map[string][]bgpv1alpha1.ServiceVIPBinding {
	t.Helper()
	out := map[string][]bgpv1alpha1.ServiceVIPBinding{}
	for _, b := range listBindings(t, c) {
		if b.Labels[networkRuleLabel] == rule {
			out[b.Spec.VIPAddress] = append(out[b.Spec.VIPAddress], b)
		}
	}
	return out
}

// TestNetworkServiceBindingReconciler_WritesBindingPerFamily: a rule with an
// IPv6 and an IPv4 VIP gets one binding per family for a backend with an
// address of each, the IPv6 VIP's to the IPv6 address and the IPv4 VIP's to
// the IPv4 address, under distinct names. A VIP the spec writes IPv4-mapped
// is bound in its plain form.
func TestNetworkServiceBindingReconciler_WritesBindingPerFamily(t *testing.T) {
	for _, ipv4VIP := range []string{testVIP4, "::ffff:" + testVIP4} {
		t.Run(ipv4VIP, func(t *testing.T) {
			rule := markIPv4Loaded(newBindingTestRule())
			rule.Spec.VIPAddresses = []string{testBindingVIP, ipv4VIP}
			r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef, testBackendAddr, testBackendAddr4))

			reconcileBindings(t, r)

			byVIP := bindingsByVIP(t, c, testRuleName)
			if len(byVIP) != 2 || len(byVIP[testBindingVIP]) != 1 || len(byVIP[testVIP4]) != 1 {
				t.Fatalf("bindings by VIP = %+v, want one for %s and one for %s", byVIP, testBindingVIP, testVIP4)
			}
			v6, v4 := byVIP[testBindingVIP][0], byVIP[testVIP4][0]
			if v6.Spec.BackendAddress != testBackendAddr || v4.Spec.BackendAddress != testBackendAddr4 {
				t.Errorf("backends = %s for IPv6, %s for IPv4; want %s and %s",
					v6.Spec.BackendAddress, v4.Spec.BackendAddress, testBackendAddr, testBackendAddr4)
			}
			wantName := crdnames.ServiceVIPBindingName(
				testRuleName, testComputeNodeName, testVIP4, testBackendAddr4, testBackendPort)
			if v4.Name != wantName || v4.Name == v6.Name {
				t.Errorf("IPv4 binding name = %q (IPv6 %q), want %q", v4.Name, v6.Name, wantName)
			}
		})
	}
}

// TestNetworkServiceBindingReconciler_IPv4VIPNeedsIPv4Backend: an attachment
// with no IPv4 address is no backend for the IPv4 VIP, and one with no IPv6
// address none for the IPv6 VIP.
func TestNetworkServiceBindingReconciler_IPv4VIPNeedsIPv4Backend(t *testing.T) {
	r, c := newBindingWriter(t, markIPv4Loaded(newBindingTestRule()), newBackendAttachment(testVPCRef, testBackendAddr4))

	reconcileBindings(t, r)

	byVIP := bindingsByVIP(t, c, testRuleName)
	if len(byVIP) != 1 || len(byVIP[testVIP4]) != 1 {
		t.Errorf("bindings by VIP = %+v, want only the IPv4 VIP's", byVIP)
	}
}

// TestNetworkServiceBindingReconciler_SecondIPv4VIP: a rule with two IPv4
// VIPs reports InvalidRule, keeps the IPv4 binding it already has untouched,
// and keeps its IPv6 VIP's bindings current.
func TestNetworkServiceBindingReconciler_SecondIPv4VIP(t *testing.T) {
	rule := markIPv4Loaded(newBindingTestRule())
	attachment := newBackendAttachment(testVPCRef, testBackendAddr, testBackendAddr4)
	r, c := newBindingWriter(t, rule, attachment)
	reconcileBindings(t, r)
	before := bindingsByVIP(t, c, testRuleName)[testVIP4]
	if len(before) != 1 {
		t.Fatalf("IPv4 bindings while valid = %d, want 1", len(before))
	}
	ipv6Before := bindingsByVIP(t, c, testRuleName)[testBindingVIP]
	if len(ipv6Before) != 1 {
		t.Fatalf("IPv6 bindings while valid = %d, want 1", len(ipv6Before))
	}

	current := getBindingRule(t, c)
	current.Spec.VIPAddresses = append(current.Spec.VIPAddresses, "198.51.100.33")
	if err := c.Update(context.Background(), current); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	// A second IPv6 backend appears: the IPv6 VIP's bindings must follow it.
	att := attachment.DeepCopy()
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(attachment), att); err != nil {
		t.Fatalf("get attachment: %v", err)
	}
	att.Spec.Interface.Addresses = append(att.Spec.Interface.Addresses, "fd00:10::2/64")
	if err := c.Update(context.Background(), att); err != nil {
		t.Fatalf("update attachment: %v", err)
	}
	reconcileBindings(t, r)

	byVIP := bindingsByVIP(t, c, testRuleName)
	if got := byVIP[testVIP4]; len(got) != 1 || got[0].ResourceVersion != before[0].ResourceVersion {
		t.Errorf("IPv4 bindings = %+v, want %s untouched at resourceVersion %s",
			got, before[0].Name, before[0].ResourceVersion)
	}
	if len(byVIP["198.51.100.33"]) != 0 {
		t.Errorf("second IPv4 VIP got bindings: %+v", byVIP["198.51.100.33"])
	}
	if got := backendAddresses(byVIP[testBindingVIP]); len(got) != 2 {
		t.Errorf("IPv6 bindings = %v, want both IPv6 backends", got)
	}
	cond := meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions,
		backendsBoundConditionType(testComputeNodeName))
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonBindingsInvalid ||
		!strings.Contains(cond.Message, "2 IPv4 VIPs") {
		t.Errorf("BackendsBound = %+v, want False/%s naming 2 IPv4 VIPs", cond, reasonBindingsInvalid)
	}
}

// newIPv4SharingRule returns newSharingBindingRule with vips in place of its
// IPv6 VIP.
func newIPv4SharingRule(name string, created int64, vips ...string) *bgpv1alpha1.NetworkService {
	rule := newSharingBindingRule(name, testBindingVIP, created, testBackendPort)
	rule.Spec.VIPAddresses = vips
	return rule
}

// TestNetworkServiceBindingReconciler_IPv4SharedBackendServesOldestRule: two
// rules selecting one IPv4 backend on one backend port and protocol: only the
// older rule gets a binding, and the newer one reports the backend claimed.
func TestNetworkServiceBindingReconciler_IPv4SharedBackendServesOldestRule(t *testing.T) {
	older := markIPv4Loaded(newIPv4SharingRule(testOlderRule, 100, testVIP4))
	newer := markIPv4Loaded(newIPv4SharingRule(testNewerRule, 200, "198.51.100.33"))
	r, c := newBindingWriter(t, newer, older, newBackendAttachment(testVPCRef, testBackendAddr4))

	reconcileRule(t, r, testNewerRule)
	reconcileRule(t, r, testOlderRule)

	if got := bindingsByVIP(t, c, testOlderRule)[testVIP4]; len(got) != 1 {
		t.Errorf("older rule's IPv4 bindings = %d, want 1", len(got))
	}
	if got := bindingsByVIP(t, c, testNewerRule); len(got) != 0 {
		t.Errorf("newer rule's bindings = %+v, want none", got)
	}
	current := &bgpv1alpha1.NetworkService{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: testNewerRule},
		current); err != nil {
		t.Fatalf("get newer rule: %v", err)
	}
	cond := meta.FindStatusCondition(current.Status.Conditions, backendsBoundConditionType(testComputeNodeName))
	if cond == nil || cond.Reason != reasonBindingsClaimed {
		t.Errorf("newer rule BackendsBound = %+v, want %s", cond, reasonBindingsClaimed)
	}
}

// TestNetworkServiceBindingReconciler_IPv4AndIPv6ClaimsAreDistinct: an
// IPv6-only rule and a newer IPv4-only rule selecting one attachment on the
// same backend port and protocol each serve their own family's address of it:
// their replies are rewritten by different rows.
func TestNetworkServiceBindingReconciler_IPv4AndIPv6ClaimsAreDistinct(t *testing.T) {
	older := newSharingBindingRule(testOlderRule, testBindingVIP, 100, testBackendPort)
	newer := markIPv4Loaded(newIPv4SharingRule(testNewerRule, 200, testVIP4))
	r, c := newBindingWriter(t, newer, older, newBackendAttachment(testVPCRef, testBackendAddr, testBackendAddr4))

	reconcileRule(t, r, testNewerRule)
	reconcileRule(t, r, testOlderRule)

	if got := bindingsByVIP(t, c, testOlderRule)[testBindingVIP]; len(got) != 1 ||
		got[0].Spec.BackendAddress != testBackendAddr {
		t.Errorf("older IPv6 rule's bindings = %+v, want one to %s", got, testBackendAddr)
	}
	if got := bindingsByVIP(t, c, testNewerRule)[testVIP4]; len(got) != 1 ||
		got[0].Spec.BackendAddress != testBackendAddr4 {
		t.Errorf("newer IPv4 rule's bindings = %+v, want one to %s", got, testBackendAddr4)
	}
}

// TestNetworkServiceBindingReconciler_IPv4BindingsFollowGatewayLoad: a rule
// with an IPv4 VIP no gateway node has loaded, such as one created before
// admission refused IPv4 VIPs on a cell whose gateways leave them out, gets no
// IPv4 binding. Once a node reports it loaded the binding appears, and once
// no node does it is deleted. The IPv6 binding is never touched.
func TestNetworkServiceBindingReconciler_IPv4BindingsFollowGatewayLoad(t *testing.T) {
	r, c := newBindingWriter(t, newBindingTestRule(), newBackendAttachment(testVPCRef, testBackendAddr, testBackendAddr4))
	reconcileBindings(t, r)

	ipv6 := bindingsByVIP(t, c, testRuleName)[testBindingVIP]
	if len(ipv6) != 1 {
		t.Fatalf("IPv6 bindings = %d, want 1", len(ipv6))
	}
	requireIPv6Unchanged := func(stage string) {
		t.Helper()
		got := bindingsByVIP(t, c, testRuleName)[testBindingVIP]
		if len(got) != 1 || got[0].ResourceVersion != ipv6[0].ResourceVersion {
			t.Errorf("%s: IPv6 bindings = %+v, want %s unchanged", stage, got, ipv6[0].Name)
		}
	}
	setIPv4Served := func(reason string) {
		t.Helper()
		rule := getBindingRule(t, c)
		meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
			Type: ipv4ServedConditionType(testNodeGWA), Status: metav1.ConditionFalse, Reason: reason,
		})
		if err := c.Status().Update(context.Background(), rule); err != nil {
			t.Fatalf("update rule status: %v", err)
		}
		reconcileBindings(t, r)
	}

	if got := bindingsByVIP(t, c, testRuleName)[testVIP4]; len(got) != 0 {
		t.Errorf("IPv4 bindings with no gateway loading the VIP = %d, want 0", len(got))
	}

	setIPv4Served(reasonIPv4Unsupported)
	if got := bindingsByVIP(t, c, testRuleName)[testVIP4]; len(got) != 0 {
		t.Errorf("IPv4 bindings while the gateway reports %s = %d, want 0", reasonIPv4Unsupported, len(got))
	}

	setIPv4Served(reasonIPv4NotAdvertised)
	got := bindingsByVIP(t, c, testRuleName)[testVIP4]
	if len(got) != 1 || got[0].Spec.BackendAddress != testBackendAddr4 {
		t.Errorf("IPv4 bindings once a gateway loads the VIP = %+v, want one to %s", got, testBackendAddr4)
	}
	requireIPv6Unchanged("after the gateway loads the IPv4 VIP")

	rule := getBindingRule(t, c)
	meta.RemoveStatusCondition(&rule.Status.Conditions, ipv4ServedConditionType(testNodeGWA))
	if err := c.Status().Update(context.Background(), rule); err != nil {
		t.Fatalf("update rule status: %v", err)
	}
	reconcileBindings(t, r)
	if got := bindingsByVIP(t, c, testRuleName)[testVIP4]; len(got) != 0 {
		t.Errorf("IPv4 bindings once no gateway loads the VIP = %+v, want none", got)
	}
	requireIPv6Unchanged("after the gateway drops the IPv4 VIP")
}

// TestRuleBindingInputsChanged_IPv4Load: a status-only change to whether some
// gateway node has the rule's IPv4 VIP loaded passes the predicate, and other
// status changes do not.
func TestRuleBindingInputsChanged_IPv4Load(t *testing.T) {
	oldRule := newBindingTestRule()
	loaded := markIPv4Loaded(oldRule.DeepCopy())
	otherStatus := oldRule.DeepCopy()
	meta.SetStatusCondition(&otherStatus.Status.Conditions, metav1.Condition{
		Type: ipv4ServedConditionType(testNodeGWA), Status: metav1.ConditionFalse, Reason: reasonIPv4NoBackend,
	})
	p := ruleBindingInputsChanged()
	if !p.Update(event.UpdateEvent{ObjectOld: oldRule, ObjectNew: loaded}) {
		t.Error("IPv4 VIP becoming loaded on a gateway: predicate dropped the event")
	}
	if !p.Update(event.UpdateEvent{ObjectOld: loaded, ObjectNew: oldRule}) {
		t.Error("IPv4 VIP no longer loaded on any gateway: predicate dropped the event")
	}
	if p.Update(event.UpdateEvent{ObjectOld: oldRule, ObjectNew: otherStatus}) {
		t.Error("IPv4Served change that loads nothing: predicate passed the event")
	}
}
