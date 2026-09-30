// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"testing"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestCompileUsesObservedNodeAndSelector(t *testing.T) {
	policy := &networkv1alpha1.ServiceRoutePolicy{
		Spec: networkv1alpha1.ServiceRoutePolicySpec{
			AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{"egress": "enabled"}},
			ProtocolPorts:      []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: networkv1alpha1.NetworkRuleProtocolUDP, Port: 53}},
		},
	}
	endpoint := &networkv1alpha1.ServiceEndpoint{Spec: networkv1alpha1.ServiceEndpointSpec{
		Address: "fd20:0:21::1:0:0", Port: 53, Protocol: networkv1alpha1.NetworkRuleProtocolUDP,
	}}
	attachments := []*cloudv1alpha1.VPCAttachment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "selected", Labels: map[string]string{"egress": "enabled"}}, Status: cloudv1alpha1.VPCAttachmentStatus{Node: "node-a", PodSubnet: "fd20:0:19::2:0:0/96"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "other-node", Labels: map[string]string{"egress": "enabled"}}, Status: cloudv1alpha1.VPCAttachmentStatus{Node: "node-b", PodSubnet: "fd20:0:20::2:0:0/96"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "not-selected", Labels: map[string]string{"egress": "disabled"}}, Status: cloudv1alpha1.VPCAttachmentStatus{Node: "node-a", PodSubnet: "fd20:0:21::2:0:0/96"}},
	}

	got, err := Compile(policy, endpoint, attachments, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Attachment != (types.NamespacedName{Namespace: "a", Name: "selected"}) {
		t.Fatalf("intents = %+v, want selected attachment only", got)
	}
	if got[0].Service.String() != "fd20:0:21::1:0:0/128" {
		t.Fatalf("service prefix = %s", got[0].Service)
	}
}

func TestCompileUsesEndpointPortByDefault(t *testing.T) {
	policy := &networkv1alpha1.ServiceRoutePolicy{Spec: networkv1alpha1.ServiceRoutePolicySpec{
		AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{"egress": "enabled"}},
	}}
	endpoint := &networkv1alpha1.ServiceEndpoint{Spec: networkv1alpha1.ServiceEndpointSpec{Address: "192.0.2.10", Port: 53, Protocol: networkv1alpha1.NetworkRuleProtocolTCP}}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "selected", Labels: map[string]string{"egress": "enabled"}}, Status: cloudv1alpha1.VPCAttachmentStatus{Node: "node-a", PodSubnet: "fd20::/96"}}

	got, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{attachment}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Ports) != 1 || got[0].Ports[0].Port != 53 || got[0].Ports[0].Protocol != networkv1alpha1.NetworkRuleProtocolTCP {
		t.Fatalf("ports = %+v", got[0].Ports)
	}
}
