// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"net"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testNodeName       = "node-a"
	testRemoteNodeName = "node-b"
	testAccessLabel    = "access"
	testProducerLabel  = "producer"
)

func testLabels(key, value string) map[string]string { return map[string]string{key: value} }

func readyAttachment(namespace, name, uid, node, host string, labels map[string]string) *cloudv1alpha1.VPCAttachment {
	return &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid), Generation: 3, Labels: labels},
		Status: cloudv1alpha1.VPCAttachmentStatus{
			ObservedGeneration: 3, Node: node, VPC: "vpc-" + node, VPCAttachment: "attachment-" + name,
			HostInterface: host,
			Conditions: []metav1.Condition{
				{Type: cloudv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue},
				{Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue},
			},
		},
	}
}

func testPolicyAndEndpoint(mode networkv1alpha1.ServiceEndpointDeliveryMode) (
	*networkv1alpha1.ServiceRoutePolicy, *networkv1alpha1.ServiceEndpoint,
) {
	policy := &networkv1alpha1.ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "platform", UID: "policy-uid"},
		Spec: networkv1alpha1.ServiceRoutePolicySpec{
			ServiceRef:         networkv1alpha1.ServiceEndpointReference{Name: "dns"},
			AttachmentSelector: metav1.LabelSelector{MatchLabels: testLabels(testAccessLabel, "yes")},
		},
	}
	endpoint := &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "platform", UID: "endpoint-uid"},
		Spec: networkv1alpha1.ServiceEndpointSpec{
			Address: "fd00::53", Protocol: networkv1alpha1.NetworkRuleProtocolUDP, Port: 53, DeliveryMode: mode,
			AttachmentSelector: &metav1.LabelSelector{MatchLabels: testLabels(testProducerLabel, "yes")},
		},
	}
	return policy, endpoint
}

func TestCompilePreferNodeLocalIgnoresInputOrder(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	remote := readyAttachment(
		"service", "a-remote", "remote-uid", testRemoteNodeName, "remote0", testLabels(testProducerLabel, "yes"),
	)
	local := readyAttachment(
		"service", "z-local", "local-uid", testNodeName, "local0", testLabels(testProducerLabel, "yes"),
	)

	got, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{remote, consumer, local}, testNodeName, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 1 || got[0].Kind != RouteIntentLocal || got[0].ServiceDevice != "local0" {
		t.Fatalf("intents = %+v, want one local intent through local0", got)
	}
}

func TestCompileDirectVIPSelectsOneExactLocalProducer(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	first := readyAttachment(
		"service", "a-producer", "first-uid", testNodeName, "producer-a", testLabels(testProducerLabel, "yes"),
	)
	last := readyAttachment(
		"service", "z-producer", "last-uid", testNodeName, "producer-z", testLabels(testProducerLabel, "yes"),
	)
	first.Status.VPC = "service-vpc-a"
	last.Status.VPC = "service-vpc-z"

	got, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{last, consumer, first}, testNodeName, nil,
	)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	wantProducer := types.NamespacedName{Namespace: first.Namespace, Name: first.Name}
	if len(got) != 1 || got[0].Kind != RouteIntentLocal || got[0].ProducerAttachment != wantProducer ||
		got[0].ServiceDevice != first.Status.HostInterface {
		t.Fatalf("intents = %+v, want one local intent through %s on %s", got, wantProducer, first.Status.HostInterface)
	}
	if got[0].Service.String() != endpoint.Spec.Address+"/128" {
		t.Fatalf("service destination = %s, want declared endpoint %s/128 unchanged", got[0].Service, endpoint.Spec.Address)
	}
}

func TestCompileRejectsAmbiguousProducerTopology(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	first := readyAttachment(
		"service", "a-producer", "first-uid", testNodeName, "producer-a", testLabels(testProducerLabel, "yes"),
	)
	last := readyAttachment(
		"service", "z-producer", "last-uid", testNodeName, "producer-z", testLabels(testProducerLabel, "yes"),
	)

	_, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{last, consumer, first}, testNodeName, nil,
	)
	if err == nil {
		t.Fatal("Compile succeeded with two ready producers on the same node and VPC")
	}
	for _, want := range []string{
		"service/a-producer", "service/z-producer", `node "node-a"`, `VPC "vpc-node-a"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Compile error = %q, want it to contain %q", err, want)
		}
	}
}

func TestCompileAllowsDistinguishableProducerTopologies(t *testing.T) {
	tests := []struct {
		name      string
		configure func(first, last *cloudv1alpha1.VPCAttachment)
	}{
		{
			name: "different nodes",
			configure: func(_ *cloudv1alpha1.VPCAttachment, last *cloudv1alpha1.VPCAttachment) {
				last.Status.Node = testRemoteNodeName
				last.Status.VPC = "vpc-" + testRemoteNodeName
			},
		},
		{
			name: "different VPCs on one node",
			configure: func(first, last *cloudv1alpha1.VPCAttachment) {
				first.Status.VPC = "service-vpc-a"
				last.Status.VPC = "service-vpc-z"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
			consumer := readyAttachment(
				"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
			)
			first := readyAttachment(
				"service", "a-producer", "first-uid", testNodeName, "producer-a", testLabels(testProducerLabel, "yes"),
			)
			last := readyAttachment(
				"service", "z-producer", "last-uid", testNodeName, "producer-z", testLabels(testProducerLabel, "yes"),
			)
			tt.configure(first, last)

			got, err := Compile(
				policy, endpoint, []*cloudv1alpha1.VPCAttachment{last, consumer, first}, testNodeName,
				func(*cloudv1alpha1.VPCAttachment) (net.IP, error) { return net.ParseIP("fd00::b"), nil },
			)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			wantProducer := types.NamespacedName{Namespace: first.Namespace, Name: first.Name}
			if len(got) != 1 || got[0].ProducerAttachment != wantProducer {
				t.Fatalf("intents = %+v, want selected producer %s", got, wantProducer)
			}
		})
	}
}

func TestCompileUsesObservedNodeAndSelector(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	endpoint.Spec.AttachmentSelector = nil
	endpoint.Spec.AttachmentRef = &networkv1alpha1.ServiceEndpointAttachmentReference{
		Namespace: "service", Name: "producer",
	}
	consumer := readyAttachment(
		"tenant", "selected", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	producer := readyAttachment("service", "producer", "producer-uid", testNodeName, "producer0", nil)
	otherNode := readyAttachment(
		"tenant", "other-node", "other-uid", testRemoteNodeName, "other0", testLabels(testAccessLabel, "yes"),
	)
	notSelected := readyAttachment(
		"tenant", "not-selected", "not-selected-uid", testNodeName, "disabled0", testLabels(testAccessLabel, "no"),
	)

	got, err := Compile(policy, endpoint,
		[]*cloudv1alpha1.VPCAttachment{otherNode, notSelected, producer, consumer}, testNodeName, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 1 || got[0].Attachment != (types.NamespacedName{Namespace: "tenant", Name: "selected"}) {
		t.Fatalf("intents = %+v, want selected attachment only", got)
	}
	if got[0].Service.String() != "fd00::53/128" {
		t.Fatalf("service prefix = %s", got[0].Service)
	}
}

func TestCompileUsesEndpointPortByDefault(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	policy.Spec.ProtocolPorts = nil
	endpoint.Spec.Address = "192.0.2.10"
	endpoint.Spec.Protocol = networkv1alpha1.NetworkRuleProtocolTCP
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	producer := readyAttachment(
		"service", "producer", "producer-uid", testNodeName, "producer0", testLabels(testProducerLabel, "yes"),
	)

	got, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{consumer, producer}, testNodeName, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 1 || len(got[0].Ports) != 1 || got[0].Ports[0].Port != 53 ||
		got[0].Ports[0].Protocol != networkv1alpha1.NetworkRuleProtocolTCP {
		t.Fatalf("ports = %+v", got[0].Ports)
	}
}

func TestCompilePreferNodeLocalBuildsMatchingRemoteHalves(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	producer := readyAttachment(
		"service", "producer", "producer-uid", testRemoteNodeName, "producer0", testLabels(testProducerLabel, "yes"),
	)
	resolver := func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		if attachment.Status.Node == testNodeName {
			return net.ParseIP("fd00::a"), nil
		}
		return net.ParseIP("fd00::b"), nil
	}

	consumerIntents, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{producer, consumer}, testNodeName, resolver,
	)
	if err != nil {
		t.Fatalf("Compile consumer node: %v", err)
	}
	producerIntents, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{consumer, producer}, testRemoteNodeName, resolver,
	)
	if err != nil {
		t.Fatalf("Compile producer node: %v", err)
	}
	if len(consumerIntents) != 1 || consumerIntents[0].Kind != RouteIntentRemoteConsumer ||
		!consumerIntents[0].ServiceSID.Equal(net.ParseIP("fd00::b")) {
		t.Fatalf("consumer intents = %+v", consumerIntents)
	}
	if len(producerIntents) != 1 || producerIntents[0].Kind != RouteIntentRemoteProducer ||
		!producerIntents[0].ConsumerSID.Equal(net.ParseIP("fd00::a")) {
		t.Fatalf("producer intents = %+v", producerIntents)
	}
	if consumerIntents[0].GrantID == (ServiceGrantID{}) || consumerIntents[0].GrantID != producerIntents[0].GrantID {
		t.Fatalf("grant IDs differ or are zero: %x / %x", consumerIntents[0].GrantID, producerIntents[0].GrantID)
	}
}

func TestCompileNodeLocalDoesNotUseRemoteProducer(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	producer := readyAttachment(
		"service", "producer", "producer-uid", testRemoteNodeName, "producer0", testLabels(testProducerLabel, "yes"),
	)
	got, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{consumer, producer}, testNodeName,
		func(*cloudv1alpha1.VPCAttachment) (net.IP, error) { return net.ParseIP("fd00::b"), nil })
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("intents = %+v, want none", got)
	}
}

func TestCompileSkipsUnreadyLocalProducerAndFallsBackRemote(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	local := readyAttachment(
		"service", "local", "local-uid", testNodeName, "local0", testLabels(testProducerLabel, "yes"),
	)
	local.Status.Conditions[1].Status = metav1.ConditionFalse
	remote := readyAttachment(
		"service", "remote", "remote-uid", testRemoteNodeName, "remote0", testLabels(testProducerLabel, "yes"),
	)
	got, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{local, remote, consumer}, testNodeName,
		func(*cloudv1alpha1.VPCAttachment) (net.IP, error) { return net.ParseIP("fd00::b"), nil })
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 1 || got[0].Kind != RouteIntentRemoteConsumer {
		t.Fatalf("intents = %+v, want remote consumer fallback", got)
	}
}

func TestCompileClassifiesUnavailableRemoteSIDAsDependencyNotReady(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	producer := readyAttachment(
		"service", "producer", "producer-uid", testRemoteNodeName, "producer0", testLabels(testProducerLabel, "yes"),
	)
	want := errors.New("routing dependency unavailable")
	_, err := Compile(policy, endpoint, []*cloudv1alpha1.VPCAttachment{consumer, producer}, testNodeName,
		func(*cloudv1alpha1.VPCAttachment) (net.IP, error) { return nil, want })
	var dependencyErr *DependencyNotReadyError
	if !errors.As(err, &dependencyErr) || !errors.Is(err, want) {
		t.Fatalf("Compile error = %v, want DependencyNotReadyError wrapping %v", err, want)
	}
}

func TestCompilePreferNodeLocalSelectsStableRemoteFallback(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment(
		"tenant", "consumer", "consumer-uid", testNodeName, "consumer0", testLabels(testAccessLabel, "yes"),
	)
	first := readyAttachment(
		"service", "a-remote", "first-uid", testRemoteNodeName, "first0", testLabels(testProducerLabel, "yes"),
	)
	last := readyAttachment(
		"service", "z-remote", "last-uid", "node-c", "last0", testLabels(testProducerLabel, "yes"),
	)
	resolver := func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		if attachment.Name == first.Name {
			return net.ParseIP("fd00::b"), nil
		}
		return net.ParseIP("fd00::c"), nil
	}

	one, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{last, consumer, first}, testNodeName, resolver,
	)
	if err != nil {
		t.Fatalf("Compile first order: %v", err)
	}
	two, err := Compile(
		policy, endpoint, []*cloudv1alpha1.VPCAttachment{first, last, consumer}, testNodeName, resolver,
	)
	if err != nil {
		t.Fatalf("Compile second order: %v", err)
	}
	wantProducer := types.NamespacedName{Namespace: first.Namespace, Name: first.Name}
	for _, intents := range [][]RouteIntent{one, two} {
		if len(intents) != 1 || intents[0].Kind != RouteIntentRemoteConsumer ||
			intents[0].ProducerAttachment != wantProducer || !intents[0].ServiceSID.Equal(net.ParseIP("fd00::b")) {
			t.Fatalf("intents = %+v, want stable fallback through %s", intents, wantProducer)
		}
	}
	if one[0].GrantID == (ServiceGrantID{}) || one[0].GrantID != two[0].GrantID {
		t.Fatalf("grant ID changed with input order: %x / %x", one[0].GrantID, two[0].GrantID)
	}
}

func TestServiceGrantIDCanonicalizesPortOrder(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment("tenant", "consumer", "consumer-uid", testNodeName, "consumer0", nil)
	producer := readyAttachment("service", "producer", "producer-uid", "node-b", "producer0", nil)
	ports := []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}}
	a := clonePorts(ports)
	b := clonePorts(ports)
	sortPorts := func(p []networkv1alpha1.ServiceRouteProtocolPort) {
		if p[0].Protocol > p[1].Protocol {
			p[0], p[1] = p[1], p[0]
		}
	}
	sortPorts(a)
	b[0], b[1] = b[1], b[0]
	sortPorts(b)
	idA, err := serviceGrantID(policy, endpoint, consumer, producer, a)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := serviceGrantID(policy, endpoint, consumer, producer, b)
	if err != nil {
		t.Fatal(err)
	}
	if idA != idB {
		t.Fatalf("canonical grant IDs differ: %x / %x", idA, idB)
	}
}
