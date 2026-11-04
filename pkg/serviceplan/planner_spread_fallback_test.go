// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceplan

import (
	"net"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// unhealthyLocalTopology is a consumer with two producers on its own node and
// one on testRemoteNodeName.
type unhealthyLocalTopology struct {
	policy      *networkv1alpha1.ServiceRoutePolicy
	endpoint    *networkv1alpha1.ServiceEndpoint
	consumer    *cloudv1alpha1.VPCAttachment
	first, last *cloudv1alpha1.VPCAttachment
	remote      *cloudv1alpha1.VPCAttachment
	attachments []*cloudv1alpha1.VPCAttachment
}

func newUnhealthyLocalTopology(mode networkv1alpha1.ServiceEndpointDeliveryMode) *unhealthyLocalTopology {
	policy, endpoint := spreadEndpoint(mode)
	topology := &unhealthyLocalTopology{
		policy: policy, endpoint: endpoint, consumer: spreadConsumer(),
		first: readyAttachment(spreadProducerNamespace, "a-producer", "first-uid", testNodeName, "producer-a",
			testLabels(testProducerLabel, "yes")),
		last: readyAttachment(spreadProducerNamespace, "z-producer", "last-uid", testNodeName, "producer-z",
			testLabels(testProducerLabel, "yes")),
		remote: readyAttachment(spreadProducerNamespace, firstRemoteProducer, "remote-uid", testRemoteNodeName,
			"remote-a", testLabels(testProducerLabel, "yes")),
	}
	topology.attachments = []*cloudv1alpha1.VPCAttachment{
		topology.consumer, topology.first, topology.last, topology.remote,
	}
	return topology
}

func (topology *unhealthyLocalTopology) compile(t *testing.T, node string, pairing SpreadPairing) []RouteIntent {
	t.Helper()
	resolver := func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		return net.ParseIP("fd00::" + string(attachment.UID[0])), nil
	}
	got, err := CompileWithOptions(topology.policy, topology.endpoint, topology.attachments, node, resolver,
		CompileOptions{SpreadPairing: pairing})
	if err != nil {
		t.Fatalf("Compile on %s: %v", node, err)
	}
	return got
}

func (topology *unhealthyLocalTopology) planNodes(t *testing.T) []string {
	t.Helper()
	plan, err := ProgrammingPlan(topology.policy, topology.endpoint, topology.attachments, "")
	if err != nil {
		t.Fatalf("ProgrammingPlan: %v", err)
	}
	return plan.Nodes
}

// requireLocal fails unless the consumer's node holds one LocalSet intent
// whose producers are want, the producer node holds nothing, and the plan
// needs the consumer's node alone.
func (topology *unhealthyLocalTopology) requireLocal(t *testing.T, want string) {
	t.Helper()
	for _, pairing := range spreadPairings {
		got := topology.compile(t, testNodeName, pairing)
		if len(got) != 1 || got[0].Kind != RouteIntentLocalSet {
			t.Fatalf("%s: consumer node intents = %+v, want one LocalSet intent", pairing, got)
		}
		if summary := producerSummary(got[0]); summary != want {
			t.Fatalf("%s: producers = %s, want %s", pairing, summary, want)
		}
		if got := topology.compile(t, testRemoteNodeName, pairing); len(got) != 0 {
			t.Fatalf("%s: producer node intents = %+v, want none", pairing, got)
		}
	}
	if nodes := topology.planNodes(t); !slices.Equal(nodes, []string{testNodeName}) {
		t.Fatalf("ProgrammingPlan nodes = %v, want [%s]", nodes, testNodeName)
	}
}

// requireRemote fails unless, under every pairing, the consumer's node sends
// the consumer to the remote producer, the producer's node accepts it, and
// the plan needs both nodes.
func (topology *unhealthyLocalTopology) requireRemote(t *testing.T) {
	t.Helper()
	remoteKey := types.NamespacedName{Namespace: topology.remote.Namespace, Name: topology.remote.Name}
	for _, pairing := range spreadPairings {
		got := topology.compile(t, testNodeName, pairing)
		if len(got) != 1 || got[0].Kind != RouteIntentRemoteConsumer || got[0].ProducerAttachment != remoteKey {
			t.Fatalf("%s: consumer node intents = %+v, want one RemoteConsumer intent to %s", pairing, got, remoteKey)
		}
		got = topology.compile(t, testRemoteNodeName, pairing)
		if len(got) != 1 || got[0].Kind != RouteIntentRemoteProducer || got[0].ProducerAttachment != remoteKey ||
			got[0].Attachment.Name != topology.consumer.Name {
			t.Fatalf("%s: producer node intents = %+v, want one RemoteProducer half for the consumer", pairing, got)
		}
	}
	if nodes := topology.planNodes(t); !slices.Equal(nodes, []string{testNodeName, testRemoteNodeName}) {
		t.Fatalf("ProgrammingPlan nodes = %v, want [%s %s]", nodes, testNodeName, testRemoteNodeName)
	}
}

func TestCompileSpreadSendsConsumerRemoteWhenEveryLocalProducerIsUnhealthy(t *testing.T) {
	for _, state := range []networkv1alpha1.BackendHealthState{
		networkv1alpha1.BackendHealthHealthy, networkv1alpha1.BackendHealthUnknown, "",
	} {
		t.Run("remote "+string(state), func(t *testing.T) {
			topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
			reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
			reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthUnhealthy)
			if state != "" {
				reportHealth(topology.endpoint, topology.remote, state)
			}
			topology.requireRemote(t)

			// One local producer recovering brings the consumer back.
			topology.endpoint.Status.Producers[1].State = networkv1alpha1.BackendHealthHealthy
			topology.requireLocal(t, firstDraining)
		})
	}
}

func TestCompileSpreadKeepsUnhealthyLocalProducersWithoutAnEligibleRemote(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.remote, networkv1alpha1.BackendHealthUnhealthy)
	topology.requireLocal(t, bothLocalProducers)

	// A remote producer whose node stopped reporting may be down.
	topology.endpoint.Status.Producers[2].State = networkv1alpha1.BackendHealthHealthy
	expireReport(topology.endpoint)
	topology.requireLocal(t, bothLocalProducers)
}

func TestCompileSpreadKeepsLocalProducersUnlessEveryOneIsUnhealthy(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	reportHealth(topology.endpoint, topology.remote, networkv1alpha1.BackendHealthHealthy)
	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	// An expired Unhealthy report is no evidence the producer is down.
	reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthUnhealthy)
	expireReport(topology.endpoint)
	topology.requireLocal(t, firstDraining)
}

func TestCompileSpreadNodeLocalNeverLeavesTheNode(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.remote, networkv1alpha1.BackendHealthHealthy)
	topology.requireLocal(t, bothLocalProducers)
}

func TestCompileSpreadHoldsNewFlowsFromUncheckedProducers(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	consumer := spreadConsumer()
	healthy := readyAttachment(spreadProducerNamespace, "a-producer", "healthy-uid", testNodeName, "producer-a",
		testLabels(testProducerLabel, "yes"))
	unknown := readyAttachment(spreadProducerNamespace, "b-producer", "unknown-uid", testNodeName, "producer-b",
		testLabels(testProducerLabel, "yes"))
	unreported := readyAttachment(spreadProducerNamespace, "c-producer", "unreported-uid", testNodeName,
		"producer-c", testLabels(testProducerLabel, "yes"))
	unhealthy := readyAttachment(spreadProducerNamespace, "d-producer", "unhealthy-uid", testNodeName,
		"producer-d", testLabels(testProducerLabel, "yes"))
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, healthy, unknown, unreported, unhealthy}
	compile := func() string {
		t.Helper()
		got, err := Compile(policy, endpoint, attachments, testNodeName, nil)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("intents = %+v, want one", got)
		}
		return producerSummary(got[0])
	}

	// Before any result, as after a router restart, every producer stays
	// eligible.
	reportHealth(endpoint, unknown, networkv1alpha1.BackendHealthUnknown)
	if got, want := compile(), "producer-a,producer-b,producer-c,producer-d"; got != want {
		t.Fatalf("producers with no result = %s, want %s", got, want)
	}
	// Without a Healthy producer, unchecked ones stay eligible while an
	// Unhealthy one drains.
	reportHealth(endpoint, unhealthy, networkv1alpha1.BackendHealthUnhealthy)
	if got, want := compile(), "producer-a,producer-b,producer-c,producer-d(draining)"; got != want {
		t.Fatalf("producers with one Unhealthy = %s, want %s", got, want)
	}
	// Once one passes its check, the unchecked ones take no new flows.
	reportHealth(endpoint, healthy, networkv1alpha1.BackendHealthHealthy)
	if got, want := compile(),
		"producer-a,producer-b(draining),producer-c(draining),producer-d(draining)"; got != want {
		t.Fatalf("producers with one Healthy = %s, want %s", got, want)
	}
	// An expired report, as from a node that stopped renewing, is not a
	// pending check.
	reportHealth(endpoint, unreported, networkv1alpha1.BackendHealthHealthy)
	expireReport(endpoint)
	if got, want := compile(),
		"producer-a,producer-b(draining),producer-c,producer-d(draining)"; got != want {
		t.Fatalf("producers with an expired report = %s, want %s", got, want)
	}
}
