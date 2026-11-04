// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceplan

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Health states for reportState beyond the API's own.
const (
	// unreported writes no entry for the producer.
	unreported networkv1alpha1.BackendHealthState = "unreported"
	// staleEntry writes a Healthy entry for an earlier attachment of the
	// same name, which says nothing of this one.
	staleEntry networkv1alpha1.BackendHealthState = "stale"
)

// reportState reports producer in state, or as unreported or staleEntry say.
func reportState(endpoint *networkv1alpha1.ServiceEndpoint, producer *cloudv1alpha1.VPCAttachment,
	state networkv1alpha1.BackendHealthState,
) {
	switch state {
	case unreported:
	case staleEntry:
		reportHealth(endpoint, producer, networkv1alpha1.BackendHealthHealthy)
		endpoint.Status.Producers[len(endpoint.Status.Producers)-1].AttachmentUID = "earlier-uid"
	default:
		reportHealth(endpoint, producer, state)
	}
}

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

func TestCompileSpreadSendsConsumerRemoteWhenNoLocalProducerIsUsable(t *testing.T) {
	for _, remoteState := range []networkv1alpha1.BackendHealthState{
		networkv1alpha1.BackendHealthHealthy, networkv1alpha1.BackendHealthUnknown, unreported,
	} {
		// first is Unhealthy; last is Unhealthy, or has no result yet, as a
		// replacement starting while first fails.
		for _, lastState := range []networkv1alpha1.BackendHealthState{
			networkv1alpha1.BackendHealthUnhealthy, networkv1alpha1.BackendHealthUnknown, unreported, staleEntry,
		} {
			t.Run("remote "+string(remoteState)+" last "+string(lastState), func(t *testing.T) {
				topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
				reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
				reportState(topology.endpoint, topology.last, lastState)
				reportState(topology.endpoint, topology.remote, remoteState)
				topology.requireRemote(t)

				// The consumer returns once a local producer passes its check.
				topology.endpoint.Status.Producers = topology.endpoint.Status.Producers[:1]
				reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthHealthy)
				reportState(topology.endpoint, topology.remote, remoteState)
				topology.requireLocal(t, firstDraining)
			})
		}
	}
}

func TestCompileSpreadSendsLoneUnhealthyLocalProducersConsumerRemote(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	topology.attachments = []*cloudv1alpha1.VPCAttachment{topology.consumer, topology.first, topology.remote}
	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	topology.requireRemote(t)
	topology.endpoint.Status.Producers[0].State = networkv1alpha1.BackendHealthHealthy
	topology.requireLocal(t, "producer-a")
}

func TestCompileSpreadFallbackAcceptedOnEveryPairingsNode(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthUnhealthy)
	const extraRemotes = 8
	remotes := make([]*cloudv1alpha1.VPCAttachment, 0, 1+extraRemotes)
	remotes = append(remotes, topology.remote)
	for i := range extraRemotes {
		remotes = append(remotes, readyAttachment(spreadProducerNamespace, fmt.Sprintf("remote-%02d", i),
			fmt.Sprintf("remote-%02d-uid", i), fmt.Sprintf("node-r%02d", i), fmt.Sprintf("remote%02d", i),
			testLabels(testProducerLabel, "yes")))
	}
	topology.attachments = append([]*cloudv1alpha1.VPCAttachment{topology.consumer, topology.first, topology.last},
		remotes...)
	producers := append([]*cloudv1alpha1.VPCAttachment{topology.first, topology.last}, remotes...)
	health := producersHealth(topology.endpoint, producers, time.Now())
	picks := map[string]*cloudv1alpha1.VPCAttachment{}
	for _, pairing := range spreadPairings {
		picks[string(pairing)] = spreadRemoteProducer(topology.consumer, producers, health, pairing)
	}
	if picks[string(SpreadPairingFirst)] == picks[string(SpreadPairingRendezvous)] {
		t.Fatal("test topology needs pairings that pick different remote producers")
	}
	nodes := make([]string, 0, 1+len(spreadPairings))
	nodes = append(nodes, testNodeName)
	for _, pairing := range spreadPairings {
		picked := picks[string(pairing)]
		nodes = append(nodes, picked.Status.Node)
		got := topology.compile(t, testNodeName, pairing)
		if len(got) != 1 || got[0].Kind != RouteIntentRemoteConsumer || got[0].ProducerAttachment.Name != picked.Name {
			t.Fatalf("%s: consumer node intents = %+v, want one RemoteConsumer intent to %s", pairing, got, picked.Name)
		}
		// Whichever pairing it uses itself, each picked producer's node
		// accepts the consumer.
		for _, other := range spreadPairings {
			got = topology.compile(t, picked.Status.Node, other)
			if len(got) != 1 || got[0].Kind != RouteIntentRemoteProducer || got[0].ProducerAttachment.Name != picked.Name {
				t.Fatalf("%s node using %s: intents = %+v, want one RemoteProducer half", picked.Status.Node, other, got)
			}
		}
	}
	slices.Sort(nodes)
	if got := topology.planNodes(t); !slices.Equal(got, nodes) {
		t.Fatalf("ProgrammingPlan nodes = %v, want %v", got, nodes)
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

func TestCompileSpreadKeepsUsableLocalProducers(t *testing.T) {
	topology := newUnhealthyLocalTopology(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	reportHealth(topology.endpoint, topology.remote, networkv1alpha1.BackendHealthHealthy)
	// Before any result, as after a router restart, nothing says the local
	// producers fail.
	topology.requireLocal(t, bothLocalProducers)

	reportHealth(topology.endpoint, topology.first, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(topology.endpoint, topology.last, networkv1alpha1.BackendHealthHealthy)
	topology.requireLocal(t, firstDraining)

	// An expired Unhealthy report is no evidence the producer is down.
	topology.endpoint.Status.Producers[2].State = networkv1alpha1.BackendHealthUnhealthy
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
