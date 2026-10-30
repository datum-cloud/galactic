// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	spreadProducerNamespace = "service"
	spreadConsumerName      = "consumer"
	bothLocalProducers      = "producer-a,producer-z"
	firstRemoteProducer     = "a-remote"
	firstDraining           = "producer-a(draining),producer-z"
)

func spreadEndpoint(mode networkv1alpha1.ServiceEndpointDeliveryMode) (
	*networkv1alpha1.ServiceRoutePolicy, *networkv1alpha1.ServiceEndpoint,
) {
	policy, endpoint := testPolicyAndEndpoint(mode)
	endpoint.Spec.Distribution = networkv1alpha1.ServiceEndpointDistributionSpread
	endpoint.Spec.HealthCheck = &networkv1alpha1.ServiceEndpointHealthCheck{Port: 8053}
	return policy, endpoint
}

func spreadConsumer() *cloudv1alpha1.VPCAttachment {
	return readyAttachment(eligibilityNamespace, spreadConsumerName, "consumer-uid", testNodeName, "consumer0",
		testLabels(testAccessLabel, "yes"))
}

func reportHealth(endpoint *networkv1alpha1.ServiceEndpoint, producer *cloudv1alpha1.VPCAttachment,
	state networkv1alpha1.BackendHealthState,
) {
	endpoint.Status.Producers = append(endpoint.Status.Producers, networkv1alpha1.ServiceEndpointProducerStatus{
		Namespace: producer.Namespace, Name: producer.Name, AttachmentUID: producer.UID,
		Node: producer.Status.Node, Port: 8053, State: state, LastTransitionTime: metav1.Now(),
		RenewTime: ptr.To(metav1.Now()),
	})
}

// expireReport makes the last entry of endpoint's status.producers one its
// node stopped renewing before the report lifetime.
func expireReport(endpoint *networkv1alpha1.ServiceEndpoint) {
	entry := &endpoint.Status.Producers[len(endpoint.Status.Producers)-1]
	entry.RenewTime = ptr.To(metav1.NewTime(
		time.Now().Add(-networkv1alpha1.ServiceEndpointProducerReportLifetime - time.Second)))
}

func producerSummary(intent RouteIntent) string {
	parts := make([]string, 0, len(intent.Producers))
	for _, p := range intent.Producers {
		part := p.Device
		if p.Draining {
			part += "(draining)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

func TestCompileSpreadAcceptsEveryLocalProducer(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	consumer := spreadConsumer()
	first := readyAttachment(spreadProducerNamespace, "a-producer", "first-uid", testNodeName, "producer-a",
		testLabels(testProducerLabel, "yes"))
	last := readyAttachment(spreadProducerNamespace, "z-producer", "last-uid", testNodeName, "producer-z",
		testLabels(testProducerLabel, "yes"))
	attachments := []*cloudv1alpha1.VPCAttachment{last, consumer, first}

	got, err := Compile(policy, endpoint, attachments, testNodeName, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got) != 1 || got[0].Kind != RouteIntentLocalSet || got[0].ConsumerDevice != "consumer0" ||
		producerSummary(got[0]) != bothLocalProducers {
		t.Fatalf("intents = %+v, want one LocalSet intent through producer-a and producer-z", got)
	}
	if got[0].ServiceDevice != "" || got[0].ProducerAttachment != (types.NamespacedName{}) {
		t.Fatalf("LocalSet intent names a single producer: %+v", got[0])
	}
	if _, err := ProgrammingPlan(policy, endpoint, attachments, ""); err != nil {
		t.Fatalf("ProgrammingPlan: %v", err)
	}

	endpoint.Spec.Distribution, endpoint.Spec.HealthCheck = "", nil
	if _, err := Compile(policy, endpoint, attachments, testNodeName, nil); err == nil {
		t.Fatal("Compile accepted two producers on one node and VPC without Spread")
	}
}

func TestCompileSpreadDrainsUnhealthyProducers(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	consumer := spreadConsumer()
	first := readyAttachment(spreadProducerNamespace, "a-producer", "first-uid", testNodeName, "producer-a",
		testLabels(testProducerLabel, "yes"))
	last := readyAttachment(spreadProducerNamespace, "z-producer", "last-uid", testNodeName, "producer-z",
		testLabels(testProducerLabel, "yes"))
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, first, last}
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

	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(endpoint, last, networkv1alpha1.BackendHealthHealthy)
	if got := compile(); got != firstDraining {
		t.Fatalf("producers = %s, want producer-a draining", got)
	}

	endpoint.Status.Producers[1].State = networkv1alpha1.BackendHealthUnhealthy
	if got := compile(); got != bothLocalProducers {
		t.Fatalf("producers with every one Unhealthy = %s, want all eligible", got)
	}

	// A decision written for an earlier attachment of the same name, or by
	// another node, does not describe this producer.
	endpoint.Status.Producers[0].AttachmentUID = "earlier-uid"
	endpoint.Status.Producers[1].Node = testRemoteNodeName
	if got := compile(); got != bothLocalProducers {
		t.Fatalf("producers with stale decisions = %s, want all eligible", got)
	}

	endpoint.Status.Producers = nil
	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnknown)
	if got := compile(); got != bothLocalProducers {
		t.Fatalf("producers with an Unknown decision = %s, want all eligible", got)
	}
}

func TestCompileSpreadFallsBackToHealthyRemoteProducer(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := spreadConsumer()
	first := readyAttachment(spreadProducerNamespace, firstRemoteProducer, "first-uid", testRemoteNodeName, "remote-a",
		testLabels(testProducerLabel, "yes"))
	last := readyAttachment(spreadProducerNamespace, "z-remote", "last-uid", testRemoteNodeName, "remote-z",
		testLabels(testProducerLabel, "yes"))
	resolver := func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		return net.ParseIP("fd00::" + string(attachment.UID[0])), nil
	}
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, first, last}
	remote := func() types.NamespacedName {
		t.Helper()
		got, err := Compile(policy, endpoint, attachments, testNodeName, resolver)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(got) != 1 || got[0].Kind != RouteIntentRemoteConsumer {
			t.Fatalf("intents = %+v, want one RemoteConsumer intent", got)
		}
		return got[0].ProducerAttachment
	}

	if got := remote(); got.Name != firstRemoteProducer {
		t.Fatalf("remote producer = %s, want a-remote", got)
	}
	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnhealthy)
	if got := remote(); got.Name != "z-remote" {
		t.Fatalf("remote producer with a-remote Unhealthy = %s, want z-remote", got)
	}
	reportHealth(endpoint, last, networkv1alpha1.BackendHealthUnhealthy)
	if got := remote(); got.Name != firstRemoteProducer {
		t.Fatalf("remote producer with both Unhealthy = %s, want a-remote", got)
	}

	// Two producers on one remote node are told apart by their SIDs.
	got, err := Compile(policy, endpoint, attachments, testRemoteNodeName, resolver)
	if err != nil {
		t.Fatalf("Compile on the producer node: %v", err)
	}
	if len(got) != 1 || got[0].Kind != RouteIntentRemoteProducer || got[0].ServiceDevice != "remote-a" {
		t.Fatalf("producer node intents = %+v, want one RemoteProducer half through remote-a", got)
	}
}

func TestCompileSpreadIgnoresExpiredLocalReports(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	consumer := spreadConsumer()
	first := readyAttachment(spreadProducerNamespace, "a-producer", "first-uid", testNodeName, "producer-a",
		testLabels(testProducerLabel, "yes"))
	last := readyAttachment(spreadProducerNamespace, "z-producer", "last-uid", testNodeName, "producer-z",
		testLabels(testProducerLabel, "yes"))
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, first, last}
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

	// An Unhealthy decision written before its node's router stopped no
	// longer drains the producer.
	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnhealthy)
	expireReport(endpoint)
	reportHealth(endpoint, last, networkv1alpha1.BackendHealthHealthy)
	if got := compile(); got != bothLocalProducers {
		t.Fatalf("producers with an expired Unhealthy decision = %s, want all eligible", got)
	}
	endpoint.Status.Producers[0].RenewTime = nil
	if got := compile(); got != bothLocalProducers {
		t.Fatalf("producers with a never-renewed Unhealthy decision = %s, want all eligible", got)
	}
}

func TestCompileSpreadAvoidsRemoteProducersWithExpiredReports(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := spreadConsumer()
	lost := readyAttachment(spreadProducerNamespace, firstRemoteProducer, "lost-uid", testRemoteNodeName, "remote-a",
		testLabels(testProducerLabel, "yes"))
	live := readyAttachment(spreadProducerNamespace, "z-remote", "live-uid", "node-c", "remote-z",
		testLabels(testProducerLabel, "yes"))
	resolver := func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		return net.ParseIP("fd00::" + string(attachment.UID[0])), nil
	}
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, lost, live}
	remote := func() string {
		t.Helper()
		got, err := Compile(policy, endpoint, attachments, testNodeName, resolver)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(got) != 1 || got[0].Kind != RouteIntentRemoteConsumer {
			t.Fatalf("intents = %+v, want one RemoteConsumer intent", got)
		}
		plan, err := ProgrammingPlan(policy, endpoint, attachments, "")
		if err != nil {
			t.Fatalf("ProgrammingPlan: %v", err)
		}
		if want := []string{got[0].ProducerAttachment.Name}; !planNodesInclude(plan, attachments, want) {
			t.Fatalf("ProgrammingPlan nodes = %v, want the node of %v", plan.Nodes, want)
		}
		return got[0].ProducerAttachment.Name
	}

	// a-remote's node went down while its attachment still reads ready.
	reportHealth(endpoint, lost, networkv1alpha1.BackendHealthHealthy)
	expireReport(endpoint)
	reportHealth(endpoint, live, networkv1alpha1.BackendHealthHealthy)
	if got := remote(); got != "z-remote" {
		t.Fatalf("remote producer with a-remote's report expired = %s, want z-remote", got)
	}
	// An expired report is preferred over a current Unhealthy one.
	endpoint.Status.Producers[1].State = networkv1alpha1.BackendHealthUnhealthy
	if got := remote(); got != firstRemoteProducer {
		t.Fatalf("remote producer with z-remote Unhealthy = %s, want a-remote", got)
	}
	endpoint.Status.Producers[1].State = networkv1alpha1.BackendHealthHealthy
	expireReport(endpoint)
	if got := remote(); got != firstRemoteProducer {
		t.Fatalf("remote producer with every report expired = %s, want a-remote", got)
	}
}

func TestNextProducerReportExpiry(t *testing.T) {
	_, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	now := time.Now()
	if _, ok := NextProducerReportExpiry(endpoint, now); ok {
		t.Fatal("NextProducerReportExpiry found an expiry with no reports")
	}
	lifetime := networkv1alpha1.ServiceEndpointProducerReportLifetime
	for _, ago := range []time.Duration{lifetime + time.Second, 10 * time.Second, 40 * time.Second} {
		renewed := metav1.NewTime(now.Add(-ago))
		endpoint.Status.Producers = append(endpoint.Status.Producers,
			networkv1alpha1.ServiceEndpointProducerStatus{RenewTime: &renewed})
	}
	endpoint.Status.Producers = append(endpoint.Status.Producers, networkv1alpha1.ServiceEndpointProducerStatus{})
	if left, ok := NextProducerReportExpiry(endpoint, now); !ok || left != lifetime-40*time.Second {
		t.Fatalf("NextProducerReportExpiry = %v, %v, want %v", left, ok, lifetime-40*time.Second)
	}
}

func planNodesInclude(plan ProgrammingRequirements, attachments []*cloudv1alpha1.VPCAttachment,
	names []string,
) bool {
	for _, attachment := range attachments {
		for _, name := range names {
			if attachment.Name == name && !slices.Contains(plan.Nodes, attachment.Status.Node) {
				return false
			}
		}
	}
	return true
}

func TestCompileSpreadRefusesMoreProducersThanASetHolds(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	attachments := make([]*cloudv1alpha1.VPCAttachment, 0, networkv1alpha1.ServiceEndpointMaxProducersPerNode+2)
	attachments = append(attachments, spreadConsumer())
	for i := range networkv1alpha1.ServiceEndpointMaxProducersPerNode {
		attachments = append(attachments, readyAttachment(spreadProducerNamespace, fmt.Sprintf("producer-%02d", i),
			fmt.Sprintf("uid-%02d", i), testNodeName, fmt.Sprintf("p%02d", i), testLabels(testProducerLabel, "yes")))
	}
	got, err := Compile(policy, endpoint, attachments, testNodeName, nil)
	if err != nil || len(got) != 1 || len(got[0].Producers) != networkv1alpha1.ServiceEndpointMaxProducersPerNode {
		t.Fatalf("Compile with a full set: intents=%+v err=%v", got, err)
	}
	attachments = append(attachments, readyAttachment(spreadProducerNamespace, "producer-extra", "uid-extra", testNodeName,
		"pextra", testLabels(testProducerLabel, "yes")))
	if _, err := Compile(policy, endpoint, attachments, testNodeName, nil); err == nil ||
		!strings.Contains(err.Error(), `node "node-a"`) {
		t.Fatalf("Compile with %d producers on one node: err=%v, want a refusal naming the node",
			len(attachments)-1, err)
	}
}

func TestWithProducerReportsPrefersReportsOverStatus(t *testing.T) {
	policy, endpoint := spreadEndpoint(networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal)
	endpoint.UID = "endpoint-uid"
	consumer := spreadConsumer()
	first := readyAttachment(spreadProducerNamespace, "a-producer", "first-uid", testNodeName, "producer-a",
		testLabels(testProducerLabel, "yes"))
	last := readyAttachment(spreadProducerNamespace, "z-producer", "last-uid", testNodeName, "producer-z",
		testLabels(testProducerLabel, "yes"))
	attachments := []*cloudv1alpha1.VPCAttachment{consumer, first, last}
	report := func(uid types.UID, producer *cloudv1alpha1.VPCAttachment,
		state networkv1alpha1.BackendHealthState,
	) networkv1alpha1.ServiceEndpointProducerReport {
		entries := &networkv1alpha1.ServiceEndpoint{}
		reportHealth(entries, producer, state)
		return networkv1alpha1.ServiceEndpointProducerReport{
			ObjectMeta: metav1.ObjectMeta{Namespace: endpoint.Namespace, Name: "report-" + string(uid)},
			Spec: networkv1alpha1.ServiceEndpointProducerReportSpec{
				EndpointName: endpoint.Name, EndpointUID: uid, Node: producer.Status.Node,
				Producers: entries.Status.Producers,
			},
		}
	}
	compile := func(reports ...networkv1alpha1.ServiceEndpointProducerReport) string {
		t.Helper()
		view := WithProducerReports(endpoint, reports)
		got, err := Compile(policy, view, attachments, testNodeName, nil)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("intents = %+v, want one", got)
		}
		return producerSummary(got[0])
	}

	// A report drains its Unhealthy producer.
	if got := compile(report(endpoint.UID, first, networkv1alpha1.BackendHealthUnhealthy)); got !=
		firstDraining {
		t.Fatalf("producers = %s, want producer-a draining", got)
	}
	// A report for an earlier endpoint of the same name is ignored.
	if got := compile(report("earlier-uid", first, networkv1alpha1.BackendHealthUnhealthy)); got !=
		bothLocalProducers {
		t.Fatalf("producers with an earlier endpoint's report = %s, want all eligible", got)
	}
	// While routers are upgraded, a status entry still drains a producer no
	// report describes, and a report overrides the status entry of the same
	// producer and node.
	reportHealth(endpoint, last, networkv1alpha1.BackendHealthUnhealthy)
	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnhealthy)
	if got := compile(report(endpoint.UID, first, networkv1alpha1.BackendHealthHealthy)); got !=
		"producer-a,producer-z(draining)" {
		t.Fatalf("producers = %s, want producer-z drained by its status entry, producer-a healthy by report", got)
	}
	if len(endpoint.Status.Producers) != 2 {
		t.Fatalf("WithProducerReports changed the endpoint: %+v", endpoint.Status.Producers)
	}

	// A node rolled back to a router that writes status.producers leaves an
	// expired report entry behind; its fresh status entry still drains.
	endpoint.Status.Producers = nil
	reportHealth(endpoint, first, networkv1alpha1.BackendHealthUnhealthy)
	stale := report(endpoint.UID, first, networkv1alpha1.BackendHealthHealthy)
	stale.Spec.Producers[0].RenewTime = ptr.To(metav1.NewTime(
		time.Now().Add(-networkv1alpha1.ServiceEndpointProducerReportLifetime - time.Second)))
	if got := compile(stale); got != firstDraining {
		t.Fatalf("producers after rollback = %s, want producer-a drained by its newer status entry", got)
	}
}
