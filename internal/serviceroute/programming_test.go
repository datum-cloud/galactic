// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"testing"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func TestProgrammingPlanFencesTopologyAndIgnoresUnrelatedVPC(t *testing.T) {
	policy, endpoint := testPolicyAndEndpoint(networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal)
	consumer := readyAttachment("tenant", "client", "client", testNodeName, "client0", testLabels(testAccessLabel, "yes"))
	producer := readyAttachment("service", "server", "server", testRemoteNodeName, "server0",
		testLabels(testProducerLabel, "yes"))
	topology := []*cloudv1alpha1.VPCAttachment{consumer, producer}
	first, err := ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 2 {
		t.Fatalf("nodes=%v", first.Nodes)
	}
	unrelated := readyAttachment("other", "other", "other", testNodeName, "other0", nil)
	second, err := ProgrammingPlan(policy, endpoint, append(topology, unrelated), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.InputDigest != second.InputDigest {
		t.Fatal("unrelated VPC invalidated programming")
	}
	producer.UID = "replacement"
	second, err = ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.InputDigest == second.InputDigest {
		t.Fatal("recreated producer retained acknowledgment digest")
	}
	endpoint.Generation++
	third, err := ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.InputDigest == third.InputDigest {
		t.Fatal("endpoint generation retained acknowledgment digest")
	}
	producer.Status.Conditions[0].Status = "False"
	if _, err := ProgrammingPlan(policy, endpoint, topology, ""); err == nil {
		t.Fatal("unhealthy producer considered programmed")
	}
}
