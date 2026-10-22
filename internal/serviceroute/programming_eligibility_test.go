package serviceroute

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cloud "go.datum.net/galactic/api/cloud/v1alpha1"
	network "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	eligibilityNamespace  = "tenant"
	eligibilityRoleLabel  = "role"
	eligibilityPolicyName = "policy"
)

func TestProgrammingPlanKeepsEligibleConsumersIndependent(t *testing.T) {
	attachment := func(name, node, role string) *cloud.VPCAttachment {
		return &cloud.VPCAttachment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: eligibilityNamespace, Name: name, UID: types.UID(name), Generation: 1,
				Labels: map[string]string{eligibilityRoleLabel: role},
			},
			Status: cloud.VPCAttachmentStatus{
				ObservedGeneration: 1, Node: node, VPC: "vpc", VPCAttachment: name, HostInterface: name,
				Conditions: []metav1.Condition{
					{Type: cloud.ConditionTypeReady, Status: metav1.ConditionTrue},
					{Type: cloud.ConditionTypeProgrammed, Status: metav1.ConditionTrue},
				},
			},
		}
	}
	policy := &network.ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: eligibilityNamespace, Name: eligibilityPolicyName, UID: eligibilityPolicyName,
		},
		Spec: network.ServiceRoutePolicySpec{
			AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{eligibilityRoleLabel: "consumer"}},
		},
	}
	endpoint := &network.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: eligibilityNamespace, Name: "endpoint", UID: "endpoint"},
		Spec: network.ServiceEndpointSpec{DeliveryMode: network.ServiceEndpointDeliveryModePreferNodeLocal,
			AttachmentSelector: &metav1.LabelSelector{MatchLabels: map[string]string{eligibilityRoleLabel: "producer"}}}}
	healthy := attachment("healthy", "node-a", "consumer")
	sibling := attachment("sibling", "node-c", "consumer")
	producer := attachment("producer", "node-b", "producer")
	topology := []*cloud.VPCAttachment{healthy, sibling, producer}
	before, err := ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatal(err)
	}
	sibling.Status.Node = ""
	sibling.Status.HostInterface = ""
	sibling.Status.Conditions[1].Status = metav1.ConditionFalse
	after, err := ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatalf("unattached sibling blocked healthy consumer: %v", err)
	}
	if !reflect.DeepEqual(after.Nodes, []string{"node-a", "node-b"}) {
		t.Fatalf("nodes=%v", after.Nodes)
	}
	if before.InputDigest == after.InputDigest {
		t.Fatal("withdrawal retained stale topology digest")
	}
	sibling.Status.Node = "node-c"
	sibling.Status.HostInterface = "sibling"
	sibling.Status.Conditions[1].Status = metav1.ConditionTrue
	restored, err := ProgrammingPlan(policy, endpoint, topology, "")
	if err != nil {
		t.Fatal(err)
	}
	if restored.InputDigest != before.InputDigest {
		t.Fatal("restored topology has inconsistent digest")
	}
	if _, err := ProgrammingPlan(policy, endpoint, []*cloud.VPCAttachment{producer}, ""); err == nil {
		t.Fatal("producer-only topology reported ready")
	}
	healthy.Status.HostInterface = ""
	sibling.Status.HostInterface = ""
	if _, err := ProgrammingPlan(policy, endpoint, topology, ""); err == nil {
		t.Fatal("topology without eligible consumers reported ready")
	}
}
