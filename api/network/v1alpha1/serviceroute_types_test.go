package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceRoutePolicyDeepCopy(t *testing.T) {
	original := &ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "platform"},
		Spec: ServiceRoutePolicySpec{
			ServiceRef:         ServiceEndpointReference{Name: "ipv6-egress-dns"},
			AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{"egress": "enabled"}},
			ProtocolPorts:      []ServiceRouteProtocolPort{{Protocol: NetworkServiceProtocolUDP, Port: 53}},
			Region:             "us-central-1",
		},
		Status: ServiceRoutePolicyStatus{Conditions: []metav1.Condition{{Type: "Accepted"}}},
	}

	copy := original.DeepCopy()
	copy.Spec.AttachmentSelector.MatchLabels["egress"] = "disabled"
	copy.Spec.ProtocolPorts[0].Port = 853
	copy.Status.Conditions[0].Type = "Rejected"

	if original.Spec.AttachmentSelector.MatchLabels["egress"] != "enabled" {
		t.Fatal("DeepCopy shared selector labels")
	}
	if original.Status.Conditions[0].Type != "Accepted" {
		t.Fatal("DeepCopy shared status conditions")
	}
	if original.Spec.ProtocolPorts[0].Port != 53 {
		t.Fatal("DeepCopy shared protocol ports")
	}
}

func TestServiceRoutePolicyListDeepCopy(t *testing.T) {
	original := &ServiceRoutePolicyList{Items: []ServiceRoutePolicy{{
		Spec: ServiceRoutePolicySpec{
			AttachmentSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "region", Operator: metav1.LabelSelectorOpIn, Values: []string{"us-central-1"},
			}}},
		}}}}

	copy := original.DeepCopy()
	copy.Items[0].Spec.AttachmentSelector.MatchExpressions[0].Values[0] = "eu-west-1"
	if got := original.Items[0].Spec.AttachmentSelector.MatchExpressions[0].Values[0]; got != "us-central-1" {
		t.Fatalf("DeepCopy shared selector values: got %q", got)
	}
}

func TestServiceEndpointDeepCopy(t *testing.T) {
	original := &ServiceEndpoint{Spec: ServiceEndpointSpec{
		DeliveryMode: ServiceEndpointDeliveryModePreferNodeLocal,
		AttachmentSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
			"service.datumapis.com/name": "dns64",
		}},
	}}

	copy := original.DeepCopy()
	copy.Spec.AttachmentSelector.MatchLabels["service.datumapis.com/name"] = "other"
	if got := original.Spec.AttachmentSelector.MatchLabels["service.datumapis.com/name"]; got != "dns64" {
		t.Fatalf("DeepCopy shared endpoint selector labels: got %q", got)
	}
}
