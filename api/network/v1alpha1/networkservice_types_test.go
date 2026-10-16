package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestService() *NetworkService {
	return &NetworkService{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "NetworkService",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-service", Namespace: "galactic-system"},
		Spec: NetworkServiceSpec{
			VPCRef:       "vpc-a",
			VIPAddresses: []string{"2001:db8:1::10"},
			Protocol:     NetworkServiceProtocolTCP,
			Port:         443,
			BackendSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			BackendPort: 8443,
		},
	}
}

// TestNetworkServiceDeepCopy verifies that DeepCopy produces an independent
// copy: mutations to slices in the copy must not affect the original.
func TestNetworkServiceDeepCopy(t *testing.T) {
	orig := newTestService()
	dup := orig.DeepCopy()

	dup.Spec.VIPAddresses[0] = "2001:db8:1::20"
	dup.Spec.BackendSelector.MatchLabels["app"] = "api"

	if orig.Spec.VIPAddresses[0] != "2001:db8:1::10" {
		t.Errorf("VIPAddresses[0] mutated: got %q", orig.Spec.VIPAddresses[0])
	}
	if orig.Spec.BackendSelector.MatchLabels["app"] != "web" {
		t.Errorf("BackendSelector.MatchLabels mutated: got %v", orig.Spec.BackendSelector.MatchLabels)
	}
}

// TestNetworkServiceDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestNetworkServiceDeepCopyNil(t *testing.T) {
	var r *NetworkService
	if r.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestNetworkServiceJSONRoundTrip verifies that the struct serialises and
// deserialises through JSON without data loss.
func TestNetworkServiceJSONRoundTrip(t *testing.T) {
	orig := newTestService()
	orig.Spec.BackendSelector.MatchExpressions = []metav1.LabelSelectorRequirement{
		{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend"}},
	}
	orig.Status.Conditions = []metav1.Condition{
		{Type: ConditionTypeAccepted, Status: metav1.ConditionTrue, Reason: AcceptedReasonOwnershipVerified},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got NetworkService
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.VPCRef != orig.Spec.VPCRef {
		t.Errorf("VPCRef: got %q, want %q", got.Spec.VPCRef, orig.Spec.VPCRef)
	}
	if got.Spec.BackendSelector.MatchLabels["app"] != "web" || len(got.Spec.BackendSelector.MatchExpressions) != 1 {
		t.Errorf("BackendSelector: got %+v", got.Spec.BackendSelector)
	}
	if got.Spec.BackendPort != orig.Spec.BackendPort {
		t.Errorf("BackendPort: got %d, want %d", got.Spec.BackendPort, orig.Spec.BackendPort)
	}
	if len(got.Status.Conditions) != 1 || got.Status.Conditions[0].Reason != AcceptedReasonOwnershipVerified {
		t.Errorf("Conditions: got %v", got.Status.Conditions)
	}
}

// TestNetworkServiceListDeepCopy verifies that NetworkServiceList.DeepCopy
// produces independent copies of each item.
func TestNetworkServiceListDeepCopy(t *testing.T) {
	list := &NetworkServiceList{
		Items: []NetworkService{*newTestService()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.VPCRef = "vpc-b"

	if list.Items[0].Spec.VPCRef != "vpc-a" {
		t.Errorf("original list item mutated via copy")
	}
}

// TestNetworkServiceStatusHasNoPrimaryNode is a regression test: the earlier
// active-passive Full-NAT design assigned a single primaryNode per service.
// This design's anycast/DSR model has every NetworkGateway serve every service
// identically, so no such field should exist any more.
func TestNetworkServiceStatusHasNoPrimaryNode(t *testing.T) {
	orig := newTestService()
	orig.Status.Conditions = []metav1.Condition{{Type: ConditionTypeAccepted}}

	data, err := json.Marshal(orig.Status)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["primaryNode"]; ok {
		t.Errorf("unexpected primaryNode field present in status: %v", m)
	}
}

// TestNetworkServiceBackendFieldNames verifies the JSON keys for the backend
// selection fields match the CRD schema, and that the static backend list
// they replaced is gone.
func TestNetworkServiceBackendFieldNames(t *testing.T) {
	data, err := json.Marshal(newTestService().Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := m["backendSelector"]; !ok {
		t.Errorf("expected JSON key \"backendSelector\", got %v", m)
	}
	if v, ok := m["backendPort"]; !ok || v != float64(8443) {
		t.Errorf("expected JSON key \"backendPort\"=8443, got %v", m)
	}
	if _, ok := m["backends"]; ok {
		t.Errorf("unexpected \"backends\" key: %v", m)
	}
}

// TestNetworkServiceProtocolValues is a regression test pinning the accepted
// NetworkServiceProtocol enum values.
func TestNetworkServiceProtocolValues(t *testing.T) {
	if NetworkServiceProtocolTCP != "tcp" {
		t.Errorf("NetworkServiceProtocolTCP: got %q, want %q", NetworkServiceProtocolTCP, "tcp")
	}
	if NetworkServiceProtocolUDP != "udp" {
		t.Errorf("NetworkServiceProtocolUDP: got %q, want %q", NetworkServiceProtocolUDP, "udp")
	}
}
