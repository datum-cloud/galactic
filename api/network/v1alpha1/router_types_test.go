package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestRouter() *BGPRouter {
	return &BGPRouter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPRouter",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-router"},
		Spec: BGPRouterSpec{
			TargetRef: TargetRef{Kind: "Node", Name: "node-1"},
			LocalASN:  65000,
			RouterID:  "10.0.0.1",
		},
	}
}

// TestBGPRouterLargeLocalASN verifies that 4-byte ASNs (values above signed int32 max)
// survive JSON round-trip correctly.
func TestBGPRouterLargeLocalASN(t *testing.T) {
	// Max 4-byte ASN — the boundary of the uint32 range.
	const maxASN = int64(4294967295)

	router := &BGPRouter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPRouter",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "large-asn-router"},
		Spec: BGPRouterSpec{
			TargetRef: TargetRef{Kind: "Node", Name: "node-1"},
			LocalASN:  maxASN,
			RouterID:  "10.0.0.1",
			AddressFamilies: []AddressFamily{
				{AFI: AFIIPv4, SAFI: SAFIUnicast},
			},
		},
	}

	data, err := json.Marshal(router)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPRouter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.LocalASN != maxASN {
		t.Errorf("LocalASN after round-trip: got %d, want %d", got.Spec.LocalASN, maxASN)
	}
}

// TestBGPRouterLocalASNAboveSignedInt32Max verifies that values > 2^31-1
// (the signed int32 ceiling) are handled correctly.
func TestBGPRouterLocalASNAboveSignedInt32Max(t *testing.T) {
	// 2^31 = 2147483648 — the first value beyond signed int32 range.
	const aboveSignedMax int64 = 2147483648

	router := &BGPRouter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPRouter",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "above-int32-router"},
		Spec: BGPRouterSpec{
			TargetRef: TargetRef{Kind: "Node", Name: "node-1"},
			LocalASN:  aboveSignedMax,
			RouterID:  "10.0.0.1",
			AddressFamilies: []AddressFamily{
				{AFI: AFIIPv4, SAFI: SAFIUnicast},
			},
		},
	}

	data, err := json.Marshal(router)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPRouter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.LocalASN != aboveSignedMax {
		t.Errorf("LocalASN after round-trip: got %d, want %d", got.Spec.LocalASN, aboveSignedMax)
	}
}

// TestBGPRouterDeepCopyLocalASN verifies that mutating LocalASN on the copy
// does not affect the original.
func TestBGPRouterDeepCopyLocalASN(t *testing.T) {
	orig := newTestRouter()
	orig.Spec.LocalASN = 654321
	dup := orig.DeepCopy()

	dup.Spec.LocalASN = 999999
	if orig.Spec.LocalASN != 654321 {
		t.Errorf("LocalASN mutated: got %d, want 654321", orig.Spec.LocalASN)
	}
}

// TestBGPRouterJSONRoundTripSRv6Locator verifies that SRv6Locator survives
// JSON marshal/unmarshal.
func TestBGPRouterJSONRoundTripSRv6Locator(t *testing.T) {
	orig := newTestRouter()
	orig.Spec.SRv6Locator = "2001:db8:ff01::/48"

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPRouter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.SRv6Locator != orig.Spec.SRv6Locator {
		t.Errorf("SRv6Locator: got %q, want %q", got.Spec.SRv6Locator, orig.Spec.SRv6Locator)
	}
}

// TestBGPRouterSRv6LocatorFieldName verifies the JSON key is "srv6Locator".
func TestBGPRouterSRv6LocatorFieldName(t *testing.T) {
	orig := newTestRouter()
	orig.Spec.SRv6Locator = "2001:db8:ff01::/48"

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw, ok := m["srv6Locator"]; !ok || raw != "2001:db8:ff01::/48" {
		t.Errorf("unexpected srv6Locator value: %v", raw)
	}
}

// TestBGPRouterSRv6LocatorOmitEmpty verifies that a router without a
// SRv6Locator omits the "srv6Locator" key from JSON output.
func TestBGPRouterSRv6LocatorOmitEmpty(t *testing.T) {
	orig := newTestRouter()

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["srv6Locator"]; ok {
		t.Error("expected \"srv6Locator\" key to be absent when empty")
	}
}

// TestBGPRouterJSONRoundTripNodeID verifies that NodeID survives JSON
// marshal/unmarshal.
func TestBGPRouterJSONRoundTripNodeID(t *testing.T) {
	orig := newTestRouter()
	orig.Spec.NodeID = 42

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPRouter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.NodeID != orig.Spec.NodeID {
		t.Errorf("NodeID: got %d, want %d", got.Spec.NodeID, orig.Spec.NodeID)
	}
}

// TestBGPRouterNodeIDFieldName verifies the JSON key is "nodeID".
func TestBGPRouterNodeIDFieldName(t *testing.T) {
	orig := newTestRouter()
	orig.Spec.NodeID = 42

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw, ok := m["nodeID"]; !ok || raw != float64(42) {
		t.Errorf("unexpected nodeID value: %v", raw)
	}
}

// TestBGPRouterNodeIDOmitEmpty verifies that a router without a NodeID omits
// the "nodeID" key from JSON output.
func TestBGPRouterNodeIDOmitEmpty(t *testing.T) {
	orig := newTestRouter()

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["nodeID"]; ok {
		t.Error("expected \"nodeID\" key to be absent when empty")
	}
}

// TestBGPRouterJSONRoundTripListenPort verifies that ListenPort survives
// JSON marshal/unmarshal.
func TestBGPRouterJSONRoundTripListenPort(t *testing.T) {
	orig := newTestRouter()
	port := int32(179)
	orig.Spec.ListenPort = &port

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPRouter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.ListenPort == nil {
		t.Fatal("expected ListenPort to be set")
	} else if *got.Spec.ListenPort != port {
		t.Errorf("ListenPort: got %d, want %d", *got.Spec.ListenPort, port)
	}
}

// TestBGPRouterListenPortFieldName verifies the JSON key is "listenPort".
func TestBGPRouterListenPortFieldName(t *testing.T) {
	orig := newTestRouter()
	port := int32(179)
	orig.Spec.ListenPort = &port

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw, ok := m["listenPort"]; !ok || raw != float64(179) {
		t.Errorf("unexpected listenPort value: %v", raw)
	}
}

// TestBGPRouterListenPortOmitEmpty verifies that a router without a
// ListenPort omits the "listenPort" key from JSON output.
func TestBGPRouterListenPortOmitEmpty(t *testing.T) {
	orig := newTestRouter()

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["listenPort"]; ok {
		t.Error("expected \"listenPort\" key to be absent when empty")
	}
}

// TestBGPRouterListenPortBoundaryValues verifies that port values 1 and 65535
// marshal and unmarshal correctly.
func TestBGPRouterListenPortBoundaryValues(t *testing.T) {
	cases := []struct {
		name string
		port int32
	}{
		{"min port 1", 1},
		{"max port 65535", 65535},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := newTestRouter()
			orig.Spec.ListenPort = &tc.port

			data, err := json.Marshal(orig.Spec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var got BGPRouterSpec
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if got.ListenPort == nil {
				t.Fatal("expected ListenPort to be set")
			} else if *got.ListenPort != tc.port {
				t.Errorf("ListenPort: got %d, want %d", *got.ListenPort, tc.port)
			}
		})
	}
}
