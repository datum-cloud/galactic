package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestVRF() *BGPVRFInstance {
	return &BGPVRFInstance{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPVRFInstance",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-vrf"},
		Spec: BGPVRFInstanceSpec{
			RouterTarget: RouterTarget{
				RouterRef: &RouterRef{Name: "overlay-router"},
			},
			VRFID:              100,
			ImportRouteTargets: []RouteTarget{{Value: "65000:100"}},
			ExportRouteTargets: []RouteTarget{{Value: "65000:100"}},
		},
	}
}

// TestBGPVRFInstanceDeepCopy verifies that DeepCopy produces an independent copy:
// mutations to slices and maps in the copy must not affect the original.
func TestBGPVRFInstanceDeepCopy(t *testing.T) {
	orig := newTestVRF()
	dup := orig.DeepCopy()

	// Mutate dup — original must be unaffected.
	dup.Spec.VRFID = 200
	dup.Spec.ImportRouteTargets[0].Value = "65001:200"
	dup.Spec.RouterRef.Name = "other-router"

	if orig.Spec.VRFID != 100 {
		t.Errorf("VRFID mutated: got %d", orig.Spec.VRFID)
	}
	if orig.Spec.ImportRouteTargets[0].Value != "65000:100" {
		t.Errorf("ImportRouteTargets[0] mutated: got %q", orig.Spec.ImportRouteTargets[0].Value)
	}
	if orig.Spec.RouterRef.Name != "overlay-router" {
		t.Errorf("RouterRef mutated: got %q", orig.Spec.RouterRef.Name)
	}
}

// TestBGPVRFInstanceDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestBGPVRFInstanceDeepCopyNil(t *testing.T) {
	var v *BGPVRFInstance
	if v.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestBGPVRFInstanceJSONRoundTrip verifies that the struct serialises and
// deserialises through JSON without data loss.
func TestBGPVRFInstanceJSONRoundTrip(t *testing.T) {
	orig := newTestVRF()
	orig.Spec.ImportRouteTargets = []RouteTarget{{Value: "65000:100"}, {Value: "65000:200"}}
	orig.Spec.ExportRouteTargets = []RouteTarget{{Value: "65000:100"}}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPVRFInstance
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.VRFID != orig.Spec.VRFID {
		t.Errorf("VRFID: got %d, want %d", got.Spec.VRFID, orig.Spec.VRFID)
	}
	if got.Spec.RouterRef.Name != orig.Spec.RouterRef.Name {
		t.Errorf("RouterRef: got %q, want %q", got.Spec.RouterRef.Name, orig.Spec.RouterRef.Name)
	}
	if len(got.Spec.ImportRouteTargets) != 2 {
		t.Errorf("ImportRouteTargets len: got %d, want 2", len(got.Spec.ImportRouteTargets))
	}
	if len(got.Spec.ExportRouteTargets) != 1 {
		t.Errorf("ExportRouteTargets len: got %d, want 1", len(got.Spec.ExportRouteTargets))
	}
	if got.Spec.ExportRouteTargets[0].Value != "65000:100" {
		t.Errorf("ExportRouteTargets[0]: got %q, want %q", got.Spec.ExportRouteTargets[0].Value, "65000:100")
	}
}

// TestBGPVRFInstanceListDeepCopy verifies that BGPVRFInstanceList.DeepCopy
// produces independent copies of each item.
func TestBGPVRFInstanceListDeepCopy(t *testing.T) {
	list := &BGPVRFInstanceList{
		Items: []BGPVRFInstance{*newTestVRF()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.VRFID = 999

	if list.Items[0].Spec.VRFID != 100 {
		t.Errorf("original list item mutated via copy")
	}
}

// TestBGPVRFInstanceVRFIDFieldName verifies the JSON key is "vrfID".
func TestBGPVRFInstanceVRFIDFieldName(t *testing.T) {
	orig := newTestVRF()

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw, ok := m["vrfID"]; !ok || raw != float64(100) {
		t.Errorf("unexpected vrfID value: %v", raw)
	}
}

// TestRouteTargetJSONFieldName verifies the JSON field name for RouteTarget.Value
// matches the CRD schema ("value").
func TestRouteTargetJSONFieldName(t *testing.T) {
	rt := RouteTarget{Value: "65000:100"}
	data, err := json.Marshal(rt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v, ok := m["value"]; !ok || v != "65000:100" {
		t.Errorf("expected JSON key \"value\"=\"65000:100\", got %v", m)
	}
}
