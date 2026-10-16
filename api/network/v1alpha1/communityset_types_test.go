package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestCommunitySet() *BGPCommunitySet {
	return &BGPCommunitySet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPCommunitySet",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-comm"},
		Spec: BGPCommunitySetSpec{
			Type:    BGPCommunitySetTypeStandard,
			Entries: []string{"65000:100", "65000:200"},
		},
	}
}

// TestBGPCommunitySetDeepCopy verifies that DeepCopy produces an independent copy.
func TestBGPCommunitySetDeepCopy(t *testing.T) {
	orig := newTestCommunitySet()
	dup := orig.DeepCopy()

	dup.Spec.Entries[0] = "65001:999"
	dup.Spec.Type = BGPCommunitySetTypeLarge

	if orig.Spec.Entries[0] != "65000:100" {
		t.Errorf("Entry mutated: got %q", orig.Spec.Entries[0])
	}
	if orig.Spec.Type != BGPCommunitySetTypeStandard {
		t.Errorf("Type mutated: got %q", orig.Spec.Type)
	}
}

// TestBGPCommunitySetDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestBGPCommunitySetDeepCopyNil(t *testing.T) {
	var c *BGPCommunitySet
	if c.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestBGPCommunitySetJSONRoundTrip verifies that the struct serialises and
// deserialises through JSON without data loss.
func TestBGPCommunitySetJSONRoundTrip(t *testing.T) {
	orig := newTestCommunitySet()
	orig.Spec.Entries = []string{"65000:100", "no-export", "10.0.0.1:666"}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPCommunitySet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.Type != BGPCommunitySetTypeStandard {
		t.Errorf("Type: got %q, want %q", got.Spec.Type, BGPCommunitySetTypeStandard)
	}
	if len(got.Spec.Entries) != 3 {
		t.Fatalf("Entries count: got %d, want 3", len(got.Spec.Entries))
	}
	if got.Spec.Entries[0] != "65000:100" {
		t.Errorf("Entry[0]: got %q, want %q", got.Spec.Entries[0], "65000:100")
	}
	if got.Spec.Entries[1] != "no-export" {
		t.Errorf("Entry[1]: got %q, want %q", got.Spec.Entries[1], "no-export")
	}
	if got.Spec.Entries[2] != "10.0.0.1:666" {
		t.Errorf("Entry[2]: got %q, want %q", got.Spec.Entries[2], "10.0.0.1:666")
	}
}

// TestBGPCommunitySetListDeepCopy verifies that BGPCommunitySetList.DeepCopy produces
// independent copies of each item.
func TestBGPCommunitySetListDeepCopy(t *testing.T) {
	list := &BGPCommunitySetList{
		Items: []BGPCommunitySet{*newTestCommunitySet()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.Entries[0] = "99999:999"

	if list.Items[0].Spec.Entries[0] != "65000:100" {
		t.Error("original list item mutated via copy")
	}
}

// TestBGPCommunitySetTypeConstants verifies the enum constants.
func TestBGPCommunitySetTypeConstants(t *testing.T) {
	if BGPCommunitySetTypeStandard != "standard" {
		t.Errorf("BGPCommunitySetTypeStandard = %q, want %q", BGPCommunitySetTypeStandard, "standard")
	}
	if BGPCommunitySetTypeLarge != "large" {
		t.Errorf("BGPCommunitySetTypeLarge = %q, want %q", BGPCommunitySetTypeLarge, "large")
	}
}

// TestBGPCommunitySetLargeCommunities verifies large community entries survive
// JSON round-trip.
func TestBGPCommunitySetLargeCommunities(t *testing.T) {
	cs := &BGPCommunitySet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPCommunitySet",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "large-comm"},
		Spec: BGPCommunitySetSpec{
			Type:    BGPCommunitySetTypeLarge,
			Entries: []string{"65000:100:1", "65000:100:2", "65001:200:1"},
		},
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPCommunitySet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.Type != BGPCommunitySetTypeLarge {
		t.Errorf("Type: got %q, want %q", got.Spec.Type, BGPCommunitySetTypeLarge)
	}
	if len(got.Spec.Entries) != 3 {
		t.Fatalf("Entries count: got %d, want 3", len(got.Spec.Entries))
	}
	if got.Spec.Entries[0] != "65000:100:1" {
		t.Errorf("Entry[0]: got %q, want %q", got.Spec.Entries[0], "65000:100:1")
	}
}

// TestBGPCommunitySetWellKnownNames verifies well-known community names
// survive JSON round-trip.
func TestBGPCommunitySetWellKnownNames(t *testing.T) {
	cs := &BGPCommunitySet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPCommunitySet",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "wellknown-comm"},
		Spec: BGPCommunitySetSpec{
			Type:    BGPCommunitySetTypeStandard,
			Entries: []string{"graceful-shutdown", "no-export", "no-advertise", "blackhole"},
		},
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPCommunitySet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Spec.Entries) != 4 {
		t.Fatalf("Entries count: got %d, want 4", len(got.Spec.Entries))
	}

	wantNames := []string{"graceful-shutdown", "no-export", "no-advertise", "blackhole"}
	for i, want := range wantNames {
		if got.Spec.Entries[i] != want {
			t.Errorf("Entry[%d]: got %q, want %q", i, got.Spec.Entries[i], want)
		}
	}
}

// TestBGPCommunitySetFieldNames verifies the JSON key names for spec fields.
func TestBGPCommunitySetFieldNames(t *testing.T) {
	cs := newTestCommunitySet()

	data, err := json.Marshal(cs.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{"type", "entries"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("expected JSON key %q not found", key)
		}
	}
}

// TestBGPCommunitySetIPFormat verifies IP-based standard communities (IP:NN).
func TestBGPCommunitySetIPFormat(t *testing.T) {
	cs := &BGPCommunitySet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPCommunitySet",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "ip-comm"},
		Spec: BGPCommunitySetSpec{
			Type:    BGPCommunitySetTypeStandard,
			Entries: []string{"192.0.2.1:100", "198.51.100.5:200"},
		},
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPCommunitySet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Spec.Entries) != 2 {
		t.Fatalf("Entries count: got %d, want 2", len(got.Spec.Entries))
	}
	if got.Spec.Entries[0] != "192.0.2.1:100" {
		t.Errorf("Entry[0]: got %q, want %q", got.Spec.Entries[0], "192.0.2.1:100")
	}
}
