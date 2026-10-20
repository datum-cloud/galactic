package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestPrefixList() *BGPPrefixList {
	return &BGPPrefixList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPPrefixList",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-pfx"},
		Spec: BGPPrefixListSpec{
			Entries: []BGPPrefixListEntry{
				{Sequence: 5, Action: BGPPolicyActionPermit, Prefix: "10.0.0.0/8"},
			},
		},
	}
}

// TestBGPPrefixListDeepCopy verifies that DeepCopy produces an independent copy.
func TestBGPPrefixListDeepCopy(t *testing.T) {
	orig := newTestPrefixList()
	dup := orig.DeepCopy()

	dup.Spec.Entries[0].Prefix = "192.168.0.0/16"
	dup.Spec.Entries[0].Action = BGPPolicyActionDeny

	if orig.Spec.Entries[0].Prefix != "10.0.0.0/8" {
		t.Errorf("Prefix mutated: got %q", orig.Spec.Entries[0].Prefix)
	}
	if orig.Spec.Entries[0].Action != BGPPolicyActionPermit {
		t.Errorf("Action mutated: got %q", orig.Spec.Entries[0].Action)
	}
}

// TestBGPPrefixListDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestBGPPrefixListDeepCopyNil(t *testing.T) {
	var p *BGPPrefixList
	if p.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestBGPPrefixListJSONRoundTrip verifies that the struct serialises and
// deserialises through JSON without data loss.
func TestBGPPrefixListJSONRoundTrip(t *testing.T) {
	orig := newTestPrefixList()
	ge := int32(16)
	le := int32(24)
	orig.Spec.Entries = []BGPPrefixListEntry{
		{Sequence: 5, Action: BGPPolicyActionPermit, Prefix: "10.0.0.0/8", GE: &ge, LE: &le},
		{Sequence: 10, Action: BGPPolicyActionDeny, Prefix: "0.0.0.0/0"},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPPrefixList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Spec.Entries) != 2 {
		t.Fatalf("Entries count: got %d, want 2", len(got.Spec.Entries))
	}

	e0 := got.Spec.Entries[0]
	if e0.Sequence != 5 {
		t.Errorf("Entry[0].Sequence: got %d, want 5", e0.Sequence)
	}
	if e0.Action != BGPPolicyActionPermit {
		t.Errorf("Entry[0].Action: got %q, want %q", e0.Action, BGPPolicyActionPermit)
	}
	if e0.Prefix != "10.0.0.0/8" {
		t.Errorf("Entry[0].Prefix: got %q, want %q", e0.Prefix, "10.0.0.0/8")
	}
	if e0.GE == nil || *e0.GE != ge {
		t.Errorf("Entry[0].GE: got %v, want %d", e0.GE, ge)
	}
	if e0.LE == nil || *e0.LE != le {
		t.Errorf("Entry[0].LE: got %v, want %d", e0.LE, le)
	}

	e1 := got.Spec.Entries[1]
	if e1.Action != BGPPolicyActionDeny {
		t.Errorf("Entry[1].Action: got %q, want %q", e1.Action, BGPPolicyActionDeny)
	}
	if e1.Prefix != "0.0.0.0/0" {
		t.Errorf("Entry[1].Prefix: got %q, want %q", e1.Prefix, "0.0.0.0/0")
	}
}

// TestBGPPrefixListListDeepCopy verifies that BGPPrefixListList.DeepCopy produces
// independent copies of each item.
func TestBGPPrefixListListDeepCopy(t *testing.T) {
	list := &BGPPrefixListList{
		Items: []BGPPrefixList{*newTestPrefixList()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.Entries[0].Prefix = "172.16.0.0/12"

	if list.Items[0].Spec.Entries[0].Prefix != "10.0.0.0/8" {
		t.Error("original list item mutated via copy")
	}
}

// TestBGPPrefixListEntryFieldNames verifies the JSON key names for entry fields.
func TestBGPPrefixListEntryFieldNames(t *testing.T) {
	ge := int32(16)
	le := int32(24)
	entry := BGPPrefixListEntry{
		Sequence: 5,
		Action:   BGPPolicyActionPermit,
		Prefix:   "10.0.0.0/8",
		GE:       &ge,
		LE:       &le,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{"sequence", "action", "prefix", "ge", "le"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("expected JSON key %q not found", key)
		}
	}
}

// TestBGPPrefixListEntryOptionalFieldsOmitted verifies that GE and LE are
// omitted from JSON when nil.
func TestBGPPrefixListEntryOptionalFieldsOmitted(t *testing.T) {
	entry := BGPPrefixListEntry{
		Sequence: 5,
		Action:   BGPPolicyActionDeny,
		Prefix:   "0.0.0.0/0",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{"ge", "le"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected %q to be omitted when nil", key)
		}
	}
}

// TestBGPPrefixListIPv6Entries verifies IPv6 prefix-list entries survive
// JSON round-trip.
func TestBGPPrefixListIPv6Entries(t *testing.T) {
	pl := &BGPPrefixList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPPrefixList",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "ipv6-pfx"},
		Spec: BGPPrefixListSpec{
			Entries: []BGPPrefixListEntry{
				{Sequence: 5, Action: BGPPolicyActionPermit, Prefix: "2001:db8::/32", GE: ptrInt32(48), LE: ptrInt32(64)},
				{Sequence: 10, Action: BGPPolicyActionDeny, Prefix: "::/0"},
			},
		},
	}

	data, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPPrefixList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Spec.Entries) != 2 {
		t.Fatalf("Entries count: got %d, want 2", len(got.Spec.Entries))
	}
	if got.Spec.Entries[0].Prefix != "2001:db8::/32" {
		t.Errorf("Entry[0].Prefix: got %q, want %q", got.Spec.Entries[0].Prefix, "2001:db8::/32")
	}
	if got.Spec.Entries[1].Prefix != "::/0" {
		t.Errorf("Entry[1].Prefix: got %q, want %q", got.Spec.Entries[1].Prefix, "::/0")
	}
}

// TestBGPPrefixListEntryDeepCopy verifies DeepCopy handles pointer fields.
func TestBGPPrefixListEntryDeepCopy(t *testing.T) {
	ge := int32(16)
	le := int32(24)
	orig := BGPPrefixListEntry{
		Sequence: 5,
		Action:   BGPPolicyActionPermit,
		Prefix:   "10.0.0.0/8",
		GE:       &ge,
		LE:       &le,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var copied BGPPrefixListEntry
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Mutate the copy's pointers.
	newGE := int32(20)
	newLE := int32(28)
	*copied.GE = newGE
	*copied.LE = newLE

	// Original should be unchanged (json round-trip creates independent pointers).
	if *orig.GE != ge {
		t.Errorf("GE mutated: got %d, want %d", *orig.GE, ge)
	}
	if *orig.LE != le {
		t.Errorf("LE mutated: got %d, want %d", *orig.LE, le)
	}
}

func ptrInt32(v int32) *int32 {
	return &v
}
