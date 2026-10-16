package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestEgressShard() *EgressShard {
	return &EgressShard{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "EgressShard",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-egress-shard",
			Namespace: "galactic-system",
			Labels: map[string]string{
				LabelEgressShardPool: "shared-public",
				LabelEgressShardCell: "us-east-2-a",
				LabelEgressShardIPv6: LabelValueEgressFamilyServed,
			},
		},
		Spec: EgressShardSpec{
			TargetRef:        TargetRef{Kind: "Node", Name: "node-a"},
			ShardSID:         "2001:db8:ff01:2001::",
			ShardAddressIPv6: "2001:db8:f00d::100",
			ShardAddressIPv6ClaimRef: &AddressClaimRef{
				APIGroup:  "ipam.miloapis.com",
				Kind:      "IPClaim",
				Project:   "datum-network-edge",
				Namespace: "egress",
				Name:      "egress-shard-node-a-ipv6",
			},
		},
	}
}

// TestEgressShardDeepCopy verifies that DeepCopy produces an independent
// copy: mutations to the copy must not affect the original.
func TestEgressShardDeepCopy(t *testing.T) {
	orig := newTestEgressShard()
	dup := orig.DeepCopy()

	dup.Spec.ShardSID = "2001:db8:ff01:2002::"
	dup.Spec.ShardAddressIPv6 = "2001:db8:f00d::200"
	dup.Spec.ShardAddressIPv4 = "198.51.100.7"
	dup.Spec.NAT64Prefix = "64:ff9b::/96"
	dup.Labels[LabelEgressShardPool] = "dedicated-public"
	dup.Spec.ShardAddressIPv6ClaimRef.Name = "some-other-claim"
	dup.Status.Conditions = append(dup.Status.Conditions, metav1.Condition{Type: ConditionTypeProgrammed})

	if orig.Spec.ShardSID != "2001:db8:ff01:2001::" {
		t.Errorf("ShardSID mutated: got %q", orig.Spec.ShardSID)
	}
	if orig.Spec.ShardAddressIPv6 != "2001:db8:f00d::100" {
		t.Errorf("ShardAddressIPv6 mutated: got %q", orig.Spec.ShardAddressIPv6)
	}
	if orig.Spec.ShardAddressIPv4 != "" {
		t.Errorf("ShardAddressIPv4 mutated: got %q", orig.Spec.ShardAddressIPv4)
	}
	if orig.Spec.NAT64Prefix != "" {
		t.Errorf("NAT64Prefix mutated: got %q", orig.Spec.NAT64Prefix)
	}
	if orig.Labels[LabelEgressShardPool] != "shared-public" {
		t.Errorf("pool label mutated: got %q", orig.Labels[LabelEgressShardPool])
	}
	if orig.Spec.ShardAddressIPv6ClaimRef.Name != "egress-shard-node-a-ipv6" {
		t.Errorf("claim ref aliased by DeepCopy: got %q", orig.Spec.ShardAddressIPv6ClaimRef.Name)
	}
	if len(orig.Status.Conditions) != 0 {
		t.Errorf("Conditions mutated: got %v", orig.Status.Conditions)
	}
}

// TestEgressShardDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestEgressShardDeepCopyNil(t *testing.T) {
	var s *EgressShard
	if s.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestEgressShardJSONRoundTrip verifies that the spec-side addresses and the
// status-side programmed values survive JSON marshal/unmarshal independently
// of each other.
func TestEgressShardJSONRoundTrip(t *testing.T) {
	orig := newTestEgressShard()
	orig.Spec.ShardAddressIPv4 = "198.51.100.7"
	orig.Spec.NAT64Prefix = "64:ff9b::/96"
	orig.Status = EgressShardStatus{
		ObservedGeneration: 3,
		ShardSID:           "2001:db8:ff01::",
		ShardAddressIPv6:   "2001:db8:f00d::100",
		Conditions: []metav1.Condition{
			{
				Type:   ConditionTypeProgrammed,
				Status: metav1.ConditionFalse,
				Reason: ProgrammedReasonProgrammingFailed,
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got EgressShard
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.ShardSID != orig.Spec.ShardSID ||
		got.Spec.ShardAddressIPv6 != orig.Spec.ShardAddressIPv6 ||
		got.Spec.ShardAddressIPv4 != orig.Spec.ShardAddressIPv4 ||
		got.Spec.NAT64Prefix != orig.Spec.NAT64Prefix ||
		got.Spec.TargetRef != orig.Spec.TargetRef {
		t.Errorf("Spec: got %+v, want %+v", got.Spec, orig.Spec)
	}
	if got.Spec.ShardAddressIPv6ClaimRef == nil || *got.Spec.ShardAddressIPv6ClaimRef != *orig.Spec.ShardAddressIPv6ClaimRef {
		t.Errorf("ShardAddressIPv6ClaimRef: got %+v, want %+v", got.Spec.ShardAddressIPv6ClaimRef, orig.Spec.ShardAddressIPv6ClaimRef)
	}
	if got.Status.ShardSID != orig.Status.ShardSID {
		t.Errorf("ShardSID: got %q, want %q", got.Status.ShardSID, orig.Status.ShardSID)
	}
	if got.Status.ShardAddressIPv6 != orig.Status.ShardAddressIPv6 {
		t.Errorf("status ShardAddressIPv6: got %q, want %q", got.Status.ShardAddressIPv6, orig.Status.ShardAddressIPv6)
	}
	if got.Status.ShardAddressIPv4 != "" {
		t.Errorf("status ShardAddressIPv4: got %q, want empty", got.Status.ShardAddressIPv4)
	}
	if len(got.Status.Conditions) != 1 || got.Status.Conditions[0].Reason != ProgrammedReasonProgrammingFailed {
		t.Errorf("Conditions: got %+v", got.Status.Conditions)
	}
}

// TestEgressShardSpecFieldNames verifies the spec JSON keys, which the cell
// controller writes and the CRD's CEL rules name.
func TestEgressShardSpecFieldNames(t *testing.T) {
	orig := newTestEgressShard()
	orig.Spec.ShardAddressIPv4 = "198.51.100.7"
	orig.Spec.NAT64Prefix = "64:ff9b::/96"
	orig.Spec.TranslateWellKnownPrefix = true
	orig.Spec.Drain = true

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	want := map[string]string{
		"shardSID":         "2001:db8:ff01:2001::",
		"shardAddressIPv6": "2001:db8:f00d::100",
		"shardAddressIPv4": "198.51.100.7",
		"nat64Prefix":      "64:ff9b::/96",
	}
	for key, value := range want {
		if raw, ok := m[key]; !ok || raw != value {
			t.Errorf("%s: got %v, want %q", key, raw, value)
		}
	}
	if raw, ok := m["translateWellKnownPrefix"]; !ok || raw != true {
		t.Errorf("translateWellKnownPrefix: got %v, want true", raw)
	}
	if raw, ok := m["drain"]; !ok || raw != true {
		t.Errorf("drain: got %v, want true", raw)
	}
	if _, ok := m["targetRef"]; !ok {
		t.Error("expected \"targetRef\" key to be present")
	}

	claimRef, ok := m["shardAddressIPv6ClaimRef"].(map[string]any)
	if !ok {
		t.Fatalf("shardAddressIPv6ClaimRef: got %v, want an object", m["shardAddressIPv6ClaimRef"])
	}
	wantRef := map[string]string{
		"apiGroup":  "ipam.miloapis.com",
		"kind":      "IPClaim",
		"project":   "datum-network-edge",
		"namespace": "egress",
		"name":      "egress-shard-node-a-ipv6",
	}
	for key, value := range wantRef {
		if raw, ok := claimRef[key]; !ok || raw != value {
			t.Errorf("shardAddressIPv6ClaimRef.%s: got %v, want %q", key, raw, value)
		}
	}
}

// TestEgressShardSpecOmitEmpty verifies that a shard with no address assigned
// yet omits every address key, which is what distinguishes an unclaimed
// address from a blank one.
func TestEgressShardSpecOmitEmpty(t *testing.T) {
	spec := EgressShardSpec{TargetRef: TargetRef{Kind: "Node", Name: "node-a"}}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{
		"shardSID", "shardAddressIPv6", "shardAddressIPv4", "nat64Prefix",
		"shardAddressIPv6ClaimRef", "shardAddressIPv4ClaimRef",
		"translateWellKnownPrefix", "drain",
	} {
		if _, ok := m[key]; ok {
			t.Errorf("expected %q key to be absent when empty", key)
		}
	}
}

// TestEgressShardLabelKeys verifies the selection label keys stay in this
// API group's own namespace. A key naming another group would make a data
// plane resource carry a reference to the API that selects it.
func TestEgressShardLabelKeys(t *testing.T) {
	cases := map[string]string{
		"pool": LabelEgressShardPool,
		"cell": LabelEgressShardCell,
		"ipv6": LabelEgressShardIPv6,
		"ipv4": LabelEgressShardIPv4,
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			const prefix = "galactic.datumapis.com/"
			if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
				t.Errorf("label key %q: want prefix %q", key, prefix)
			}
		})
	}
}
