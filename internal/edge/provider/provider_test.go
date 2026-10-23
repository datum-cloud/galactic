// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package provider

import (
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

// TestLeaseRecordRoundTrip: a record the store writes reads back unchanged,
// a released one included, and a Lease with a malformed protocol annotation
// is refused rather than read as zero.
func TestLeaseRecordRoundTrip(t *testing.T) {
	want := claim.Record{Key: "ei-1", Holder: "p1", Incarnation: "uid-1", Epoch: 3, Sequence: 7,
		RenewStart: 42 * time.Second, Released: true, Version: "uid-1/9"}
	s := InstanceStore{}
	spec := s.spec(want, 3)
	l := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: want.Key, UID: "uid-1", ResourceVersion: "9",
			Annotations: protocolAnnotations(want)},
		Spec: spec,
	}
	got, err := record(l)
	if err != nil || got != want {
		t.Fatalf("round trip %+v, %v; want %+v", got, err, want)
	}
	for _, key := range []string{galacticv1alpha1.EdgeLeaseRenewStartAnnotation,
		galacticv1alpha1.EdgeLeaseSequenceAnnotation, galacticv1alpha1.EdgeLeaseReleasedAnnotation} {
		bad := l.DeepCopy()
		bad.Annotations[key] = "x"
		if _, err := record(bad); err == nil {
			t.Errorf("malformed %s read", key)
		}
	}
	if _, err := leaseEpoch(1 << 31); err == nil {
		t.Error("an epoch past leaseTransitions' range was accepted")
	}
}

// TestInstanceName: an instance's name is ei- and the pod UID, the name the
// galactic-edge-provider policy requires.
func TestInstanceName(t *testing.T) {
	const uid = "0f3c9a1e-6b2d-4e8f-9a7c-1d2e3f4a5b6c"
	if got := InstanceName(uid); got != "ei-"+uid {
		t.Errorf("InstanceName(%q) = %q, want ei-%s", uid, got, uid)
	}
	if inst := NewInstance("ns", "p", "pod", uid, "node", "boot"); inst.Name != InstanceName(uid) {
		t.Errorf("NewInstance named %q, want %q", inst.Name, InstanceName(uid))
	}
}
