// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

func TestLowestFree(t *testing.T) {
	tests := []struct {
		name   string
		used   map[uint16]bool
		wantID uint16
		wantOK bool
	}{
		{name: "empty", used: map[uint16]bool{}, wantID: 0, wantOK: true},
		{name: "0 taken", used: map[uint16]bool{0: true}, wantID: 1, wantOK: true},
		{name: "0 and 1 taken", used: map[uint16]bool{0: true, 1: true}, wantID: 2, wantOK: true},
		{name: "gap in the middle", used: map[uint16]bool{0: true, 1: true, 3: true}, wantID: 2, wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := lowestFree(tc.used)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("lowestFree(%v) = (%d, %v), want (%d, %v)", tc.used, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}

	t.Run("fully exhausted", func(t *testing.T) {
		full := make(map[uint16]bool, 65536)
		for i := range 65536 {
			full[uint16(i)] = true
		}
		if _, ok := lowestFree(full); ok {
			t.Error("lowestFree(full) ok = true, want false")
		}
	})
}

func webhookFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(NewScheme()).WithObjects(objs...).Build()
}

func nadWithLabels(name, vpcName, attachmentIDBase62 string) *unstructured.Unstructured {
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(name)
	nad.SetNamespace(testNamespace)
	nad.SetLabels(map[string]string{
		labelVPC:          vpcName,
		labelAttachmentID: attachmentIDBase62,
	})
	return nad
}

func TestAllocateVPCAttachmentID(t *testing.T) {
	vpc := &cloudv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: testVPCName}}

	t.Run("no existing NADs returns the lowest ID", func(t *testing.T) {
		k8s := webhookFakeClient()
		id, err := AllocateVPCAttachmentID(context.Background(), k8s, vpc, testNamespace)
		if err != nil {
			t.Fatalf("AllocateVPCAttachmentID() = %v, want nil", err)
		}
		if id == "" {
			t.Error("id is empty, want a base62 string")
		}
	})

	t.Run("skips IDs already taken by NADs for this VPC", func(t *testing.T) {
		firstID, err := AllocateVPCAttachmentID(context.Background(), webhookFakeClient(), vpc, testNamespace)
		if err != nil {
			t.Fatalf("allocate baseline id: %v", err)
		}
		nad := nadWithLabels(testVPCName+"-"+firstID, testVPCName, firstID)
		k8s := webhookFakeClient(nad)

		secondID, err := AllocateVPCAttachmentID(context.Background(), k8s, vpc, testNamespace)
		if err != nil {
			t.Fatalf("AllocateVPCAttachmentID() = %v, want nil", err)
		}
		if secondID == firstID {
			t.Errorf("second allocation = %q, want different from already-taken %q", secondID, firstID)
		}
	})

	t.Run("NADs for a different VPC don't count against this one", func(t *testing.T) {
		otherVPCNAD := nadWithLabels("other-vpc-0", "other-vpc", "0")
		k8s := webhookFakeClient(otherVPCNAD)

		id, err := AllocateVPCAttachmentID(context.Background(), k8s, vpc, testNamespace)
		if err != nil {
			t.Fatalf("AllocateVPCAttachmentID() = %v, want nil", err)
		}
		// The lowest ID (base62 "0") must still be available for testVPCName
		// even though "other-vpc" has already used it.
		if id != "0" {
			t.Errorf("id = %q, want %q (cross-VPC NAD must not count)", id, "0")
		}
	})

	t.Run("malformed attachment-id label is ignored, not fatal", func(t *testing.T) {
		nad := nadWithLabels(testVPCName+"-bad", testVPCName, "not-base62-!!!")
		k8s := webhookFakeClient(nad)

		id, err := AllocateVPCAttachmentID(context.Background(), k8s, vpc, testNamespace)
		if err != nil {
			t.Fatalf("AllocateVPCAttachmentID() = %v, want nil", err)
		}
		if id == "" {
			t.Error("id is empty, want a base62 string")
		}
	})
}
