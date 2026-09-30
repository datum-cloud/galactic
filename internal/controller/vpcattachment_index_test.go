// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"testing"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVPCAttachmentIndexTracksObservedNode(t *testing.T) {
	index := NewVPCAttachmentIndex()
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "attachment-a"},
		Status:     cloudv1alpha1.VPCAttachmentStatus{Node: "node-a", PodSubnet: "fd20:0:19::2:0:0/96"},
	}

	index.Upsert(attachment)
	got := index.ForNode("node-a")
	if len(got) != 1 || got[0].Status.PodSubnet != attachment.Status.PodSubnet {
		t.Fatalf("ForNode(node-a) = %+v, want attachment", got)
	}
	if got := index.ForNode("node-b"); len(got) != 0 {
		t.Fatalf("ForNode(node-b) = %+v, want empty", got)
	}
}

func TestVPCAttachmentIndexMovesAndDeletes(t *testing.T) {
	index := NewVPCAttachmentIndex()
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "attachment-a"},
		Status:     cloudv1alpha1.VPCAttachmentStatus{Node: "node-a"},
	}
	index.Upsert(attachment)

	attachment.Status.Node = "node-b"
	index.Upsert(attachment)
	if len(index.ForNode("node-a")) != 0 || len(index.ForNode("node-b")) != 1 {
		t.Fatal("attachment was not moved between node indexes")
	}

	index.Delete(attachment)
	if len(index.ForNode("node-b")) != 0 {
		t.Fatal("attachment remained after delete")
	}
}

func TestVPCAttachmentIndexIgnoresUnassignedAttachment(t *testing.T) {
	index := NewVPCAttachmentIndex()
	index.Upsert(&cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "pending"},
		Status:     cloudv1alpha1.VPCAttachmentStatus{},
	})
	if got := index.ForNode("node-a"); len(got) != 0 {
		t.Fatalf("unassigned attachment indexed: %+v", got)
	}
}
