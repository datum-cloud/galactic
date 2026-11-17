// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

// TestIPv4OnlyAttachmentSubnet: the API server rejects the bare IPv4 address
// the CNI records for an IPv4-only pod, and accepts the pod subnet the cell
// controller derives from it.
func TestIPv4OnlyAttachmentSubnet(t *testing.T) {
	t.Parallel()
	const podAddress = "192.0.2.7"
	podSubnet, ok := galactic.PodSubnet(map[string]string{
		galactic.AnnotationAllocatedSubnetIPv4 + ".0123456789ab": podAddress,
	})
	if !ok {
		t.Fatal("no pod subnet for an IPv4-only pod")
	}
	f := startAPI(t)
	va := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "v4", Namespace: tenantNS},
		Spec: cloudv1alpha1.VPCAttachmentSpec{VPC: cloudv1alpha1.VPCRef{Name: f.vpc.Name},
			Interface: cloudv1alpha1.VPCAttachmentInterface{Name: "eth0"}},
	}
	f.create(va)
	va.Status.PodSubnet = podAddress
	if err := f.admin.Status().Update(context.Background(), va); err == nil {
		t.Fatalf("API server accepted bare address %q as podSubnet", podAddress)
	}
	va.Status.PodSubnet = podSubnet
	if err := f.admin.Status().Update(context.Background(), va); err != nil {
		t.Fatalf("API server rejected podSubnet %q: %v", podSubnet, err)
	}
}
