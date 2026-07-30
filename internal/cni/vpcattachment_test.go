// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

func TestVPCAttachmentName(t *testing.T) {
	got := vpcAttachmentName(testVPC, testAttachment)
	want := testVPC + "-" + testAttachment
	if got != want {
		t.Errorf("vpcAttachmentName(%q, %q) = %q, want %q", testVPC, testAttachment, got, want)
	}
}

func TestParsePodName(t *testing.T) {
	tests := []struct {
		name     string
		cniArgs  string
		expected string
	}{
		{name: "empty string", cniArgs: "", expected: ""},
		{name: "name only", cniArgs: "K8S_POD_NAME=" + testPodName, expected: testPodName},
		{
			name:     "full multus args",
			cniArgs:  "K8S_POD_NAME=" + testPodName + ";K8S_POD_NAMESPACE=galactic-system;K8S_POD_INFRA_CONTAINER_ID=abc123",
			expected: testPodName,
		},
		{name: "name not present", cniArgs: "K8S_POD_NAMESPACE=" + testNamespace, expected: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePodName(tc.cniArgs)
			if got != tc.expected {
				t.Errorf("parsePodName(%q) = %q, want %q", tc.cniArgs, got, tc.expected)
			}
		})
	}
}

func TestTruncateContainerID(t *testing.T) {
	short := "abc123"
	if got := truncateContainerID(short); got != short {
		t.Errorf("truncateContainerID(%q) = %q, want unchanged", short, got)
	}

	full := strings.Repeat("a", 64) // real container IDs are 64 hex chars
	got := truncateContainerID(full)
	if len(got) != containerIDStatusLen {
		t.Errorf("truncateContainerID(64-char id) length = %d, want %d", len(got), containerIDStatusLen)
	}
	if got != full[:containerIDStatusLen] {
		t.Errorf("truncateContainerID(%q) = %q, want prefix %q", full, got, full[:containerIDStatusLen])
	}
}

func TestVPCAttachmentAddressesAndPodSubnet(t *testing.T) {
	t.Run("nil ipamResult", func(t *testing.T) {
		if addrs := vpcAttachmentAddresses(nil); addrs != nil {
			t.Errorf("vpcAttachmentAddresses(nil) = %v, want nil", addrs)
		}
		if subnet := vpcAttachmentPodSubnet(nil); subnet != "" {
			t.Errorf("vpcAttachmentPodSubnet(nil) = %q, want empty", subnet)
		}
	})

	t.Run("IPv4 only", func(t *testing.T) {
		res := &ipamResult{ipv4Address: net.ParseIP("10.128.0.5")}
		addrs := vpcAttachmentAddresses(res)
		if len(addrs) != 1 || addrs[0] != testIPv4Prefix {
			t.Errorf("vpcAttachmentAddresses = %v, want [%q]", addrs, testIPv4Prefix)
		}
		if subnet := vpcAttachmentPodSubnet(res); subnet != "" {
			t.Errorf("vpcAttachmentPodSubnet = %q, want empty (no IPv6 subnet)", subnet)
		}
	})

	t.Run("dual stack", func(t *testing.T) {
		ipv6Subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
		res := &ipamResult{ipv6Subnet: ipv6Subnet, ipv4Address: net.ParseIP("10.128.0.5")}
		addrs := vpcAttachmentAddresses(res)
		wantIPv6 := cloudv1alpha1.IPAddress(ipv6Subnet.String())
		if len(addrs) != 2 || addrs[0] != wantIPv6 || addrs[1] != testIPv4Prefix {
			t.Errorf("vpcAttachmentAddresses = %v, want [%q, %q]", addrs, wantIPv6, testIPv4Prefix)
		}
		if subnet := vpcAttachmentPodSubnet(res); subnet != ipv6Subnet.String() {
			t.Errorf("vpcAttachmentPodSubnet = %q, want %q", subnet, ipv6Subnet.String())
		}
	})
}

// applyTestVPCAttachment is a thin wrapper around applyVPCAttachment fixing
// node/hostIf/guestIf to constant test values, so call sites in this file
// stay under the line-length limit.
func applyTestVPCAttachment(
	k8s client.Client, args *skel.CmdArgs, conf *PluginConf, podNamespace string,
	ipamRes *ipamResult, tracker *resourceTracker,
) error {
	return applyVPCAttachment(
		context.Background(), k8s, args, conf, podNamespace, "node-1", "hostIf", "guestIf", ipamRes, tracker,
	)
}

func TestApplyVPCAttachment(t *testing.T) {
	baseConf := func() *PluginConf {
		return &PluginConf{
			VPC:           testVPC,
			VPCName:       testVPCName,
			VPCAttachment: testAttachment,
		}
	}
	baseArgs := &skel.CmdArgs{
		ContainerID: strings.Repeat("a", 64),
		IfName:      testIfName,
		Args:        "K8S_POD_NAME=" + testPodName + ";K8S_POD_NAMESPACE=" + testNamespace,
	}
	dualStackIPAM := &ipamResult{
		ipv6Subnet:  mustParseCIDR(t, "fd00:10:ff01::1234/96"),
		ipv4Address: net.ParseIP("10.128.0.5"),
	}

	t.Run("skipped when VPCName is empty", func(t *testing.T) {
		k8s := fakeClient()
		conf := baseConf()
		conf.VPCName = ""
		tracker := &resourceTracker{}

		if err := applyTestVPCAttachment(k8s, baseArgs, conf, testNamespace, dualStackIPAM, tracker); err != nil {
			t.Fatalf("applyVPCAttachment() = %v, want nil (skip)", err)
		}
		if tracker.vpcAttachmentCreated {
			t.Error("tracker.vpcAttachmentCreated = true, want false (skipped)")
		}
		var list cloudv1alpha1.VPCAttachmentList
		if err := k8s.List(context.Background(), &list); err != nil {
			t.Fatalf("list VPCAttachments: %v", err)
		}
		if len(list.Items) != 0 {
			t.Errorf("VPCAttachments created = %d, want 0", len(list.Items))
		}
	})

	t.Run("skipped when no IPAM allocation", func(t *testing.T) {
		k8s := fakeClient()
		tracker := &resourceTracker{}

		if err := applyTestVPCAttachment(k8s, baseArgs, baseConf(), testNamespace, nil, tracker); err != nil {
			t.Fatalf("applyVPCAttachment() = %v, want nil (skip)", err)
		}
		if tracker.vpcAttachmentCreated {
			t.Error("tracker.vpcAttachmentCreated = true, want false (skipped)")
		}
	})

	t.Run("errors when pod namespace is empty", func(t *testing.T) {
		k8s := fakeClient()
		tracker := &resourceTracker{}

		err := applyTestVPCAttachment(k8s, baseArgs, baseConf(), "", dualStackIPAM, tracker)
		if err == nil {
			t.Fatal("expected error for empty pod namespace, got nil")
		}
	})

	t.Run("creates Spec and Status from IPAM result", func(t *testing.T) {
		k8s := fakeClient()
		conf := baseConf()
		tracker := &resourceTracker{}

		err := applyTestVPCAttachment(k8s, baseArgs, conf, testNamespace, dualStackIPAM, tracker)
		if err != nil {
			t.Fatalf("applyVPCAttachment() = %v, want nil", err)
		}
		if !tracker.vpcAttachmentCreated {
			t.Error("tracker.vpcAttachmentCreated = false, want true")
		}

		var got cloudv1alpha1.VPCAttachment
		name := vpcAttachmentName(conf.VPC, conf.VPCAttachment)
		key := client.ObjectKey{Name: name, Namespace: testNamespace}
		if err := k8s.Get(context.Background(), key, &got); err != nil {
			t.Fatalf("get VPCAttachment: %v", err)
		}

		if got.Spec.VPC.Name != conf.VPCName {
			t.Errorf("Spec.VPC.Name = %q, want %q", got.Spec.VPC.Name, conf.VPCName)
		}
		if got.Spec.Interface.Name != testIfName {
			t.Errorf("Spec.Interface.Name = %q, want %q", got.Spec.Interface.Name, testIfName)
		}
		if len(got.Spec.Interface.Addresses) != 2 {
			t.Errorf("Spec.Interface.Addresses = %v, want 2 entries", got.Spec.Interface.Addresses)
		}

		if got.Status.VPC != conf.VPC {
			t.Errorf("Status.VPC = %q, want %q", got.Status.VPC, conf.VPC)
		}
		if got.Status.VPCAttachment != conf.VPCAttachment {
			t.Errorf("Status.VPCAttachment = %q, want %q", got.Status.VPCAttachment, conf.VPCAttachment)
		}
		if got.Status.Node != "node-1" {
			t.Errorf("Status.Node = %q, want %q", got.Status.Node, "node-1")
		}
		if len(got.Status.ContainerID) != containerIDStatusLen {
			t.Errorf("Status.ContainerID length = %d, want %d", len(got.Status.ContainerID), containerIDStatusLen)
		}
		if got.Status.PodName != testPodName {
			t.Errorf("Status.PodName = %q, want %q", got.Status.PodName, testPodName)
		}
		if got.Status.HostInterface != "hostIf" || got.Status.VRFInterface == "" || got.Status.GuestInterface != "guestIf" {
			t.Errorf("Status interface names = %+v, unexpected", got.Status)
		}
		if got.Status.PodSubnet != dualStackIPAM.ipv6Subnet.String() {
			t.Errorf("Status.PodSubnet = %q, want %q", got.Status.PodSubnet, dualStackIPAM.ipv6Subnet.String())
		}
	})

	t.Run("re-applying is idempotent (CreateOrUpdate)", func(t *testing.T) {
		k8s := fakeClient()
		conf := baseConf()
		tracker := &resourceTracker{}

		for i := range 2 {
			if err := applyTestVPCAttachment(k8s, baseArgs, conf, testNamespace, dualStackIPAM, tracker); err != nil {
				t.Fatalf("applyVPCAttachment() attempt %d = %v, want nil", i, err)
			}
		}
		var list cloudv1alpha1.VPCAttachmentList
		if err := k8s.List(context.Background(), &list); err != nil {
			t.Fatalf("list VPCAttachments: %v", err)
		}
		if len(list.Items) != 1 {
			t.Errorf("VPCAttachments after 2 applies = %d, want 1", len(list.Items))
		}
	})
}

func TestDeleteVPCAttachment(t *testing.T) {
	t.Run("not found is not an error", func(t *testing.T) {
		k8s := fakeClient()
		if err := deleteVPCAttachment(context.Background(), k8s, testVPC, testAttachment, testNamespace); err != nil {
			t.Fatalf("deleteVPCAttachment() = %v, want nil", err)
		}
	})

	t.Run("deletes an existing VPCAttachment", func(t *testing.T) {
		name := vpcAttachmentName(testVPC, testAttachment)
		existing := &cloudv1alpha1.VPCAttachment{}
		existing.SetName(name)
		existing.SetNamespace(testNamespace)
		existing.Spec = cloudv1alpha1.VPCAttachmentSpec{
			VPC: cloudv1alpha1.VPCRef{Name: testVPCName},
			Interface: cloudv1alpha1.VPCAttachmentInterface{
				Name:      testIfName,
				Addresses: []cloudv1alpha1.IPAddress{"10.0.0.1/32"},
			},
		}
		k8s := fakeClient(existing)

		if err := deleteVPCAttachment(context.Background(), k8s, testVPC, testAttachment, testNamespace); err != nil {
			t.Fatalf("deleteVPCAttachment() = %v, want nil", err)
		}

		var got cloudv1alpha1.VPCAttachment
		key := client.ObjectKey{Name: name, Namespace: testNamespace}
		if err := k8s.Get(context.Background(), key, &got); err == nil {
			t.Fatal("expected VPCAttachment to be deleted, but Get succeeded")
		}
	})
}
