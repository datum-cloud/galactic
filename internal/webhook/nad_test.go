// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// testVPCName and testNamespace are shared across this package's test files.
const (
	testVPCName   = "my-vpc"
	testNamespace = "default"
)

func TestBuildNAD(t *testing.T) {
	defaults := NADDefaults{
		MTU:           1500,
		InterfaceType: interfaceTypeVeth,
		Terminations:  []termination{{Network: "0.0.0.0/0", Via: "10.0.0.1"}},
	}

	nad, err := buildNAD("my-vpc-0", testNamespace, "vpcBase62", testVPCName, "0", defaults)
	if err != nil {
		t.Fatalf("buildNAD() = %v, want nil", err)
	}

	if nad.GroupVersionKind() != nadGVK {
		t.Errorf("GVK = %v, want %v", nad.GroupVersionKind(), nadGVK)
	}
	if nad.GetName() != "my-vpc-0" {
		t.Errorf("name = %q, want %q", nad.GetName(), "my-vpc-0")
	}
	if nad.GetNamespace() != testNamespace {
		t.Errorf("namespace = %q, want %q", nad.GetNamespace(), testNamespace)
	}
	if got := nad.GetLabels()[labelVPC]; got != testVPCName {
		t.Errorf("label %s = %q, want %q", labelVPC, got, testVPCName)
	}
	if got := nad.GetLabels()[labelAttachmentID]; got != "0" {
		t.Errorf("label %s = %q, want %q", labelAttachmentID, got, "0")
	}

	configRaw, found, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil || !found {
		t.Fatalf("spec.config not found or errored: found=%v err=%v", found, err)
	}

	var conf cniConflist
	if err := json.Unmarshal([]byte(configRaw), &conf); err != nil {
		t.Fatalf("unmarshal spec.config: %v", err)
	}
	if conf.Type != pluginType {
		t.Errorf("conf.Type = %q, want %q", conf.Type, pluginType)
	}
	if conf.VPC != "vpcBase62" {
		t.Errorf("conf.VPC = %q, want %q", conf.VPC, "vpcBase62")
	}
	if conf.VPCName != testVPCName {
		t.Errorf("conf.VPCName = %q, want %q", conf.VPCName, testVPCName)
	}
	if conf.VPCAttachment != "0" {
		t.Errorf("conf.VPCAttachment = %q, want %q", conf.VPCAttachment, "0")
	}
	if conf.MTU != 1500 {
		t.Errorf("conf.MTU = %d, want 1500", conf.MTU)
	}
	if conf.InterfaceType != interfaceTypeVeth {
		t.Errorf("conf.InterfaceType = %q, want %q", conf.InterfaceType, interfaceTypeVeth)
	}
	if len(conf.Terminations) != 1 || conf.Terminations[0].Network != "0.0.0.0/0" {
		t.Errorf("conf.Terminations = %+v, want one entry for 0.0.0.0/0", conf.Terminations)
	}
	if conf.Name != "my-vpc-0" {
		t.Errorf("conf.Name = %q, want %q (must match the NAD's own object name)", conf.Name, "my-vpc-0")
	}
}

func TestDefaultNADDefaults(t *testing.T) {
	d := DefaultNADDefaults()
	if d.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", d.MTU)
	}
	if d.InterfaceType != interfaceTypeVeth {
		t.Errorf("InterfaceType = %q, want %q", d.InterfaceType, interfaceTypeVeth)
	}
}
