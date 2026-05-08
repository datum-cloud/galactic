// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniconfig_test

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"

	"go.datum.net/galactic/internal/operator/cniconfig"
	"go.datum.net/galactic/pkg/common/cni"
)

func TestCNIConfigForVPCAttachment(t *testing.T) {
	expected := cniconfig.NetConfList{
		CNIVersion: "0.4.0",
		Plugins: []interface{}{
			cniconfig.PluginConfGalactic{
				Type:          "galactic",
				VPC:           "4GFfc3",
				VPCAttachment: "h31",
				MTU:           1300,
				IPAM: cni.IPAM{
					Type: "static",
					Addresses: []cni.Address{
						{Address: "10.1.1.1/24"},
						{Address: "2001:10:1:1::1/64"},
					},
				},
			},
		},
	}

	vpc := galacticv1alpha.VPC{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vpc",
			Namespace: "default",
		},
		Spec: galacticv1alpha.VPCSpec{
			Networks: []string{
				"10.1.1.0/24",
				"2001:10:1:1::/64",
			},
		},
		Status: galacticv1alpha.VPCStatus{
			Ready:      true,
			Identifier: "ffffffff", // 32-bit hex, max value
		},
	}
	vpcAttachment := galacticv1alpha.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vpcattachment",
			Namespace: "default",
		},
		Spec: galacticv1alpha.VPCAttachmentSpec{
			VPC: corev1.ObjectReference{
				APIVersion: "galactic.datumapis.com/v1alpha",
				Kind:       "VPC",
				Name:       "test-vpc",
				Namespace:  "default",
			},
			Interface: galacticv1alpha.VPCAttachmentInterface{
				Name: "galactic0",
				Addresses: []string{
					"10.1.1.1/24",
					"2001:10:1:1::1/64",
				},
			},
		},
		Status: galacticv1alpha.VPCAttachmentStatus{
			Ready:      true,
			Identifier: "ffff",
		},
	}
	actual, err := cniconfig.CNIConfigForVPCAttachment(vpc, vpcAttachment)
	if err != nil {
		t.Errorf("CNIConfigForVPCAttachment error: %+v", err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("configs not equal\nExpected: %+v\nActual: %+v", expected, actual)
	}
}
