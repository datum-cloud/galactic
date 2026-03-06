package cniconfig_test

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha "github.com/datum-cloud/galactic-operator/api/v1alpha"

	"github.com/datum-cloud/galactic-common/cni"
	"github.com/datum-cloud/galactic-operator/internal/cniconfig"
)

func TestCNIConfigForVPCAttachment(t *testing.T) {
	expected := cniconfig.NetConfList{
		CNIVersion: "0.4.0",
		Plugins: []interface{}{
			cniconfig.PluginConfGalactic{
				Type:          "galactic",
				VPC:           "1hVwxnaA7",
				VPCAttachment: "h31",
				MTU:           1300,
				Terminations: []cni.Termination{
					{Network: "10.1.1.0/24"},
					{Network: "2001:10:1:1::/64"},
					{Network: "192.168.1.0/24", Via: "10.1.1.1"},
					{Network: "2001:1::/64", Via: "2001:10:1:1::1"},
				},
				IPAM: cni.IPAM{
					Type: "static",
					Addresses: []cni.Address{
						{Address: "10.1.1.1/24"},
						{Address: "2001:10:1:1::1/64"},
					},
					Routes: []cni.Route{
						{Dst: "192.168.2.0/24", GW: "10.1.1.2"},
						{Dst: "2001:2::/64", GW: "2001:10:1:1::2"},
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
			Identifier: "ffffffffffff",
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
			Routes: []galacticv1alpha.VPCAttachmentRoute{
				{Destination: "192.168.1.0/24", Via: "10.1.1.1"},
				{Destination: "2001:1::/64", Via: "2001:10:1:1::1"},
				{Destination: "192.168.2.0/24", Via: "10.1.1.2"},
				{Destination: "2001:2::/64", Via: "2001:10:1:1::2"},
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
