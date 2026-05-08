// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniconfig

import (
	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"

	"go.datum.net/galactic/pkg/common/cni"
	"go.datum.net/galactic/pkg/common/util"
)

// types inlined from CNI and Galactic CNI packages to simplify cross dependencies
type NetConfList struct {
	CNIVersion string      `json:"cniVersion"`
	Plugins    interface{} `json:"plugins"`
}

// PluginConfGalactic is the per-plugin config block for the galactic CNI
// plugin embedded in the Multus NetworkAttachmentDefinition.
//
// Pod-reachable prefixes beyond the pod's own addresses are now learned via
// BGP, not declared statically in the NAD. The CNI plugin's job is reduced
// to creating the local kernel objects (VRF, veth pair) and registering
// the attachment with the local agent — which then advertises the pod's
// IPs into the cluster's BGP fabric.
type PluginConfGalactic struct {
	Type          string   `json:"type"`
	VPC           string   `json:"vpc"`
	VPCAttachment string   `json:"vpcattachment"`
	MTU           int      `json:"mtu,omitempty"`
	IPAM          cni.IPAM `json:"ipam,omitempty"`
}

func CNIConfigForVPCAttachment(vpc galacticv1alpha.VPC, vpcAttachment galacticv1alpha.VPCAttachment) (NetConfList, error) {
	addresses := make([]cni.Address, 0, len(vpcAttachment.Spec.Interface.Addresses))
	for _, address := range vpcAttachment.Spec.Interface.Addresses {
		addresses = append(addresses, cni.Address{Address: address})
	}

	vpcIdentifierBase62, err := util.HexToBase62(vpc.Status.Identifier)
	if err != nil {
		return NetConfList{}, err
	}
	vpcAttachmentIdentifierBase62, err := util.HexToBase62(vpcAttachment.Status.Identifier)
	if err != nil {
		return NetConfList{}, err
	}

	return NetConfList{
		CNIVersion: "0.4.0",
		Plugins: []interface{}{
			PluginConfGalactic{
				Type:          "galactic",
				VPC:           vpcIdentifierBase62,
				VPCAttachment: vpcAttachmentIdentifierBase62,
				MTU:           1300,
				IPAM: cni.IPAM{
					Type:      "static",
					Addresses: addresses,
				},
			},
		},
	}, nil
}
