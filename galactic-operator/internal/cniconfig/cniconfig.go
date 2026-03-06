package cniconfig

import (
	"fmt"
	"net"

	galacticv1alpha "github.com/datum-cloud/galactic-operator/api/v1alpha"

	"github.com/datum-cloud/galactic-common/cni"
	"github.com/datum-cloud/galactic-common/util"
)

// types inlined from CNI and Galactic CNI packages to simplify cross dependencies
type NetConfList struct {
	CNIVersion string      `json:"cniVersion"`
	Plugins    interface{} `json:"plugins"`
}

type PluginConfGalactic struct {
	Type          string            `json:"type"`
	VPC           string            `json:"vpc"`
	VPCAttachment string            `json:"vpcattachment"`
	MTU           int               `json:"mtu,omitempty"`
	Terminations  []cni.Termination `json:"terminations,omitempty"`
	IPAM          cni.IPAM          `json:"ipam,omitempty"`
}

func CNIConfigForVPCAttachment(vpc galacticv1alpha.VPC, vpcAttachment galacticv1alpha.VPCAttachment) (NetConfList, error) {
	terminations := make([]cni.Termination, 0, 10)
	addresses := make([]cni.Address, 0, 10)
	routes := make([]cni.Route, 0, 10)

	netAddresses := make([]net.IP, 0, 10) // to check if a route is local

	for _, address := range vpcAttachment.Spec.Interface.Addresses {
		netAddress, network, err := net.ParseCIDR(address)
		if err != nil {
			return NetConfList{}, err
		}
		netAddresses = append(netAddresses, netAddress)
		addresses = append(addresses, cni.Address{Address: address})
		terminations = append(terminations, cni.Termination{Network: network.String()})
	}

	for _, route := range vpcAttachment.Spec.Routes {
		_, network, err := net.ParseCIDR(route.Destination)
		if err != nil {
			return NetConfList{}, err
		}

		if route.Via != "" {
			via := net.ParseIP(route.Via)
			if via == nil {
				return NetConfList{}, fmt.Errorf("failed to parse route via %q", route.Via)
			}

			local := false
			for _, netAddress := range netAddresses {
				if via.Equal(netAddress) {
					local = true
					break
				}
			}
			if local { // local routes are terminations
				terminations = append(terminations, cni.Termination{Network: network.String(), Via: via.String()})
			} else {
				routes = append(routes, cni.Route{Dst: network.String(), GW: via.String()})
			}
		}
	}

	vpcIdentifierBase62, err := util.HexToBase62(vpc.Status.Identifier)
	if err != nil {
		return NetConfList{}, err
	}
	vpcAttachmentIdentifierBase62, err := util.HexToBase62(vpcAttachment.Status.Identifier)
	if err != nil {
		return NetConfList{}, err
	}

	// TODO Change to use VPC & VPCAttachment identifiers once CNI is adjusted
	return NetConfList{
		CNIVersion: "0.4.0",
		Plugins: []interface{}{
			PluginConfGalactic{
				Type:          "galactic",
				VPC:           vpcIdentifierBase62,
				VPCAttachment: vpcAttachmentIdentifierBase62,
				MTU:           1300,
				Terminations:  terminations,
				IPAM: cni.IPAM{
					Type:      "static",
					Addresses: addresses,
					Routes:    routes,
				},
			},
		},
	}, nil
}
