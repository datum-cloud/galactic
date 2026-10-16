/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package galactic is the vocabulary this operator shares with the galactic
// data plane: the CNI conflist a NetworkAttachmentDefinition carries, the
// kernel interface names derived from a (vpc, attachment) pair, and the
// BGPAdvertisement annotations galactic publishes back.
package galactic

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.datum.net/galactic/internal/cloud/identifier"
)

const (
	// CNIVersion is the only conflist version galactic-bgp reconstructs a
	// prevResult from; "1.1.0" also works, anything older fails every ADD.
	CNIVersion = "1.0.0"

	// PluginVeth is the master plugin for container attachments.
	PluginVeth = "galactic-veth"

	// PluginTap is the master plugin for virtual machine guests.
	PluginTap = "galactic-tap"

	// PluginBGP publishes the attachment into BGP and SRv6.
	PluginBGP = "galactic-bgp"

	// PluginIPAM is the delegated IPAM binary.
	PluginIPAM = "galactic-ipam"

	// SystemNamespace holds the BGP CRDs the chain reads and writes.
	SystemNamespace = "galactic-system"
)

const (
	// AnnotationNetNS is the BGPAdvertisement annotation key prefix carrying a
	// container's netns path.
	AnnotationNetNS = "galactic.datum.net/netns"

	// AnnotationAllocatedSubnetIPv6 is the annotation key prefix carrying a
	// container's allocated IPv6 pod subnet.
	AnnotationAllocatedSubnetIPv6 = "galactic.datum.net/allocated-subnet-ipv6"

	// AnnotationAllocatedSubnetIPv4 is the annotation key prefix carrying a
	// container's allocated IPv4 pod address.
	AnnotationAllocatedSubnetIPv4 = "galactic.datum.net/allocated-subnet-ipv4"

	// AnnotationNoAddressing marks an advertisement whose guest manages its own
	// addressing, so an empty prefix list is intentional.
	AnnotationNoAddressing = "galactic.datum.net/no-addressing"

	// ConditionAdvertised is set on a BGPAdvertisement from live GoBGP state.
	ConditionAdvertised = "Advertised"
)

// NetConfList is a CNI conflist, the payload of a NAD's spec.config.
type NetConfList struct {
	CNIVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Plugins    []any  `json:"plugins"`
}

// MasterPlugin is the galactic-veth or galactic-tap stanza.
type MasterPlugin struct {
	Type          string `json:"type"`
	VPC           string `json:"vpc"`
	VPCAttachment string `json:"vpcattachment"`
	Namespace     string `json:"namespace"`
	MTU           int32  `json:"mtu,omitempty"`
	// DAN asks the tap plugin to describe the device to the hypervisor in a
	// file the hypervisor reads, rather than leaving it to be discovered from
	// the node. Only the tap plugin reads it, and it is omitted when false so
	// every conflist rendered until now is byte-identical.
	DAN  bool  `json:"dan,omitempty"`
	IPAM *IPAM `json:"ipam,omitempty"`
}

// BGPPlugin is the galactic-bgp stanza. It is never optional: the master plugin
// fetches its own NAD and fails ADD before creating kernel state without it.
type BGPPlugin struct {
	Type          string `json:"type"`
	VPC           string `json:"vpc"`
	VPCAttachment string `json:"vpcattachment"`
	Namespace     string `json:"namespace"`
}

// IPAM is the delegated IPAM block. Presence alone decides whether IPAM runs.
type IPAM struct {
	Type      string    `json:"type"`
	Addresses []Address `json:"addresses,omitempty"`
}

// Address is one pre-decided address, in CIDR notation, with the next hop the
// interface routes through for its family. Without the gateway the guest has an
// address but no route off its own link, and the host installs neither the tap
// gateway address nor the route to the attachment's prefix.
type Address struct {
	Address string `json:"address"`
	Gateway string `json:"gateway,omitempty"`
}

// Conflist renders the conflist for one attachment. Addresses are the addresses
// NSO already allocated; an empty list means the guest addresses itself and no
// IPAM block is emitted. Set dan for a guest whose hypervisor is handed the
// device rather than discovering it.
func Conflist(name, plugin, vpc, vpcAttachment string, mtu int32, addresses []Address, dan bool) NetConfList {
	master := MasterPlugin{
		Type:          plugin,
		VPC:           vpc,
		VPCAttachment: vpcAttachment,
		Namespace:     SystemNamespace,
		MTU:           mtu,
		DAN:           dan,
	}
	if len(addresses) > 0 {
		master.IPAM = &IPAM{Type: PluginIPAM, Addresses: addresses}
	}
	return NetConfList{
		CNIVersion: CNIVersion,
		Name:       name,
		Plugins: []any{
			master,
			BGPPlugin{Type: PluginBGP, VPC: vpc, VPCAttachment: vpcAttachment, Namespace: SystemNamespace},
		},
	}
}

// ConflistJSON renders the conflist as the string a NAD's spec.config holds.
func ConflistJSON(name, plugin, vpc, vpcAttachment string, mtu int32, addresses []Address, dan bool) (string, error) {
	raw, err := json.Marshal(Conflist(name, plugin, vpc, vpcAttachment, mtu, addresses, dan))
	if err != nil {
		return "", fmt.Errorf("marshal CNI conflist: %w", err)
	}
	return string(raw), nil
}

// HostInterfaceName returns the host-side veth or tap device name.
func HostInterfaceName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("G%09s%03sH", vpc, vpcAttachment)
}

// GuestInterfaceName returns the guest-side veth device name.
func GuestInterfaceName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("G%09s%03sG", vpc, vpcAttachment)
}

// VRFInterfaceName returns the VRF device name, which is per-VPC rather than
// per-attachment.
func VRFInterfaceName(vpc string) string {
	return fmt.Sprintf("G%09sV", vpc)
}

// AdvertisementName returns the hex-encoded identity prefix shared by every
// node-qualified BGPAdvertisement galactic derives from an attachment.
func AdvertisementName(vpc, vpcAttachment string) string {
	vpcHex, err := identifier.Base62ToHex(vpc)
	if err != nil {
		return ""
	}
	attachmentHex, err := identifier.Base62ToHex(vpcAttachment)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s-%s", vpcHex, attachmentHex)
}

// SplitAdvertisementName recovers the base62 (vpc, attachment) pair from a
// current node-qualified advertisement name.
func SplitAdvertisementName(name string) (vpc, vpcAttachment string, ok bool) {
	parts := strings.SplitN(name, "-", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	vpc, err := identifier.HexToBase62(parts[0])
	if err != nil || vpc == "" {
		return "", "", false
	}
	vpcAttachment, err = identifier.HexToBase62(parts[1])
	if err != nil || vpcAttachment == "" {
		return "", "", false
	}
	return vpc, vpcAttachment, true
}

// AllocatedSubnets returns every allocated subnet recorded on an advertisement,
// across both families and every container ID.
func AllocatedSubnets(annotations map[string]string) []string {
	var subnets []string
	for key, value := range annotations {
		if strings.HasPrefix(key, AnnotationAllocatedSubnetIPv6+".") ||
			strings.HasPrefix(key, AnnotationAllocatedSubnetIPv4+".") {
			subnets = append(subnets, value)
		}
	}
	return subnets
}
