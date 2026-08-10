// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package intf provides deterministic interface naming and base62↔hex ID
// encoding for Galactic VPC identifiers.
package intf

import (
	"fmt"
	"strings"

	"github.com/kenshaw/baseconv"
)

const interfaceNameTemplate = "G%09s%03s%s"

// vrfInterfaceNameTemplate has no VPCAttachment segment: the VRF is shared
// by every attachment (pod or VM) landing on a given VPC on a given node, so
// it is keyed by VPC alone. Unlike the CRD-level VRF identity (see
// crdnames.BGPVRFInstanceName), the node itself never needs to appear in the
// name — kernel interface names only have to be unique within one host's own
// namespace, and each host only ever creates VRF interfaces for itself.
const vrfInterfaceNameTemplate = "G%09s%s"

// GenerateInterfaceNameVRF returns the kernel interface name for the VRF
// associated with the given base62-encoded VPC. The VRF is per-VPC-per-node,
// shared by every attachment on that VPC on this node — not per-attachment.
func GenerateInterfaceNameVRF(vpc string) string {
	return fmt.Sprintf(vrfInterfaceNameTemplate, vpc, "V")
}

// GenerateInterfaceNameHost returns the kernel interface name for the host-side
// veth endpoint for the given base62-encoded VPC and VPCAttachment.
func GenerateInterfaceNameHost(vpc, vpcAttachment string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, vpcAttachment, "H")
}

// GenerateInterfaceNameGuest returns the kernel interface name for the
// guest-side veth endpoint (moved into the container netns) for the given
// base62-encoded VPC and VPCAttachment.
func GenerateInterfaceNameGuest(vpc, vpcAttachment string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, vpcAttachment, "G")
}

// HexToBase62 converts a hex string to base62. VPC and VPCAttachment
// identifiers are hex in BGP artifacts but base62 in kernel interface names to
// stay within the 15-character limit.
func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

// Base62ToHex converts a base62 string to lowercase hex.
func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}
