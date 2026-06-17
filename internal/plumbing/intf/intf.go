// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package intf provides deterministic interface naming, base62↔hex ID
// encoding, and SRv6 endpoint encode/decode for Galactic VPC identifiers.
package intf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/kenshaw/baseconv"
)

const interfaceNameTemplate = "G%09s%03s%s"

// GenerateInterfaceNameVRF returns the kernel interface name for the VRF
// associated with the given base62-encoded VPC and VPCAttachment.
func GenerateInterfaceNameVRF(vpc, vpcAttachment string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, vpcAttachment, "V")
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
// identifiers are hex in SRv6 SIDs but base62 in kernel interface names to
// stay within the 15-character limit.
func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

// Base62ToHex converts a base62 string to lowercase hex.
func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}

// EncodeSRv6Endpoint packs hex VPC (48-bit) and VPCAttachment (16-bit)
// identifiers into the low 64 bits of an IPv6 address within srv6Net.
// srv6Net must be an IPv6 prefix of /64 or shorter.
func EncodeSRv6Endpoint(srv6Net, vpc, vpcAttachment string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(srv6Net)
	if err != nil {
		return "", err
	}
	if ip.To4() != nil {
		return "", fmt.Errorf("provided srv6Net is not IPv6: %s", srv6Net)
	}
	maskLen, _ := ipnet.Mask.Size()
	if maskLen > 64 {
		return "", fmt.Errorf("srv6Net must be at least 64 bits long")
	}

	vpcInt, err := strconv.ParseUint(vpc, 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid vpc %q: %w", vpc, err)
	}
	vpcAttachmentInt, err := strconv.ParseUint(vpcAttachment, 16, 16)
	if err != nil {
		return "", fmt.Errorf("invalid vpcAttachment %q: %w", vpcAttachment, err)
	}

	binary.BigEndian.PutUint64(ip[8:16], (vpcInt<<16)|vpcAttachmentInt)
	return ip.String(), nil
}

// DecodeSRv6Endpoint extracts the 12-digit hex VPC and 4-digit hex
// VPCAttachment identifiers from the low 64 bits of an SRv6 SID produced by
// EncodeSRv6Endpoint. endpoint must be an IPv6 address.
func DecodeSRv6Endpoint(endpoint net.IP) (string, string, error) {
	ep := endpoint.To16()
	if ep == nil || endpoint.To4() != nil {
		return "", "", fmt.Errorf("provided endpoint is not an IPv6 address: %s", endpoint)
	}

	id := binary.BigEndian.Uint64(ep[8:16])
	vpc := (id >> 16) & 0xFFFFFFFFFFFF
	vpcAttachment := id & 0xFFFF
	return fmt.Sprintf("%012x", vpc), fmt.Sprintf("%04x", vpcAttachment), nil
}
