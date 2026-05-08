// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package util

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/kenshaw/baseconv"
)

// InterfaceNameTemplate generates kernel interface names. VPC base62
// width is 6 chars (32-bit id, ⌈32/log2(62)⌉); attachment base62 width
// is 3 chars (16-bit id). Total length: 1 + 6 + 3 + 1 = 11 chars, well
// within the 15-char Linux interface name limit.
const InterfaceNameTemplate = "G%06s%03s%s"

func GenerateInterfaceNameVRF(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "V")
}

func GenerateInterfaceNameHost(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "H")
}

func GenerateInterfaceNameGuest(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "G")
}

func ParseIP(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("cannot parse IP: %v", ip)
	}
	return parsed, nil
}

func ParseSegments(input []string) ([]net.IP, error) {
	var segments []net.IP
	for _, ipStr := range input {
		ip, err := ParseIP(ipStr)
		if err != nil {
			return nil, fmt.Errorf("could not parse ip (%s): %v", ipStr, err)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("not an ipv6 address: %s", ipStr)
		}
		segments = append([]net.IP{ip}, segments...)
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("no segments parsed: %v", input)
	}
	return segments, nil
}

func IsHost(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	// host if mask is full length: /32 for IPv4, /128 for IPv6
	return ones == bits
}

// DecodeSRv6Endpoint extracts the (vpc, attachment) pair from an SRv6
// service SID. The SID layout in the lower 64 bits is
// <vpc-32>:<attach-16>:<zero-16>, so VPC is bits 32..64 and attachment
// is bits 16..32 (zero-indexed from LSB).
func DecodeSRv6Endpoint(endpoint net.IP) (string, string, error) {
	if endpoint.To4() != nil {
		return "", "", fmt.Errorf("provided endpoint is not an IPv6 address: %s", endpoint)
	}

	endpointNum := new(big.Int).SetBytes(endpoint)
	vpcNum := new(big.Int).And(
		new(big.Int).Rsh(endpointNum, 32), // drop the attachment + zero-pad bits
		big.NewInt(0xFFFFFFFF),            // mask the 32-bit vpc
	)
	vpcAttachmentNum := new(big.Int).And(
		new(big.Int).Rsh(endpointNum, 16), // drop the zero-pad bits
		big.NewInt(0xFFFF),
	)

	return fmt.Sprintf("%08x", vpcNum), fmt.Sprintf("%04x", vpcAttachmentNum), nil
}

// EncodeSRv6Endpoint constructs an SRv6 service SID from the locator
// prefix, a 32-bit VPC id (8-char hex), and a 16-bit attachment id
// (4-char hex). The SID layout in the lower 64 bits is
// <vpc-32>:<attach-16>:<zero-16>. The 16-bit zero pad makes the SID
// /112-aligned for END.DT* behavior matching, and leaves room for a
// future per-attachment "function variant" byte without re-laying-out.
func EncodeSRv6Endpoint(srv6_net, vpc, vpcAttachment string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(srv6_net)
	if err != nil {
		return "", err
	}
	if ip.To4() != nil {
		return "", fmt.Errorf("provided srv6_net is not IPv6: %s", srv6_net)
	}
	mask_len, _ := ipnet.Mask.Size()
	if mask_len > 64 {
		return "", fmt.Errorf("srv6_net must be at least 64 bits long")
	}

	vpcInt, err := strconv.ParseUint(vpc, 16, 32)
	if err != nil {
		return "", fmt.Errorf("invalid vpc %q: %w", vpc, err)
	}
	vpcAttachmentInt, err := strconv.ParseUint(vpcAttachment, 16, 16)
	if err != nil {
		return "", fmt.Errorf("invalid vpcAttachment %q: %w", vpcAttachment, err)
	}

	binary.BigEndian.PutUint64(ip[8:16], (vpcInt<<32)|(vpcAttachmentInt<<16))
	return ip.String(), nil
}

func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}
