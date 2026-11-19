// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package intf provides deterministic interface naming and base62↔hex ID
// encoding for Galactic VPC identifiers.
package intf

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kenshaw/baseconv"
)

// hostLinkNameRegex matches the host-side interface name produced by
// GenerateInterfaceNameHost, "G%09s%03sH": the zero-padded base62 VPC and
// VPCAttachment.
var hostLinkNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})([A-Za-z0-9]{3})H$`)

const interfaceNameTemplate = "G%09s%03s%s"

// vrfInterfaceNameTemplate has no attachment segment: the VRF is shared by every
// attachment landing on a VPC on a node, so it is keyed by VPC alone. The node
// never appears either, unlike the CRD-level identity, since kernel interface
// names only have to be unique within one host and each host creates its own.
const vrfInterfaceNameTemplate = "G%09s%s"

// GenerateInterfaceNameVRF returns the kernel interface name for a
// base62-encoded VPC's VRF. The VRF is per VPC per node, shared by every
// attachment on that VPC here, rather than per attachment.
func GenerateInterfaceNameVRF(vpc string) string {
	return fmt.Sprintf(vrfInterfaceNameTemplate, vpc, "V")
}

// GenerateInterfaceNameHost returns the kernel interface name for the host-side
// veth endpoint for the given base62-encoded VPC and VPCAttachment.
func GenerateInterfaceNameHost(vpc, vpcAttachment string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, vpcAttachment, "H")
}

// GenerateInterfaceNameGuest returns the kernel interface name for the
// guest-side veth end, the one moved into the container namespace, for a
// base62-encoded VPC and attachment.
func GenerateInterfaceNameGuest(vpc, vpcAttachment string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, vpcAttachment, "G")
}

// HexToBase62 converts a hex string to base62. Identifiers are hex in BGP
// artifacts and base62 in kernel interface names, to stay within the
// 15-character limit.
func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

// Base62ToHex converts a base62 string to lowercase hex.
func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}

// ParseInterfaceNameHost reports the unpadded VPC and attachment IDs encoded
// in a host-side link name produced by GenerateInterfaceNameHost.
func ParseInterfaceNameHost(name string) (vpc, vpcAttachment string, ok bool) {
	m := hostLinkNameRegex.FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return Unpad(m[1]), Unpad(m[2]), true
}

// Unpad reverses the zero padding an interface name applies to a base62
// identifier, which CRD names do not carry. All zeros, or an empty string,
// becomes "0".
func Unpad(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// The links Worker's Local module creates for a claim. Each name carries the
// VPC, a 3-character key derived from the claim's attachment and one of these
// role letters, which no CNI-created link uses.
const (
	// LocalRolePairNAT is the NAT end of a service-internal veth pair, in
	// the host's namespace.
	LocalRolePairNAT = "N"
	// LocalRolePairTenant is the tenant end of the pair, in the VPC's VRF.
	LocalRolePairTenant = "T"
	// LocalRoleRoutedHost is the host end of a pod-to-host routed link, in
	// the VPC's VRF.
	LocalRoleRoutedHost = "R"
	// LocalRoleRoutedPod is the routed link's end in the caller's pod.
	LocalRoleRoutedPod = "P"
)

// localLinkNameRegex matches every name GenerateInterfaceNameLocal produces.
var localLinkNameRegex = regexp.MustCompile(`^G[A-Za-z0-9]{9}[A-Za-z0-9]{3}[NTRP]$`)

// cniLinkNameRegex matches CNI's host and guest link names and the VPC VRF.
var cniLinkNameRegex = regexp.MustCompile(`^G[A-Za-z0-9]{9}([A-Za-z0-9]{3}[HG]|V)$`)

// GenerateInterfaceNameLocal returns the name of a Local link: the VPC's
// base62 ID, key (3 base62 characters) and role, one of the LocalRole*
// letters.
func GenerateInterfaceNameLocal(vpc, key, role string) string {
	return fmt.Sprintf(interfaceNameTemplate, vpc, key, role)
}

// IsLocalLinkName reports whether name is a link Worker's Local module
// creates.
func IsLocalLinkName(name string) bool { return localLinkNameRegex.MatchString(name) }

// IsGalacticLinkName reports whether name is any link Galactic creates per
// VPC: a CNI attachment's host or guest end, a VPC's VRF, or a Local link.
// None of them is ever a node's uplink.
func IsGalacticLinkName(name string) bool {
	return cniLinkNameRegex.MatchString(name) || localLinkNameRegex.MatchString(name)
}
