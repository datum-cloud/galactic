// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

const sanitizeForErrorBinary = "<binary>"

// srv6LocatorErrMsg is the error message prefix for invalid SRv6 locator values.
const srv6LocatorErrMsg = "invalid srv6_locator"

// isValidBase62 reports whether s contains only valid base62 characters
// ([0-9a-zA-Z]) and is non-empty. VPC and VPCAttachment identifiers are
// base62-encoded and used throughout the ADD path (interface naming,
// SRv6 SID encoding). Rejecting them early in parseConf prevents cryptic
// errors deep in the stack after partial kernel state has been created.
func isValidBase62(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// isValidSRv6Locator reports whether s is a valid IPv6 CIDR prefix suitable
// for SRv6 SID encoding. The locator must be non-empty, parseable as an IPv6
// prefix with a mask length of 64 or less (leaving at least 64 bits of
// address space for embedding VPC/VPCAttachment identifiers).
func isValidSRv6Locator(s string) bool {
	if s == "" {
		return true // empty locator is valid — setupSRv6Ingress is a no-op
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	if ipnet.IP.To4() != nil {
		return false // must be IPv6
	}
	maskLen, _ := ipnet.Mask.Size()
	return maskLen <= 64
}

// parseConf unmarshals the CNI configuration from stdin data and validates
// the interface type and base62-encoded identifier fields. Returns an error
// if the config is malformed, interface_type is unsupported, or VPC/
// VPCAttachment contain invalid characters.
func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse CNI config: %w", err)
	}
	if !isValidBase62(conf.VPC) {
		// Use "empty" instead of "invalid" for a zero-length value so the
		// error message is actionable for the most common mistake (missing
		// field entirely).
		if len(conf.VPC) == 0 {
			return nil, errors.New("vpc is required and must be a non-empty base62 string")
		}
		return nil, fmt.Errorf("invalid base62 value for field 'vpc': %q", sanitizeForError(conf.VPC))
	}
	if !isValidBase62(conf.VPCAttachment) {
		if len(conf.VPCAttachment) == 0 {
			return nil, errors.New("vpcattachment is required and must be a non-empty base62 string")
		}
		return nil, fmt.Errorf("invalid base62 value for field 'vpcattachment': %q", sanitizeForError(conf.VPCAttachment))
	}
	if !isValidSRv6Locator(conf.SRv6Locator) {
		return nil, fmt.Errorf(
			"%s %q: must be a valid "+
				"IPv6 CIDR prefix with mask length <= 64",
			srv6LocatorErrMsg, sanitizeForError(conf.SRv6Locator),
		)
	}
	if conf.InterfaceType == "" {
		conf.InterfaceType = interfaceTypeVeth
	}
	switch conf.InterfaceType {
	case interfaceTypeVeth, interfaceTypeTap:
	default:
		return nil, fmt.Errorf(
			"invalid interface_type %q: must be %q or %q",
			conf.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
		)
	}
	return conf, nil
}

// sanitizeForError returns s unchanged if it contains only printable ASCII
// characters; otherwise returns "<binary>" to avoid corrupting log output.
func sanitizeForError(s string) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return sanitizeForErrorBinary
		}
	}
	return s
}

// subnetAnnotationKey returns the annotation key for storing the allocated
// subnet for the given container ID. Kubernetes limits the name part of an
// annotation key to 63 bytes; "allocated-subnet." is 17 bytes, leaving 46
// bytes for the container ID prefix.
func subnetAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationAllocatedSubnet, id)
}
