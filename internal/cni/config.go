// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
)

const sanitizeForErrorBinary = "<binary>"

// srv6SIDErrMsg is the error message prefix for invalid SRv6 SID values.
const srv6SIDErrMsg = "invalid srv6_sid"

// isValidBase62 reports whether s contains only valid base62 characters
// ([0-9a-zA-Z]) and is non-empty. VPC and VPCAttachment identifiers are
// base62-encoded and used throughout the ADD path (interface naming,
// BGP CRD population). Rejecting them early in parseConf prevents cryptic
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

// isValidSRv6SID reports whether s is a valid USID — a /128 IPv6 address
// suitable for use as an SRv6 endpoint identifier. The SID may be empty
// (SRv6 ingress setup is skipped) or provided as a bare IPv6 address or
// a /128 CIDR.
func isValidSRv6SID(s string) bool {
	if s == "" {
		return true
	}
	// Accept both "addr" and "addr/128" forms.
	addr := s
	if idx := stringsIndex(s, "/"); idx >= 0 {
		prefix := s[idx+1:]
		if prefix != "128" {
			return false
		}
		addr = s[:idx]
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return false
	}
	return true
}

// stringsIndex is a minimal strings.Index to avoid importing "strings"
// alongside "encoding/json" in this file.
func stringsIndex(s, substr string) int {
	n := len(s) - len(substr)
	if n < 0 {
		return -1
	}
	for i := 0; i <= n; i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// statusConf holds the minimal CNI config fields needed for STATUS validation.
// STATUS only checks that the config is parseable and the API server is reachable;
// it does not validate attachment-specific fields (VPC, VPCAttachment) because
// STATUS must succeed before any ADD has ever run.
type statusConf struct {
	CNIVersion    string `json:"cniVersion"`
	Type          string `json:"type"`
	InterfaceType string `json:"interface_type"`
}

// parseStatusConf validates that the CNI config is parseable and contains the
// required top-level fields (cniVersion, type). Unlike parseConf, it does not
// validate VPC or VPCAttachment because STATUS must succeed on a freshly
// started node before any ADD has run. However, interface_type is validated
// if present because it is a structural config field, not an attachment
// identifier.
func parseStatusConf(data []byte) error {
	var sc statusConf
	if err := json.Unmarshal(data, &sc); err != nil {
		return fmt.Errorf("parse CNI config: %w", err)
	}
	if sc.CNIVersion == "" {
		return errors.New("cniVersion is required")
	}
	if sc.Type == "" {
		return errors.New("type is required")
	}
	// Validate interface_type if present.
	if sc.InterfaceType != "" {
		switch sc.InterfaceType {
		case interfaceTypeVeth, interfaceTypeTap:
		default:
			return fmt.Errorf(
				"invalid interface_type %q: must be %q or %q",
				sc.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
			)
		}
	}
	return nil
}

// validatePrevResult checks that the prevResult (from a preceding plugin in
// the CNI chain) is a valid, parseable CNI result. Returns an error if the
// result is non-nil but cannot be parsed as a versioned CNI result, ensuring
// galactic-cni fails fast rather than silently operating on garbage state.
func validatePrevResult(res types.Result) error {
	if res == nil {
		return nil
	}
	// Marshal to JSON and re-parse to verify the result is structurally valid.
	// This catches malformed results that survived CNI framework unmarshaling.
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	if _, err := type100.NewResult(jsonBytes); err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	return nil
}

// validatePrevResultAdd performs content-level validation of prevResult during
// the ADD operation. It ensures the preceding plugin produced a result with at
// least one interface or IP assignment, which is the minimum expected structure
// for any meaningful CNI chain. Returns nil when prevResult is nil (no
// preceding plugin) or structurally valid with expected content.
func validatePrevResultAdd(res types.Result) error {
	if res == nil {
		return nil
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	result, err := type100.NewResult(jsonBytes)
	if err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	versioned, err := type100.GetResult(result)
	if err != nil {
		return fmt.Errorf("get prevResult version: %w", err)
	}
	// A valid prevResult must declare at least one interface or IP assignment.
	if len(versioned.Interfaces) == 0 && len(versioned.IPs) == 0 {
		return errors.New("prevResult declares no interfaces or IP assignments")
	}
	return nil
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
	if !isValidSRv6SID(conf.SRv6SID) {
		return nil, fmt.Errorf(
			"%s %q: must be a valid IPv6 address or /128 CIDR",
			srv6SIDErrMsg, sanitizeForError(conf.SRv6SID),
		)
	}
	if conf.PrevResult != nil {
		if err := validatePrevResult(conf.PrevResult); err != nil {
			return nil, fmt.Errorf("invalid prevResult: %w", err)
		}
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

// netnsAnnotationKey returns the annotation key for storing the network
// namespace path used by the given container ID. Mirrors subnetAnnotationKey.
func netnsAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationNetNS, id)
}
