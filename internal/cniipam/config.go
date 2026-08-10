// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/config"
)

const errInvalidCNIConfig = "invalid CNI config"

const (
	// maxIPv6SubnetPrefixLen mirrors internal/cni's own constraint: pool
	// prefix must be no longer than the per-allocation subnet length, and
	// dual-stack tenant addressing allocates /96 endpoints.
	maxIPv6SubnetPrefixLen = 96
	maxIPv4SubnetPrefixLen = 32
)

const (
	addressFamilyIPv6 = "ipv6"
	addressFamilyIPv4 = "ipv4"
)

// sanitizeForErrorBinary is substituted for a config value that fails
// sanitizeForError's printable-ASCII check.
const sanitizeForErrorBinary = "<binary>"

// parseConf unmarshals the full CNI config document (the same one the
// master plugin itself received) and validates/normalizes the "ipam"
// block. Returns a *types.Error (CNI error code 7) for anything a real IPAM
// invocation should never see, since a master plugin only ever delegates
// here when its own "ipam" block is present.
func parseConf(data []byte) (*pluginConf, error) {
	conf := &pluginConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, &types.Error{Code: 7, Msg: errInvalidCNIConfig, Details: err.Error()}
	}
	if conf.IPAM == nil {
		return nil, &types.Error{Code: 7, Msg: "ipam block is required"}
	}

	if conf.IPAM.IPv6Subnet != "" {
		if err := validateIPv6Subnet(conf.IPAM.IPv6Subnet); err != nil {
			return nil, err
		}
	}
	if conf.IPAM.IPv4Subnet != "" {
		if err := validateIPv4Subnet(conf.IPAM.IPv4Subnet); err != nil {
			return nil, err
		}
	}

	// Default-filler: only when the ipam block is present but specifies
	// neither a static address nor a pool CIDR for either family. Cannot
	// manufacture an ipam block out of thin air — that decision already
	// happened in the master plugin, before this process was even execed.
	if conf.IPAM.StaticIP == "" && conf.IPAM.IPv6Subnet == "" && conf.IPAM.IPv4Subnet == "" {
		if config.IPAMGetEnableLocalIPAM() {
			conf.IPAM.IPv6Subnet = localIPAMDefaultPool
		}
	}

	if len(conf.IPAM.AddressFamilies) == 0 {
		conf.IPAM.AddressFamilies = []string{addressFamilyIPv6}
	} else {
		for _, af := range conf.IPAM.AddressFamilies {
			switch af {
			case addressFamilyIPv6, addressFamilyIPv4:
			default:
				return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
					"invalid ipam.address_families entry %q: must be %q or %q",
					sanitizeForError(af), addressFamilyIPv6, addressFamilyIPv4),
				}
			}
		}
	}

	return conf, nil
}

func validateIPv6Subnet(subnet string) error {
	ip, mask, err := net.ParseCIDR(subnet)
	if err != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"invalid CIDR value for field 'ipam.ipv6_subnet': %q", sanitizeForError(subnet)),
		}
	}
	if ip.To4() != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"ipam.ipv6_subnet must be an IPv6 CIDR, got IPv4: %q", sanitizeForError(subnet)),
		}
	}
	if prefixLen, _ := mask.Mask.Size(); prefixLen > maxIPv6SubnetPrefixLen {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"ipam.ipv6_subnet prefix length %d exceeds maximum of %d: %q",
			prefixLen, maxIPv6SubnetPrefixLen, sanitizeForError(subnet)),
		}
	}
	return nil
}

func validateIPv4Subnet(subnet string) error {
	ip, mask, err := net.ParseCIDR(subnet)
	if err != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"invalid CIDR value for field 'ipam.ipv4_subnet': %q", sanitizeForError(subnet)),
		}
	}
	if ip.To4() == nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"ipam.ipv4_subnet must be an IPv4 CIDR, got IPv6: %q", sanitizeForError(subnet)),
		}
	}
	if prefixLen, _ := mask.Mask.Size(); prefixLen > maxIPv4SubnetPrefixLen {
		return &types.Error{Code: 7, Msg: fmt.Sprintf(
			"ipam.ipv4_subnet prefix length %d exceeds maximum of %d: %q",
			prefixLen, maxIPv4SubnetPrefixLen, sanitizeForError(subnet)),
		}
	}
	return nil
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

// parseStatusConf validates that STATUS's config is minimally parseable.
// galactic-ipam has no attachment-specific or API-server state to check —
// STATUS just confirms the binary can parse a well-formed CNI config.
func parseStatusConf(data []byte) error {
	var sc struct {
		CNIVersion string `json:"cniVersion"`
	}
	if err := json.Unmarshal(data, &sc); err != nil {
		return &types.Error{Code: 7, Msg: errInvalidCNIConfig, Details: err.Error()}
	}
	if sc.CNIVersion == "" {
		return &types.Error{Code: 7, Msg: "cniVersion is required"}
	}
	return nil
}
