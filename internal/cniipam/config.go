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

	if len(conf.IPAM.Addresses) > 0 {
		if err := validateAddressesMode(conf.IPAM); err != nil {
			return nil, err
		}
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
	if len(conf.IPAM.Addresses) == 0 && conf.IPAM.StaticIP == "" &&
		conf.IPAM.IPv6Subnet == "" && conf.IPAM.IPv4Subnet == "" {
		if config.IPAMGetEnableLocalIPAM() {
			conf.IPAM.IPv6Subnet = localIPAMDefaultPool
		}
	}

	// Unset means "no restriction" — allocate from whatever pool(s) are
	// configured, exactly like before this field had any effect at all.
	// Defaulting an unset field to ["ipv6"] here would silently turn every
	// existing dual-stack or IPv4-only config that has never set this field
	// into IPv6-only once the filter below is applied.
	if len(conf.IPAM.AddressFamilies) > 0 {
		var wantIPv6, wantIPv4 bool
		for _, af := range conf.IPAM.AddressFamilies {
			switch af {
			case addressFamilyIPv6:
				wantIPv6 = true
			case addressFamilyIPv4:
				wantIPv4 = true
			default:
				return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
					"invalid ipam.address_families entry %q: must be %q or %q",
					sanitizeForError(af), addressFamilyIPv6, addressFamilyIPv4),
				}
			}
		}

		// Meaningless for the paths that carry addresses they were given
		// rather than allocating: both are selected on their own field's
		// presence, regardless of what else is configured.
		if conf.IPAM.StaticIP == "" && len(conf.IPAM.Addresses) == 0 {
			if !wantIPv6 {
				conf.IPAM.IPv6Subnet = ""
			}
			if !wantIPv4 {
				conf.IPAM.IPv4Subnet = ""
			}
			if conf.IPAM.IPv6Subnet == "" && conf.IPAM.IPv4Subnet == "" {
				return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
					"ipam.address_families %v excludes every pool this config configures "+
						"(ipam.ipv6_subnet/ipam.ipv4_subnet)", conf.IPAM.AddressFamilies),
				}
			}
		}
	}

	return conf, nil
}

// parsedAddresses is the addresses path's config, validated and parsed:
// at most one address per family, each keeping the exact prefix length it
// was given.
type parsedAddresses struct {
	ipv6        *net.IPNet
	ipv6Gateway net.IP
	ipv4        net.IP
	ipv4Gateway net.IP
}

// validateAddressesMode rejects a config that pairs addresses with another
// mode's fields, so mode selection never has to guess.
func validateAddressesMode(conf *IPAM) error {
	for field, set := range map[string]bool{
		"static_ip":   conf.StaticIP != "",
		"ipv6_subnet": conf.IPv6Subnet != "",
		"ipv4_subnet": conf.IPv4Subnet != "",
	} {
		if set {
			return &types.Error{Code: 7, Msg: fmt.Sprintf(
				"ipam.addresses cannot be combined with ipam.%s: addresses assigns "+
					"pre-decided addresses, the other fields allocate", field),
			}
		}
	}
	_, err := parseAddresses(conf.Addresses)
	return err
}

// parseAddresses validates and parses the addresses block. Every address
// must carry an explicit prefix length, which is preserved exactly: an
// endpoint block decided upstream as a /96 stays a /96.
func parseAddresses(addresses []Address) (*parsedAddresses, error) {
	parsed := &parsedAddresses{}
	for _, addr := range addresses {
		ip, cidr, err := net.ParseCIDR(addr.Address)
		if err != nil {
			return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
				"invalid CIDR value for field 'ipam.addresses[].address': %q "+
					"(an explicit prefix length is required)", sanitizeForError(addr.Address)),
			}
		}
		gateway, err := parseAddressGateway(addr, ip)
		if err != nil {
			return nil, err
		}

		prefixLen, _ := cidr.Mask.Size()
		if ip.To4() != nil {
			if parsed.ipv4 != nil {
				return nil, &types.Error{Code: 7, Msg: "ipam.addresses carries more than one IPv4 address"}
			}
			if prefixLen != maxIPv4SubnetPrefixLen {
				return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
					"ipam.addresses IPv4 entry %q must be a /%d: the data plane models an IPv4 "+
						"endpoint as a host route", sanitizeForError(addr.Address), maxIPv4SubnetPrefixLen),
				}
			}
			parsed.ipv4 = ip
			parsed.ipv4Gateway = gateway
			continue
		}

		if parsed.ipv6 != nil {
			return nil, &types.Error{Code: 7, Msg: "ipam.addresses carries more than one IPv6 address"}
		}
		parsed.ipv6 = &net.IPNet{IP: ip.To16(), Mask: cidr.Mask}
		parsed.ipv6Gateway = gateway
	}

	if parsed.ipv6 == nil && parsed.ipv4 == nil {
		return nil, &types.Error{Code: 7, Msg: "ipam.addresses is present but empty"}
	}
	return parsed, nil
}

// parseAddressGateway validates an entry's gateway against its own address:
// a gateway of the other family is a config error, not a silent drop.
func parseAddressGateway(addr Address, ip net.IP) (net.IP, error) {
	if addr.Gateway == "" {
		return nil, nil
	}
	gateway := net.ParseIP(addr.Gateway)
	if gateway == nil {
		return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
			"invalid IP for field 'ipam.addresses[].gateway': %q", sanitizeForError(addr.Gateway)),
		}
	}
	if (gateway.To4() != nil) != (ip.To4() != nil) {
		return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
			"ipam.addresses gateway %q is not the same address family as %q",
			sanitizeForError(addr.Gateway), sanitizeForError(addr.Address)),
		}
	}
	if gateway.To4() != nil {
		return gateway.To4(), nil
	}
	return gateway.To16(), nil
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
