// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config is the provider's configuration file: the provider it runs
// as and the EdgeServices it attaches to. A provider cannot read an
// EdgeService, which lives in the VPC's namespace, so the deployer copies
// each service's UID and its VPC's UID from the grant into this file.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"

	"sigs.k8s.io/yaml"
)

// Capability names and the version of each this provider implements.
const (
	SocketAccess      = "SocketAccess"
	PacketAccess      = "PacketAccess"
	CapabilityVersion = "v1"
	ContractVersion   = "v1alpha1"
)

// Config is the provider's configuration.
type Config struct {
	// Provider is the EdgeProvider this process runs as.
	Provider string `json:"provider"`
	// Port is the UDP port the SocketAccess echo listens on.
	Port uint16 `json:"port"`
	// Services are the grants to attach to.
	Services []Service `json:"services"`
}

// Service is one EdgeService to attach to.
type Service struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	// VPCUID is the metadata.uid of the VPC the service grants.
	VPCUID string `json:"vpcUID"`
	// Capabilities are SocketAccess, PacketAccess or both.
	Capabilities []string `json:"capabilities"`
	// Prefixes are the IPv6 prefixes to claim. They need PacketAccess.
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
	// ContractVersion overrides the contract version the attachment is
	// written to. It exists to exercise refusal of an unsupported version.
	ContractVersion string `json:"contractVersion,omitempty"`
	// CapabilityVersion overrides the version of every capability the
	// attachment requests, for the same purpose.
	CapabilityVersion string `json:"capabilityVersion,omitempty"`
}

// Has reports whether s requests capability.
func (s Service) Has(capability string) bool {
	for _, c := range s.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// Load reads and validates the file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses and validates a configuration.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if c.Port == 0 {
		c.Port = 7777
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Provider == "" {
		return errors.New("provider is required")
	}
	if len(c.Services) == 0 {
		return errors.New("at least one service is required")
	}
	seen := map[string]bool{}
	for i, s := range c.Services {
		if s.Namespace == "" || s.Name == "" || s.UID == "" || s.VPCUID == "" {
			return fmt.Errorf("services[%d]: namespace, name, uid and vpcUID are required", i)
		}
		if seen[s.UID] {
			return fmt.Errorf("services[%d]: service %s is listed twice", i, s.UID)
		}
		seen[s.UID] = true
		if len(s.Capabilities) == 0 {
			return fmt.Errorf("services[%d]: at least one capability is required", i)
		}
		for _, cap := range s.Capabilities {
			if cap != SocketAccess && cap != PacketAccess {
				return fmt.Errorf("services[%d]: capability %q is not SocketAccess or PacketAccess", i, cap)
			}
		}
		if len(s.Prefixes) > 0 && !s.Has(PacketAccess) {
			return fmt.Errorf("services[%d]: prefixes need PacketAccess", i)
		}
		for _, p := range s.Prefixes {
			if !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() || p.Bits() == 0 {
				return fmt.Errorf("services[%d]: prefix %s must be a masked, non-default IPv6 prefix", i, p)
			}
		}
	}
	return nil
}
