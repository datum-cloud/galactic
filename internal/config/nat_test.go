// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

const (
	testNAT66NodeName = "test-nat66-node"
	testNAT66Iface    = "eth1"
	testNATShardSID   = "fc00:1:2::1"
	testNATShardPub4  = "192.0.2.10"
	testNAT64Prefix   = "2001:db8:64::/96"
	testNATShardPub   = "2001:db8:9999::1"
)

func TestNATConfigDefaults(t *testing.T) {
	cfg := NewNATConfig()

	if cfg.MetricsPort != DefaultNATMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultNATMetricsPort)
	}
	if cfg.GRPCHealthPort != DefaultNATGRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, DefaultNATGRPCHealthPort)
	}
	if cfg.NodeName != "" {
		t.Errorf("NodeName = %q, want empty", cfg.NodeName)
	}
	if cfg.UplinkInterface != "" {
		t.Errorf("UplinkInterface = %q, want empty", cfg.UplinkInterface)
	}
	if cfg.ShardSID != "" {
		t.Errorf("ShardSID = %q, want empty", cfg.ShardSID)
	}
	if cfg.ShardPubAddr != "" {
		t.Errorf("ShardPubAddr = %q, want empty", cfg.ShardPubAddr)
	}
}

func TestNATConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvNATNodeName, testEnvNode)
	t.Setenv(EnvNATMetricsPort, "9090")
	t.Setenv(EnvNATGRPCHealthPort, "9091")
	t.Setenv(EnvNATUplinkInterface, testNAT66Iface)
	t.Setenv(EnvNATShardSID, testNATShardSID)
	t.Setenv(EnvNATShardPubAddr, testNATShardPub)

	cfg := NewNATConfig()

	if cfg.NodeName != testEnvNode {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, testEnvNode)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
	if cfg.GRPCHealthPort != 9091 {
		t.Errorf("GRPCHealthPort = %d, want 9091", cfg.GRPCHealthPort)
	}
	if cfg.UplinkInterface != testNAT66Iface {
		t.Errorf("UplinkInterface = %q, want %q", cfg.UplinkInterface, testNAT66Iface)
	}
	if cfg.ShardSID != testNATShardSID {
		t.Errorf("ShardSID = %q, want %q", cfg.ShardSID, testNATShardSID)
	}
	if cfg.ShardPubAddr != testNATShardPub {
		t.Errorf("ShardPubAddr = %q, want %q", cfg.ShardPubAddr, testNATShardPub)
	}
}

func TestNATConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name: testCaseMissingNodeName,
			envVars: map[string]string{
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
			},
			wantErr: testErrNodeNameRequired,
		},
		{
			name: "missing uplink interface",
			envVars: map[string]string{
				EnvNATNodeName:     testNAT66NodeName,
				EnvNATShardSID:     testNATShardSID,
				EnvNATShardPubAddr: testNATShardPub,
			},
			wantErr: "uplink interface is required",
		},
		{
			name: "missing shard SID",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardPubAddr:    testNATShardPub,
			},
			wantErr: "shard SID is required",
		},
		{
			name: "unparseable shard SID",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        "not-an-ip-address",
				EnvNATShardPubAddr:    testNATShardPub,
			},
			wantErr: "is not a valid IP address",
		},
		{
			name: "ipv4 shard SID is wrong family",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testIPv4Addr,
				EnvNATShardPubAddr:    testNATShardPub,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			// No longer "the IPv6 address is required" -- a shard may serve
			// NAT64 alone. What is still required is that it serve something.
			name: "serving neither address family",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
			},
			wantErr: "must serve at least one address family",
		},
		{
			name: "NAT64 prefix without a public IPv4 address",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
				EnvNAT64Prefix:        testNAT64Prefix,
			},
			wantErr: "shard public IPv4 address is not",
		},
		{
			name: "public IPv4 address without a NAT64 prefix",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
				EnvNATShardPubAddr4:   testNATShardPub4,
			},
			wantErr: "NAT64 prefix is not",
		},
		{
			name: "ipv6 shard public IPv4 address is wrong family",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr4:   testNATShardPub,
				EnvNAT64Prefix:        testNAT64Prefix,
			},
			wantErr: "must be an IPv4 address",
		},
		{
			// The datapath extracts the embedded IPv4 address from one aligned
			// four-byte run, which only a /96 guarantees.
			name: "NAT64 prefix of the wrong length",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr4:   testNATShardPub4,
				EnvNAT64Prefix:        "2001:db8:64::/64",
			},
			wantErr: "must be a /96",
		},
		{
			name: "NAT64 prefix with bits below its length",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr4:   testNATShardPub4,
				EnvNAT64Prefix:        "2001:db8:64::1/96",
			},
			wantErr: "bits set below its prefix length",
		},
		{
			name: "ipv4 shard public address is wrong family",
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testIPv4Addr,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
				EnvNATMetricsPort:     "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
				EnvNATGRPCHealthPort:  "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			name: testCaseValidConfig,
			envVars: map[string]string{
				EnvNATNodeName:        testNAT66NodeName,
				EnvNATUplinkInterface: testNAT66Iface,
				EnvNATShardSID:        testNATShardSID,
				EnvNATShardPubAddr:    testNATShardPub,
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			cfg := NewNATConfig()
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Errorf("Validate() = nil, want error containing %q", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestNATConfigValidateAcceptsEachFamilyCombination pins the three shard shapes
// the generalization is for: NAT66 alone (what every shard was before this),
// NAT64 alone, and both at once. The negative table above proves half a NAT64
// configuration is rejected; this proves a whole one is not.
func TestNATConfigValidateAcceptsEachFamilyCombination(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantNAT66   bool
		wantNAT64   bool
		description string
	}{
		{
			name: "NAT66 only",
			envVars: map[string]string{
				EnvNATShardPubAddr: testNATShardPub,
			},
			wantNAT66:   true,
			description: "the shape every shard had before NAT64 existed",
		},
		{
			name: "NAT64 only",
			envVars: map[string]string{
				EnvNATShardPubAddr4: testNATShardPub4,
				EnvNAT64Prefix:      testNAT64Prefix,
			},
			wantNAT64:   true,
			description: "a shard dedicated to IPv4 reachability",
		},
		{
			name: "both families",
			envVars: map[string]string{
				EnvNATShardPubAddr:  testNATShardPub,
				EnvNATShardPubAddr4: testNATShardPub4,
				EnvNAT64Prefix:      testNAT64Prefix,
			},
			wantNAT66:   true,
			wantNAT64:   true,
			description: "one shard, one session table, both families",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNAT66NodeName)
			t.Setenv(EnvNATUplinkInterface, testNAT66Iface)
			t.Setenv(EnvNATShardSID, testNATShardSID)
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := NewNATConfig()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil (%s)", err, tt.description)
			}
			if got := cfg.ServesNAT66(); got != tt.wantNAT66 {
				t.Errorf("ServesNAT66() = %v, want %v", got, tt.wantNAT66)
			}
			if got := cfg.ServesNAT64(); got != tt.wantNAT64 {
				t.Errorf("ServesNAT64() = %v, want %v", got, tt.wantNAT64)
			}
		})
	}
}
