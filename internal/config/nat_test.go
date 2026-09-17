// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	testNATNodeName  = "test-nat-node"
	testNATIface     = "eth1"
	testNATIface2    = "eth2"
	testNATShardSID  = "fc00:1:2::1"
	testNATShardPub4 = "192.0.2.10"
	testNAT64Prefix  = "2001:db8:64::/96"
	testNATShardPub  = "2001:db8:9999::1"
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
	if len(cfg.UplinkInterfaces) != 0 {
		t.Errorf("UplinkInterfaces = %q, want empty", cfg.UplinkInterfaces)
	}
	if cfg.ShardSID != "" {
		t.Errorf("ShardSID = %q, want empty", cfg.ShardSID)
	}
	if cfg.ShardPubAddr6 != "" {
		t.Errorf("ShardPubAddr6 = %q, want empty", cfg.ShardPubAddr6)
	}
}

func TestNATConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvNATNodeName, testEnvNode)
	t.Setenv(EnvNATMetricsPort, "9090")
	t.Setenv(EnvNATGRPCHealthPort, "9091")
	t.Setenv(EnvNATUplinkInterfaces, testNATIface)
	t.Setenv(EnvNATShardSID, testNATShardSID)
	t.Setenv(EnvNATShardPubAddr6, testNATShardPub)

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
	if len(cfg.UplinkInterfaces) != 1 || cfg.UplinkInterfaces[0] != testNATIface {
		t.Errorf("UplinkInterfaces = %q, want [%q]", cfg.UplinkInterfaces, testNATIface)
	}
	if cfg.ShardSID != testNATShardSID {
		t.Errorf("ShardSID = %q, want %q", cfg.ShardSID, testNATShardSID)
	}
	if cfg.ShardPubAddr6 != testNATShardPub {
		t.Errorf("ShardPubAddr6 = %q, want %q", cfg.ShardPubAddr6, testNATShardPub)
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
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
			},
			wantErr: testErrNodeNameRequired,
		},
		{
			name: "missing uplink interface",
			envVars: map[string]string{
				EnvNATNodeName:      testNATNodeName,
				EnvNATShardSID:      testNATShardSID,
				EnvNATShardPubAddr6: testNATShardPub,
			},
			wantErr: "uplink interface is required",
		},
		{
			name: "missing shard SID",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
			},
			wantErr: "shard SID is required",
		},
		{
			name: "unparseable shard SID",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         "not-an-ip-address",
			},
			wantErr: "is not a valid IP address",
		},
		{
			name: "ipv4 shard SID is wrong family",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testIPv4Addr,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			// No longer an error, and the reason this table has no
			// "serving neither address family" case any more: the IPv6
			// address is assigned in EgressShard spec, so every shard starts
			// serving nothing and is programmed from a reconcile.
			name: "no address family configured",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
			},
			wantErr: "",
		},
		{
			name: "NAT64 prefix without a public IPv4 address",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNAT64Prefix:         testNAT64Prefix,
			},
			wantErr: "shard public IPv4 address is not",
		},
		{
			name: "public IPv4 address without a NAT64 prefix",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr4:    testNATShardPub4,
			},
			wantErr: "NAT64 prefix is not",
		},
		{
			name: "ipv6 shard public IPv4 address is wrong family",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr4:    testNATShardPub,
				EnvNAT64Prefix:         testNAT64Prefix,
			},
			wantErr: "must be an IPv4 address",
		},
		{
			// The datapath extracts the embedded IPv4 address from one aligned
			// four-byte run, which only a /96 guarantees.
			name: "NAT64 prefix of the wrong length",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr4:    testNATShardPub4,
				EnvNAT64Prefix:         "2001:db8:64::/64",
			},
			wantErr: "must be a /96",
		},
		{
			name: "NAT64 prefix with bits below its length",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr4:    testNATShardPub4,
				EnvNAT64Prefix:         "2001:db8:64::1/96",
			},
			wantErr: "bits set below its prefix length",
		},
		{
			// Rejected rather than ignored, and rejected whatever it holds:
			// two writers for one datapath row cannot be reconciled, and an
			// operator who left this set would have no way to tell which
			// address the shard actually translates to.
			name: "removed shard public IPv6 address is rejected",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr6:    testNATShardPub,
			},
			wantErr: "no longer read",
		},
		{
			name: "removed shard public IPv6 address is rejected whatever its family",
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATShardPubAddr6:    testIPv4Addr,
			},
			wantErr: "no longer read",
		},
		{
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATMetricsPort:      "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
				EnvNATGRPCHealthPort:   "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			name: testCaseValidConfig,
			envVars: map[string]string{
				EnvNATNodeName:         testNATNodeName,
				EnvNATUplinkInterfaces: testNATIface,
				EnvNATShardSID:         testNATShardSID,
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

// TestNATConfigValidateAcceptsEachFamilyCombination pins the two shard shapes
// process configuration can still describe: no family at all, which is every
// shard awaiting an assigned IPv6 address, and NAT64, which is still
// configured here. The negative table above proves half a NAT64 configuration
// is rejected; this proves a whole one is not.
//
// There is no NAT66 shape any more. That address arrives in EgressShard spec,
// so no environment combination can turn it on.
func TestNATConfigValidateAcceptsEachFamilyCombination(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantNAT64   bool
		description string
	}{
		{
			name:        "no configured family",
			envVars:     map[string]string{},
			description: "a shard awaiting the IPv6 address its spec assigns",
		},
		{
			name: "NAT64",
			envVars: map[string]string{
				EnvNATShardPubAddr4: testNATShardPub4,
				EnvNAT64Prefix:      testNAT64Prefix,
			},
			wantNAT64:   true,
			description: "a shard whose IPv4 reachability is still process configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			t.Setenv(EnvNATUplinkInterfaces, testNATIface)
			t.Setenv(EnvNATShardSID, testNATShardSID)
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := NewNATConfig()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil (%s)", err, tt.description)
			}
			if got := cfg.ServesNAT64(); got != tt.wantNAT64 {
				t.Errorf("ServesNAT64() = %v, want %v", got, tt.wantNAT64)
			}
		})
	}
}

// TestNATConfigUplinkInterfaces is the regression test for a shard that could
// only ever attach to one uplink (#545). A multi-homed shard node needs every
// fabric uplink named here: one an operator cannot express is one the datapath
// never claims, and traffic arriving there leaves untranslated and uncounted.
//
// Before the field became a list, the comma-separated form below resolved to a
// single interface literally named "eth1,eth2", which Validate accepted and no
// LinkByName could ever resolve.
func TestNATConfigUplinkInterfaces(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "single uplink",
			value: testNATIface,
			want:  []string{testNATIface},
		},
		{
			name:  "dual-homed shard node",
			value: testNATIface + "," + testNATIface2,
			want:  []string{testNATIface, testNATIface2},
		},
		{
			// A trailing comma or a stray space must not produce an interface
			// name no attach could resolve, which would fail the whole
			// all-or-nothing attach over a typo.
			name:  "trailing comma and surrounding whitespace",
			value: " " + testNATIface + " , " + testNATIface2 + " ,",
			want:  []string{testNATIface, testNATIface2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			t.Setenv(EnvNATUplinkInterfaces, tt.value)
			t.Setenv(EnvNATShardSID, testNATShardSID)

			cfg := NewNATConfig()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if !slices.Equal(cfg.UplinkInterfaces, tt.want) {
				t.Errorf("UplinkInterfaces = %q, want %q", cfg.UplinkInterfaces, tt.want)
			}
		})
	}
}

// TestNATConfigUplinkInterfacesRequired covers the other half: a shard with no
// usable uplink must fail at startup naming the field, not load a datapath it
// then attaches nowhere.
func TestNATConfigUplinkInterfacesRequired(t *testing.T) {
	for _, value := range []string{"", "  ", ",", " , "} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			t.Setenv(EnvNATUplinkInterfaces, value)
			t.Setenv(EnvNATShardSID, testNATShardSID)

			cfg := NewNATConfig()
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error for a shard with no uplink")
			}
			if !strings.Contains(err.Error(), EnvNATUplinkInterfaces) {
				t.Errorf("Validate() = %v, want an error naming %s", err, EnvNATUplinkInterfaces)
			}
		})
	}
}
