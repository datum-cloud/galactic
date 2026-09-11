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
	testNAT66ShardSID = "fc00:1:2::1"
	testNAT66ShardPub = "2001:db8:9999::1"
)

func TestNAT66ConfigDefaults(t *testing.T) {
	cfg := NewNAT66Config()

	if cfg.MetricsPort != DefaultNAT66MetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultNAT66MetricsPort)
	}
	if cfg.GRPCHealthPort != DefaultNAT66GRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, DefaultNAT66GRPCHealthPort)
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

func TestNAT66ConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvNAT66NodeName, testEnvNode)
	t.Setenv(EnvNAT66MetricsPort, "9090")
	t.Setenv(EnvNAT66GRPCHealthPort, "9091")
	t.Setenv(EnvNAT66UplinkInterface, testNAT66Iface)
	t.Setenv(EnvNAT66ShardSID, testNAT66ShardSID)
	t.Setenv(EnvNAT66ShardPubAddr, testNAT66ShardPub)

	cfg := NewNAT66Config()

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
	if cfg.ShardSID != testNAT66ShardSID {
		t.Errorf("ShardSID = %q, want %q", cfg.ShardSID, testNAT66ShardSID)
	}
	if cfg.ShardPubAddr != testNAT66ShardPub {
		t.Errorf("ShardPubAddr = %q, want %q", cfg.ShardPubAddr, testNAT66ShardPub)
	}
}

func TestNAT66ConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name: testCaseMissingNodeName,
			envVars: map[string]string{
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
			},
			wantErr: testErrNodeNameRequired,
		},
		{
			name: "missing uplink interface",
			envVars: map[string]string{
				EnvNAT66NodeName:     testNAT66NodeName,
				EnvNAT66ShardSID:     testNAT66ShardSID,
				EnvNAT66ShardPubAddr: testNAT66ShardPub,
			},
			wantErr: "uplink interface is required",
		},
		{
			name: "missing shard SID",
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
			},
			wantErr: "shard SID is required",
		},
		{
			name: "unparseable shard SID",
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        "not-an-ip-address",
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
			},
			wantErr: "is not a valid IP address",
		},
		{
			name: "ipv4 shard SID is wrong family",
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testIPv4Addr,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			name: "missing shard public address",
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
			},
			wantErr: "shard public address is required",
		},
		{
			name: "ipv4 shard public address is wrong family",
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
				EnvNAT66ShardPubAddr:    testIPv4Addr,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
				EnvNAT66MetricsPort:     "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
				EnvNAT66GRPCHealthPort:  "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			name: testCaseValidConfig,
			envVars: map[string]string{
				EnvNAT66NodeName:        testNAT66NodeName,
				EnvNAT66UplinkInterface: testNAT66Iface,
				EnvNAT66ShardSID:        testNAT66ShardSID,
				EnvNAT66ShardPubAddr:    testNAT66ShardPub,
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			cfg := NewNAT66Config()
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
