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
	testNATNodeName = "test-nat-node"
	testNATIface    = "eth1"
	testNATIface2   = "eth2"
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
}

func TestNATConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvNATNodeName, testEnvNode)
	t.Setenv(EnvNATMetricsPort, "9090")
	t.Setenv(EnvNATGRPCHealthPort, "9091")
	t.Setenv(EnvNATUplinkInterfaces, testNATIface)

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
}

func TestNATConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    testCaseMissingNodeName,
			envVars: map[string]string{EnvNATUplinkInterfaces: testNATIface},
			wantErr: testErrNodeNameRequired,
		},
		{
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvNATNodeName:    testNATNodeName,
				EnvNATMetricsPort: "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvNATNodeName:       testNATNodeName,
				EnvNATGRPCHealthPort: "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			// The node name is the only required value. Uplinks are
			// auto-detected when unset, and the shard's identity comes from
			// its EgressShard's spec, not from process configuration.
			name:    testCaseValidConfig,
			envVars: map[string]string{EnvNATNodeName: testNATNodeName},
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

// TestNATConfigUplinkInterfaces is the regression test for a shard that could
// only ever attach to one uplink (#545). The override must be able to name
// every fabric uplink of a multi-homed node: one an operator cannot express is
// one the datapath never claims, and traffic arriving there leaves untranslated
// and uncounted.
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

// TestNATConfigUplinkInterfacesOptional covers the other half: an override
// that is unset or names nothing usable means auto-detect, not an error.
// Treating it as required is what forced a hand-written per-node patch onto
// every shard (#581).
func TestNATConfigUplinkInterfacesOptional(t *testing.T) {
	for _, value := range []string{"", "  ", ",", " , "} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			t.Setenv(EnvNATUplinkInterfaces, value)

			cfg := NewNATConfig()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil (an empty override means auto-detect)", err)
			}
			if len(cfg.UplinkInterfaces) != 0 {
				t.Errorf("UplinkInterfaces = %q, want empty", cfg.UplinkInterfaces)
			}
		})
	}
}
