// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

const (
	testBoolFalse   = "false"
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

// TestNATConfigXDPAttach covers the attach mode: direct unless set, dispatch
// when asked for, the retired chain read as dispatch, and anything else
// refused at startup rather than read as one of them.
func TestNATConfigXDPAttach(t *testing.T) {
	tests := []struct {
		value   string
		set     bool
		want    string
		wantErr bool
	}{
		{want: NATXDPAttachDirect},
		{value: NATXDPAttachDirect, set: true, want: NATXDPAttachDirect},
		{value: NATXDPAttachDispatch, set: true, want: NATXDPAttachDispatch},
		{value: NATXDPAttachChain, set: true, want: NATXDPAttachDispatch},
		{value: "tc", set: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.value), func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			if tt.set {
				t.Setenv(EnvNATXDPAttach, tt.value)
			}

			cfg := NewNATConfig()
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg.XDPAttach != tt.want {
				t.Errorf("XDPAttach = %q, want %q", cfg.XDPAttach, tt.want)
			}
		})
	}
}

// TestNATConfigEchoResponder covers the echo responder's three tiers: off
// unless asked for, on from the environment, and the CLI flag winning over the
// environment in either direction. Off is the default that matters: a shard
// that answered pings without being told to would change what an
// internet-facing address does on upgrade.
func TestNATConfigEchoResponder(t *testing.T) {
	tests := []struct {
		name string
		env  string
		flag string
		want bool
	}{
		{name: "default", want: false},
		{name: "env on", env: testBoolTrue, want: true},
		{name: "env off", env: testBoolFalse, want: false},
		{name: "flag over env", env: testBoolFalse, flag: testBoolTrue, want: true},
		{name: "flag off over env on", env: testBoolTrue, flag: testBoolFalse, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv(EnvNATEchoResponder, tt.env)
			}
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.String(FlagNodeName, "", "")
			flags.Int(FlagMetricsPort, DefaultNATMetricsPort, "")
			flags.Int(FlagGRPCHealthPort, DefaultNATGRPCHealthPort, "")
			flags.String("nat-uplink-interfaces", "", "")
			flags.String("nat-xdp-attach", NATXDPAttachDirect, "")
			flags.Bool("nat-echo-responder", false, "")
			if tt.flag != "" {
				if err := flags.Set("nat-echo-responder", tt.flag); err != nil {
					t.Fatalf("set flag: %v", err)
				}
			}

			cfg := NewNATConfig()
			cfg.BindFlags(flags)
			if cfg.EchoResponder != tt.want {
				t.Errorf("EchoResponder = %v, want %v", cfg.EchoResponder, tt.want)
			}
		})
	}
}

// TestNATConfigDatapathEnabled covers the datapath switch's three tiers. On is
// the default that matters: a shard that came up disabled after an upgrade
// would withdraw its advertisement and stop translating.
func TestNATConfigDatapathEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string
		flag string
		want bool
	}{
		{name: "default", want: true},
		{name: "env off", env: testBoolFalse, want: false},
		{name: "env on", env: testBoolTrue, want: true},
		{name: "flag off over env on", env: testBoolTrue, flag: testBoolFalse, want: false},
		{name: "flag on over env off", env: testBoolFalse, flag: testBoolTrue, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv(EnvNATDatapathEnabled, tt.env)
			}
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.String(FlagNodeName, "", "")
			flags.Int(FlagMetricsPort, DefaultNATMetricsPort, "")
			flags.Int(FlagGRPCHealthPort, DefaultNATGRPCHealthPort, "")
			flags.String("nat-uplink-interfaces", "", "")
			flags.String("nat-xdp-attach", NATXDPAttachDirect, "")
			flags.Bool("nat-datapath-enabled", true, "")
			flags.Bool("nat-echo-responder", false, "")
			if tt.flag != "" {
				if err := flags.Set("nat-datapath-enabled", tt.flag); err != nil {
					t.Fatalf("set flag: %v", err)
				}
			}

			cfg := NewNATConfig()
			cfg.BindFlags(flags)
			if cfg.DatapathEnabled != tt.want {
				t.Errorf("DatapathEnabled = %v, want %v", cfg.DatapathEnabled, tt.want)
			}
		})
	}
}
