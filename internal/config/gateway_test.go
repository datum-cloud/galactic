// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

const (
	testGatewayNodeName = "test-gateway-node"
)

func TestGatewayConfigDefaults(t *testing.T) {
	cfg := NewGatewayConfig()

	if cfg.MetricsPort != DefaultGatewayMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultGatewayMetricsPort)
	}
	if cfg.GRPCHealthPort != DefaultGatewayGRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, DefaultGatewayGRPCHealthPort)
	}
	if cfg.NodeName != "" {
		t.Errorf("NodeName = %q, want empty", cfg.NodeName)
	}
	if cfg.PublicInterface != "" {
		t.Errorf("PublicInterface = %q, want empty", cfg.PublicInterface)
	}
	if cfg.SRv6Address != "" {
		t.Errorf("SRv6Address = %q, want empty", cfg.SRv6Address)
	}
}

func TestGatewayConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvGatewayNodeName, testEnvNode)
	t.Setenv(EnvGatewayMetricsPort, "9090")
	t.Setenv(EnvGatewayGRPCHealthPort, "9091")
	t.Setenv(EnvGatewayPublicInterface, testGatewayIface)
	t.Setenv(EnvGatewaySRv6Address, testGatewaySRv6)

	cfg := NewGatewayConfig()

	if cfg.NodeName != testEnvNode {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, testEnvNode)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
	if cfg.GRPCHealthPort != 9091 {
		t.Errorf("GRPCHealthPort = %d, want 9091", cfg.GRPCHealthPort)
	}
	if cfg.PublicInterface != testGatewayIface {
		t.Errorf("PublicInterface = %q, want %q", cfg.PublicInterface, testGatewayIface)
	}
	if cfg.SRv6Address != testGatewaySRv6 {
		t.Errorf("SRv6Address = %q, want %q", cfg.SRv6Address, testGatewaySRv6)
	}
}

func TestGatewayConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    testCaseMissingNodeName,
			envVars: map[string]string{EnvGatewayPublicInterface: testGatewayIface, EnvGatewaySRv6Address: testGatewaySRv6},
			wantErr: testErrNodeNameRequired,
		},
		{
			name:    "missing public interface",
			envVars: map[string]string{EnvGatewayNodeName: testGatewayNodeName, EnvGatewaySRv6Address: testGatewaySRv6},
			wantErr: "public interface is required",
		},
		{
			// #707: left unset, the address is derived from this node's
			// BGPRouter at startup, so Validate has nothing to reject.
			name:    "missing srv6 address is derived",
			envVars: map[string]string{EnvGatewayNodeName: testGatewayNodeName, EnvGatewayPublicInterface: testGatewayIface},
			wantErr: "",
		},
		{
			name: "unparseable srv6 address",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     "not-an-ip-address",
			},
			wantErr: "is not a valid IP address",
		},
		{
			// Regression test for #360: an IPv4 address used to pass this
			// Validate() call and only fail later, deeper in, at
			// internal/gateway/kerneldatapath.go's identical Is6()/Is4In6()
			// check -- reject it here instead, at startup.
			name: "ipv4 srv6 address is wrong family",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testIPv4Addr,
			},
			wantErr: testErrMustBeNativeIPv6,
		},
		{
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayMetricsPort:     "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayGRPCHealthPort:  "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			name: testCaseValidConfig,
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			cfg := NewGatewayConfig()
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

// TestGatewayConfigXDPAttach covers the attach mode: dispatch unless set,
// direct when asked for, and anything else refused at startup.
func TestGatewayConfigXDPAttach(t *testing.T) {
	tests := []struct {
		value   string
		want    string
		wantErr bool
	}{
		{want: GatewayXDPAttachDispatch},
		{value: GatewayXDPAttachDirect, want: GatewayXDPAttachDirect},
		{value: "chain", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv(EnvGatewayNodeName, testEnvNode)
			t.Setenv(EnvGatewayPublicInterface, testGatewayIface)
			t.Setenv(EnvGatewaySRv6Address, testGatewaySRv6)
			if tt.value != "" {
				t.Setenv(EnvGatewayXDPAttach, tt.value)
			}
			cfg := NewGatewayConfig()
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

// TestGatewayConfigDisabledNeedsNoInterface: a node with its datapath off has
// nothing to attach, so it starts without a public interface or SRv6 address.
func TestGatewayConfigDisabledNeedsNoInterface(t *testing.T) {
	t.Setenv(EnvGatewayNodeName, testEnvNode)
	t.Setenv(EnvGatewayDatapathEnabled, "false")
	cfg := NewGatewayConfig()
	if cfg.DatapathEnabled {
		t.Fatal("DatapathEnabled = true with the env set to false")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v for a disabled datapath with no interface", err)
	}

	t.Setenv(EnvGatewayDatapathEnabled, "true")
	if err := NewGatewayConfig().Validate(); err == nil {
		t.Error("Validate() = nil for an enabled datapath with no public interface")
	}
}

func TestGatewayConfigProcSysPath(t *testing.T) {
	if got := NewGatewayConfig().ProcSysPath; got != DefaultProcSysPath {
		t.Errorf("default ProcSysPath = %q, want %q", got, DefaultProcSysPath)
	}
	t.Setenv(EnvGatewayProcSysPath, testHostProcSys)
	if got := NewGatewayConfig().ProcSysPath; got != testHostProcSys {
		t.Errorf("ProcSysPath = %q with %s set, want %s", got, EnvGatewayProcSysPath, testHostProcSys)
	}
}
