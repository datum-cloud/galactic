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
	t.Setenv(EnvGatewayNodeName, "env-node")
	t.Setenv(EnvGatewayMetricsPort, "9090")
	t.Setenv(EnvGatewayGRPCHealthPort, "9091")
	t.Setenv(EnvGatewayPublicInterface, testGatewayIface)
	t.Setenv(EnvGatewaySRv6Address, testGatewaySRv6)

	cfg := NewGatewayConfig()

	if cfg.NodeName != "env-node" {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, "env-node")
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
			name:    "missing node name",
			envVars: map[string]string{EnvGatewayPublicInterface: testGatewayIface, EnvGatewaySRv6Address: testGatewaySRv6},
			wantErr: "node name is required",
		},
		{
			name:    "missing public interface",
			envVars: map[string]string{EnvGatewayNodeName: testGatewayNodeName, EnvGatewaySRv6Address: testGatewaySRv6},
			wantErr: "public interface is required",
		},
		{
			name:    "missing srv6 address",
			envVars: map[string]string{EnvGatewayNodeName: testGatewayNodeName, EnvGatewayPublicInterface: testGatewayIface},
			wantErr: "SRv6 address is required",
		},
		{
			name: "invalid metrics port",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayMetricsPort:     "0",
			},
			wantErr: "metrics port must be between",
		},
		{
			name: "invalid grpc health port",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayGRPCHealthPort:  "0",
			},
			wantErr: "grpc health port must be between",
		},
		{
			name: "valid config",
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
