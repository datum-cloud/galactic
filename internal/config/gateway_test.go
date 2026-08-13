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
	testGatewayEgress   = "2001:db8:8::1"
	testInvalidAddr     = "not-an-ip-address"
	testIPv4Addr        = "203.0.113.1"
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
	if cfg.EgressAddress != "" {
		t.Errorf("EgressAddress = %q, want empty", cfg.EgressAddress)
	}
	if cfg.EgressSID != "" {
		t.Errorf("EgressSID = %q, want empty", cfg.EgressSID)
	}
}

func TestGatewayConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvGatewayNodeName, "env-node")
	t.Setenv(EnvGatewayMetricsPort, "9090")
	t.Setenv(EnvGatewayGRPCHealthPort, "9091")
	t.Setenv(EnvGatewayPublicInterface, testGatewayIface)
	t.Setenv(EnvGatewaySRv6Address, testGatewaySRv6)
	t.Setenv(EnvGatewayEgressAddress, testGatewayEgress)
	t.Setenv(EnvGatewayEgressSID, testGatewaySRv6)

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
	if cfg.EgressAddress != testGatewayEgress {
		t.Errorf("EgressAddress = %q, want %q", cfg.EgressAddress, testGatewayEgress)
	}
	if cfg.EgressSID != testGatewaySRv6 {
		t.Errorf("EgressSID = %q, want %q", cfg.EgressSID, testGatewaySRv6)
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
			name: "unparseable srv6 address",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testInvalidAddr,
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
			wantErr: "must be a native IPv6 address",
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
		{
			name: "egress address without egress sid",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testGatewayEgress,
			},
			wantErr: "must be set together",
		},
		{
			name: "egress sid without egress address",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressSID:       testGatewayEgress,
			},
			wantErr: "must be set together",
		},
		{
			name: "unparseable egress address",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testInvalidAddr,
				EnvGatewayEgressSID:       testGatewayEgress,
			},
			wantErr: "egress address \"not-an-ip-address\" is not a valid IP address",
		},
		{
			name: "ipv4 egress address is wrong family",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testIPv4Addr,
				EnvGatewayEgressSID:       testGatewayEgress,
			},
			wantErr: "egress address \"203.0.113.1\" must be a native IPv6 address",
		},
		{
			name: "unparseable egress sid",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testGatewayEgress,
				EnvGatewayEgressSID:       testInvalidAddr,
			},
			wantErr: "egress SID \"not-an-ip-address\" is not a valid IP address",
		},
		{
			name: "ipv4 egress sid is wrong family",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testGatewayEgress,
				EnvGatewayEgressSID:       testIPv4Addr,
			},
			wantErr: "egress SID \"203.0.113.1\" must be a native IPv6 address",
		},
		{
			name: "valid config with egress pair",
			envVars: map[string]string{
				EnvGatewayNodeName:        testGatewayNodeName,
				EnvGatewayPublicInterface: testGatewayIface,
				EnvGatewaySRv6Address:     testGatewaySRv6,
				EnvGatewayEgressAddress:   testGatewayEgress,
				EnvGatewayEgressSID:       testGatewaySRv6,
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
