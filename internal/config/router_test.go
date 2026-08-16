// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

const (
	testRouterNodeName = "test-node"
	testBoolTrue       = "true"
	// testGatewayIface/testGatewaySRv6 are shared with gateway_test.go's
	// GatewayConfig tests, which took over the equivalent fields dropped
	// from RouterConfig by the galactic-gateway split.
	testGatewayIface = "eth0"
	testGatewaySRv6  = "2001:db8:3::1"
)

func TestRouterConfigDefaults(t *testing.T) {
	cfg := NewRouterConfig()

	if cfg.BGPListenPort != DefaultRouterBGPListenPort {
		t.Errorf("BGPListenPort = %d, want %d", cfg.BGPListenPort, DefaultRouterBGPListenPort)
	}
	if cfg.MetricsPort != DefaultRouterMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultRouterMetricsPort)
	}
	if cfg.GRPCHealthPort != DefaultRouterGRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, DefaultRouterGRPCHealthPort)
	}
	if cfg.GCNamespace != DefaultRouterGCNamespace {
		t.Errorf("GCNamespace = %q, want %q", cfg.GCNamespace, DefaultRouterGCNamespace)
	}
	if cfg.GCInterval != DefaultRouterGCInterval {
		t.Errorf("GCInterval = %v, want %v", cfg.GCInterval, DefaultRouterGCInterval)
	}
	if cfg.Reflector {
		t.Error("Reflector = true, want false")
	}
	if cfg.WebhookEnabled {
		t.Error("WebhookEnabled = true, want false (disabled by default)")
	}
	if cfg.WebhookPort != DefaultRouterWebhookPort {
		t.Errorf("WebhookPort = %d, want %d", cfg.WebhookPort, DefaultRouterWebhookPort)
	}
	if cfg.WebhookCertDir != "" {
		t.Errorf("WebhookCertDir = %q, want empty", cfg.WebhookCertDir)
	}
}

func TestRouterConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvRouterNodeName, "env-node")
	t.Setenv(EnvRouterReflector, testBoolTrue)
	t.Setenv(EnvRouterBGPListenPort, "1790")
	t.Setenv(EnvRouterBGPLocalAddr, "2001:db8::1")
	t.Setenv(EnvRouterMetricsPort, "9090")
	t.Setenv(EnvRouterGRPCHealthPort, "5179")
	t.Setenv(EnvRouterGCNamespace, "custom-ns")
	t.Setenv(EnvRouterGCInterval, "10m")
	t.Setenv(EnvRouterWebhookEnabled, testBoolTrue)
	t.Setenv(EnvRouterWebhookPort, "9444")
	t.Setenv(EnvRouterWebhookCertDir, "/tmp/certs")

	cfg := NewRouterConfig()

	if cfg.NodeName != "env-node" {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, "env-node")
	}
	if !cfg.Reflector {
		t.Error("Reflector = false, want true")
	}
	if cfg.BGPListenPort != 1790 {
		t.Errorf("BGPListenPort = %d, want 1790", cfg.BGPListenPort)
	}
	if cfg.BGPLocalAddr != "2001:db8::1" {
		t.Errorf("BGPLocalAddr = %q, want %q", cfg.BGPLocalAddr, "2001:db8::1")
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
	if cfg.GRPCHealthPort != 5179 {
		t.Errorf("GRPCHealthPort = %d, want 5179", cfg.GRPCHealthPort)
	}
	if cfg.GCNamespace != "custom-ns" {
		t.Errorf("GCNamespace = %q, want %q", cfg.GCNamespace, "custom-ns")
	}
	if cfg.GCInterval != 10*time.Minute {
		t.Errorf("GCInterval = %v, want 10m", cfg.GCInterval)
	}
	if !cfg.WebhookEnabled {
		t.Error("WebhookEnabled = false, want true")
	}
	if cfg.WebhookPort != 9444 {
		t.Errorf("WebhookPort = %d, want 9444", cfg.WebhookPort)
	}
	if cfg.WebhookCertDir != "/tmp/certs" {
		t.Errorf("WebhookCertDir = %q, want %q", cfg.WebhookCertDir, "/tmp/certs")
	}
}

func TestRouterConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    "missing node name",
			envVars: map[string]string{},
			wantErr: "node name is required",
		},
		{
			name: "valid node name",
			envVars: map[string]string{
				EnvRouterNodeName: testRouterNodeName,
			},
			wantErr: "",
		},
		{
			name: "valid node name with reflector",
			envVars: map[string]string{
				EnvRouterNodeName:  testRouterNodeName,
				EnvRouterReflector: testBoolTrue,
			},
			wantErr: "",
		},
		{
			name: "invalid bgp listen port",
			envVars: map[string]string{
				EnvRouterNodeName:      testRouterNodeName,
				EnvRouterBGPListenPort: "0",
			},
			wantErr: "bgp listen port must be between",
		},
		{
			name: "outbound-only bgp listen port",
			envVars: map[string]string{
				EnvRouterNodeName:      testRouterNodeName,
				EnvRouterBGPListenPort: "-1",
			},
			wantErr: "",
		},
		{
			name: "invalid metrics port",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterMetricsPort: "0",
			},
			wantErr: "metrics port must be between",
		},
		{
			name: "invalid grpc health port",
			envVars: map[string]string{
				EnvRouterNodeName:       testRouterNodeName,
				EnvRouterGRPCHealthPort: "0",
			},
			wantErr: "grpc health port must be between",
		},
		{
			name: "invalid webhook port",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterWebhookPort: "0",
			},
			wantErr: "webhook port must be between",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			cfg := NewRouterConfig()
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
