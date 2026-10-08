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
	// testHostProcSys is the procfs root the gateway and NAT DaemonSets set.
	testHostProcSys = "/host/proc/sys"
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
	if cfg.ServiceFrontendEnabled {
		t.Error("service frontends must be disabled by default")
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
	if len(cfg.BMPStations) != 0 {
		t.Errorf("BMPStations = %v, want none (BMP disabled by default)", cfg.BMPStations)
	}
	if cfg.BMPPolicy != DefaultRouterBMPPolicy {
		t.Errorf("BMPPolicy = %q, want %q", cfg.BMPPolicy, DefaultRouterBMPPolicy)
	}
	if cfg.BMPStatisticsInterval != DefaultRouterBMPStatisticsInterval {
		t.Errorf("BMPStatisticsInterval = %v, want %v", cfg.BMPStatisticsInterval, DefaultRouterBMPStatisticsInterval)
	}
}

func TestRouterConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvRouterNodeName, testEnvNode)
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
	t.Setenv(EnvRouterBMPStations, "gobmp.galactic-system.svc:5000, [2001:db8::5]:5000,")
	t.Setenv(EnvRouterBMPPolicy, "local-rib")
	t.Setenv(EnvRouterBMPStatisticsInterval, "0s")

	cfg := NewRouterConfig()

	if cfg.NodeName != testEnvNode {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, testEnvNode)
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
	wantStations := []string{"gobmp.galactic-system.svc:5000", "[2001:db8::5]:5000"}
	if strings.Join(cfg.BMPStations, ",") != strings.Join(wantStations, ",") {
		t.Errorf("BMPStations = %q, want %q", cfg.BMPStations, wantStations)
	}
	if cfg.BMPPolicy != "local-rib" {
		t.Errorf("BMPPolicy = %q, want local-rib", cfg.BMPPolicy)
	}
	if cfg.BMPStatisticsInterval != 0 {
		t.Errorf("BMPStatisticsInterval = %v, want 0", cfg.BMPStatisticsInterval)
	}
}

func TestRouterConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    testCaseMissingNodeName,
			envVars: map[string]string{},
			wantErr: testErrNodeNameRequired,
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
			name: testCaseInvalidMetricsPort,
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterMetricsPort: "0",
			},
			wantErr: testErrMetricsPortRange,
		},
		{
			name: testCaseInvalidGRPCHealthPort,
			envVars: map[string]string{
				EnvRouterNodeName:       testRouterNodeName,
				EnvRouterGRPCHealthPort: "0",
			},
			wantErr: testErrGRPCHealthPortRange,
		},
		{
			name: "invalid webhook port",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterWebhookPort: "0",
			},
			wantErr: "webhook port must be between",
		},
		{
			name: "valid bmp stations",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterBMPStations: "gobmp:5000,[fc00:0:7::1]:5000,10.0.0.1:11019",
			},
			wantErr: "",
		},
		{
			name: "bmp station without port",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterBMPStations: "gobmp",
			},
			wantErr: EnvRouterBMPStations,
		},
		{
			name: "bmp station with port 0",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterBMPStations: "gobmp:0",
			},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name: "bmp station without host",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterBMPStations: ":5000",
			},
			wantErr: "has no host",
		},
		{
			name: "unbracketed ipv6 bmp station",
			envVars: map[string]string{
				EnvRouterNodeName:    testRouterNodeName,
				EnvRouterBMPStations: "fc00:0:7::1:5000",
			},
			wantErr: EnvRouterBMPStations,
		},
		{
			name: "unknown bmp policy",
			envVars: map[string]string{
				EnvRouterNodeName:  testRouterNodeName,
				EnvRouterBMPPolicy: "both",
			},
			wantErr: EnvRouterBMPPolicy,
		},
		{
			name: "fractional bmp statistics interval",
			envVars: map[string]string{
				EnvRouterNodeName:              testRouterNodeName,
				EnvRouterBMPStatisticsInterval: "1500ms",
			},
			wantErr: EnvRouterBMPStatisticsInterval,
		},
		{
			name: "bmp statistics interval too long",
			envVars: map[string]string{
				EnvRouterNodeName:              testRouterNodeName,
				EnvRouterBMPStatisticsInterval: "24h",
			},
			wantErr: EnvRouterBMPStatisticsInterval,
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

func TestParseBMPStation(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{in: "gobmp.galactic-system.svc:5000", wantHost: "gobmp.galactic-system.svc", wantPort: 5000},
		{in: "[fc00:0:7::1]:5000", wantHost: "fc00:0:7::1", wantPort: 5000},
		{in: "10.0.0.1:65535", wantHost: "10.0.0.1", wantPort: 65535},
		{in: "gobmp", wantErr: true},
		{in: "gobmp:65536", wantErr: true},
		{in: "gobmp:abc", wantErr: true},
		{in: "[]:5000", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			host, port, err := ParseBMPStation(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (host != tt.wantHost || port != tt.wantPort) {
				t.Errorf("= %q, %d, want %q, %d", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestRouterConfigServiceFrontendEnv(t *testing.T) {
	t.Setenv(EnvRouterServiceFrontendEnabled, testBoolTrue)
	if !NewRouterConfig().ServiceFrontendEnabled {
		t.Fatal("explicit service frontend enablement was ignored")
	}
}
