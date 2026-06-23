// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"testing"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testVPCHex1234 = "0000000004d2" // decimal 1234
	testRD65000_1  = "65000:1"      // RD/RT for ASN 65000, NN 1
)

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(cniScheme).WithObjects(objs...).Build()
}

// routerForNode builds a BGPRouter targeting the given node.
func routerForNode(name, node string, asn uint32, roles []bgpv1alpha1.RouterRole, afs []bgpv1alpha1.AddressFamily) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "galactic-system"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:       bgpv1alpha1.TargetRef{Kind: "Node", Name: node},
			Roles:           roles,
			LocalASN:        asn,
			RouterID:        "10.0.0.1",
			AddressFamilies: afs,
		},
	}
}

// ---- parseConf -----------------------------------------------------------

func TestParseConf(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantVPC string
		wantErr string
	}{
		{
			name:    "valid config",
			input:   `{"cniVersion":"1.0.0","name":"test","type":"galactic-cni","vpc":"abc","vpcattachment":"def","srv6_locator":"2001:db8::/48"}`,
			wantVPC: "abc",
		},
		{
			name:    "invalid JSON",
			input:   "not json",
			wantErr: "parse CNI config",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "parse CNI config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := parseConf([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf.VPC != tt.wantVPC {
				t.Errorf("VPC = %q, want %q", conf.VPC, tt.wantVPC)
			}
		})
	}
}

// ---- bgpVRFInstanceName --------------------------------------------------

func TestBGPVRFInstanceName(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{"abc", "def", "abc-def"},
		{"0000000jU", "00G", "0000000jU-00G"},
	}
	for _, tt := range tests {
		got := bgpVRFInstanceName(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("bgpVRFInstanceName(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
		}
	}
}

// ---- routeDistinguisher --------------------------------------------------

func TestRouteDistinguisher(t *testing.T) {
	tests := []struct {
		name     string
		asNumber int64
		vpcHex   string
		want     string
		wantErr  bool
	}{
		{
			name:     "small VPC value",
			asNumber: 65000,
			vpcHex:   "000000000064", // 100 decimal
			want:     "65000:100",
		},
		{
			name:     "VPC value 1",
			asNumber: 65000,
			vpcHex:   "000000000001",
			want:     testRD65000_1,
		},
		{
			name:     "exceeds Type 1 limit — valid for Type 0",
			asNumber: 65000,
			vpcHex:   "000000010000", // 65536 — would overflow Type 1 NN, safe in Type 0
			want:     "65000:65536",
		},
		{
			name:     "low 32 bits all set",
			asNumber: 65000,
			vpcHex:   "0000ffffffff", // low32 = 4294967295
			want:     "65000:4294967295",
		},
		{
			name:     "upper 16 bits of 48-bit VPC are stripped",
			asNumber: 65000,
			vpcHex:   "000100000001", // 0x000100000001; low32 = 1
			want:     testRD65000_1,
		},
		{
			name:     "four-byte ASN",
			asNumber: 4200000000,
			vpcHex:   testVPCHex1234,
			want:     "4200000000:1234",
		},
		{
			name:    "invalid hex string",
			vpcHex:  "zzzzzz",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeDistinguisher(tt.asNumber, tt.vpcHex)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("routeDistinguisher(%d, %q) = %q, want %q", tt.asNumber, tt.vpcHex, got, tt.want)
			}
		})
	}
}

// ---- routeTarget ---------------------------------------------------------

func TestRouteTarget(t *testing.T) {
	tests := []struct {
		name     string
		asNumber int64
		vpcHex   string
		want     string
		wantErr  bool
	}{
		{
			name:     "VPC value fits in 32 bits",
			asNumber: 65000,
			vpcHex:   testVPCHex1234,
			want:     "65000:1234",
		},
		{
			name:     "upper 16 bits of 48-bit VPC stripped",
			asNumber: 65000,
			vpcHex:   "000100000001", // 0x000100000001; low32 = 1
			want:     testRD65000_1,
		},
		{
			name:     "low 32 bits all set",
			asNumber: 65000,
			vpcHex:   "0000ffffffff",
			want:     "65000:4294967295",
		},
		{
			name:     "different ASN",
			asNumber: 4200000000,
			vpcHex:   testVPCHex1234,
			want:     "4200000000:1234",
		},
		{
			name:    "invalid hex string",
			vpcHex:  "zzzzzz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeTarget(tt.asNumber, tt.vpcHex)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("routeTarget(%d, %q) = %q, want %q", tt.asNumber, tt.vpcHex, got, tt.want)
			}
		})
	}
}

// ---- lookupBGPConfig -----------------------------------------------------

func TestLookupBGPConfig(t *testing.T) {
	ctx := context.Background()
	const nodeName = "node1"

	tenantRouter := routerForNode("galactic-tenant-node1", nodeName, 65000,
		[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
		[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
	)

	tests := []struct {
		name    string
		objects []client.Object
		wantErr string
		check   func(t *testing.T, cfg bgpConfig)
	}{
		{
			name:    "no routers for node",
			objects: nil,
			wantErr: "no BGPRouter found",
		},
		{
			name: "router targets a different node",
			objects: []client.Object{
				routerForNode("other-router", "other-node", 65000,
					[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
					[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
				),
			},
			wantErr: "no BGPRouter found",
		},
		{
			name:    "single router returns correct config",
			objects: []client.Object{tenantRouter},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.asNumber != 65000 {
					t.Errorf("asNumber = %d, want 65000", cfg.asNumber)
				}
				if cfg.routerSelector[labelNode] != nodeName {
					t.Errorf("routerSelector[node] = %q, want %q", cfg.routerSelector[labelNode], nodeName)
				}
			},
		},
		{
			name: "ambiguous: two routers target same node",
			objects: []client.Object{
				routerForNode("router-a", nodeName, 65000,
					[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
					[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
				),
				routerForNode("router-b", nodeName, 65001,
					[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
					[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
				),
			},
			wantErr: "ambiguous",
		},
		{
			name: "ambiguous error lists router names",
			objects: []client.Object{
				routerForNode("alpha", nodeName, 65000,
					[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
					[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
				),
				routerForNode("beta", nodeName, 65001,
					[]bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
					[]bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
				),
			},
			wantErr: "alpha",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)

			cfg, err := lookupBGPConfig(ctx, k8s, nodeName)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

// contains is a helper to avoid importing strings in test file scope.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchIn(s, substr)
}

func searchIn(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
