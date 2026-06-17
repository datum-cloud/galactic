// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"maps"
	"strings"
	"testing"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	providersv1alpha1 "go.miloapis.com/cosmos/api/providers/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	labelDaemon    = "galactic.io/daemon"
	daemonGoBGP    = "gobgp"
	testVPCHex1234 = "0000000004d2" // decimal 1234
	testRD65000_1  = "65000:1"      // RD/RT for ASN 65000, NN 1
)

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(cniScheme).WithObjects(objs...).Build()
}

// providerForNode builds a BGPProvider with the label set galactic-agent applies.
func providerForNode(name, node string, extraLabels map[string]string) *providersv1alpha1.BGPProvider {
	lbls := map[string]string{
		labelNode:                node,
		labelDaemon:              daemonGoBGP,
		"galactic.io/plane":      "overlay",
		"galactic.io/managed-by": "galactic-agent",
	}
	maps.Copy(lbls, extraLabels)
	return &providersv1alpha1.BGPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: lbls},
		Spec: providersv1alpha1.BGPProviderSpec{
			Type:  "GoBGP",
			GoBGP: &providersv1alpha1.GoBGPProviderConfig{Endpoint: "localhost:50051"},
		},
	}
}

// manualInstance builds a BGPInstance with the given providerSelector labels.
func manualInstance(name string, asn int64, selectorLabels map[string]string) *bgpv1alpha1.BGPInstance {
	return &bgpv1alpha1.BGPInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: bgpv1alpha1.BGPInstanceSpec{
			ProviderSelector: metav1.LabelSelector{MatchLabels: selectorLabels},
			ASNumber:         asn,
			AddressFamilies:  []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
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
				if !strings.Contains(err.Error(), tt.wantErr) {
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

	gobgpProvider := providerForNode("galactic-gobgp-node1", nodeName, nil)
	gobgpSelector := map[string]string{labelDaemon: daemonGoBGP}
	matchingInstance := manualInstance("overlay-instance", 65000, gobgpSelector)

	tests := []struct {
		name    string
		objects []client.Object
		wantErr string
		check   func(t *testing.T, cfg bgpConfig)
	}{
		{
			name:    "no providers for node",
			objects: nil,
			wantErr: "no BGPProvider found",
		},
		{
			name:    "provider present but no matching instance",
			objects: []client.Object{gobgpProvider},
			wantErr: "no BGPInstance found",
		},
		{
			name:    "single matching instance returns correct config",
			objects: []client.Object{gobgpProvider, matchingInstance},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.asNumber != 65000 {
					t.Errorf("asNumber = %d, want 65000", cfg.asNumber)
				}
				if cfg.instanceName != "overlay-instance" {
					t.Errorf("instanceName = %q, want %q", cfg.instanceName, "overlay-instance")
				}
			},
		},
		{
			name:    "providerSelector merges node label with instance's selector labels",
			objects: []client.Object{gobgpProvider, matchingInstance},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				ml := cfg.providerSelector.MatchLabels
				if ml[labelNode] != nodeName {
					t.Errorf("MatchLabels[node] = %q, want %q", ml[labelNode], nodeName)
				}
				if ml[labelDaemon] != "gobgp" {
					t.Errorf("MatchLabels[daemon] = %q, want %q", ml[labelDaemon], "gobgp")
				}
			},
		},
		{
			name: "non-matching instance selector is ignored",
			objects: []client.Object{
				gobgpProvider,
				matchingInstance,
				manualInstance("frr-instance", 65001, map[string]string{labelDaemon: "frr"}),
			},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.instanceName != "overlay-instance" {
					t.Errorf("instanceName = %q, want %q", cfg.instanceName, "overlay-instance")
				}
			},
		},
		{
			name: "ambiguous: two instances both select the provider",
			objects: []client.Object{
				gobgpProvider,
				manualInstance("instance-a", 65000, gobgpSelector),
				manualInstance("instance-b", 65001, gobgpSelector),
			},
			wantErr: "ambiguous",
		},
		{
			name: "ambiguous error lists instance names",
			objects: []client.Object{
				gobgpProvider,
				manualInstance("alpha", 65000, gobgpSelector),
				manualInstance("beta", 65001, gobgpSelector),
			},
			wantErr: "alpha",
		},
		{
			name: "invalid providerSelector on instance surfaces error",
			objects: []client.Object{
				gobgpProvider,
				&bgpv1alpha1.BGPInstance{
					ObjectMeta: metav1.ObjectMeta{Name: "bad-instance"},
					Spec: bgpv1alpha1.BGPInstanceSpec{
						ASNumber: 65000,
						ProviderSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{Key: "foo", Operator: "BadOperator", Values: []string{"bar"}},
							},
						},
						AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
					},
				},
			},
			wantErr: "invalid providerSelector",
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
				if !strings.Contains(err.Error(), tt.wantErr) {
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
