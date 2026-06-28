// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testVPC        = "abc"
	testAttachment = "def"
	testVPCHex1234 = "0000000004d2" // decimal 1234
	testRD65000_1  = "65000:1"      // RD/RT for ASN 65000, NN 1
)

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(cniScheme).WithObjects(objs...).Build()
}

// routerForNode builds a BGPRouter with spec.targetRef.name set to nodeName.
func routerForNode(name, nodeName, namespace string, asn int64) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{
				Kind: "Node",
				Name: nodeName,
			},
			LocalASN: asn,
			RouterID: "10.0.0.1",
			Roles:    []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}
}

// ---- parseConf -----------------------------------------------------------

func TestParseConf(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantVPC    string
		wantIfType string
		wantErr    string
	}{
		{
			name: "valid config",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_locator":"2001:db8::/48"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
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
		{
			name: "interface_type=veth",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","interface_type":"veth"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "interface_type=tap",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","interface_type":"tap"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeTap,
		},
		{
			name: "interface_type empty defaults to veth",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","interface_type":""}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "interface_type=unknown",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","interface_type":"unknown"}`,
				testVPC, testAttachment,
			),
			wantErr: `invalid interface_type "unknown": must be "veth" or "tap"`,
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
			if conf.InterfaceType != tt.wantIfType {
				t.Errorf("InterfaceType = %q, want %q", conf.InterfaceType, tt.wantIfType)
			}
		})
	}
}

// ---- bgpVRFInstanceName --------------------------------------------------

func TestBGPVRFInstanceName(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{testVPC, testAttachment, testVPC + "-" + testAttachment},
		{"0000000jU", "00G", "0000000jU-00G"},
	}
	for _, tt := range tests {
		got := bgpVRFInstanceName(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("bgpVRFInstanceName(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
		}
	}
}

// ---- bgpAdvertisementName ------------------------------------------------

func TestBGPAdvertisementName(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{testVPC, testAttachment, testVPC + "-" + testAttachment},
		{"0000000jU", "00G", "0000000jU-00G"},
	}
	for _, tt := range tests {
		got := bgpAdvertisementName(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("bgpAdvertisementName(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
		}
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

// ---- SetEnableLocalIPAM --------------------------------------------------

func TestSetEnableLocalIPAM(t *testing.T) {
	// Save and restore original state.
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()

	// Default should be false.
	if enableLocalIPAM {
		t.Error("enableLocalIPAM default = true, want false")
	}

	// Setting to true should work.
	SetEnableLocalIPAM(true)
	if !enableLocalIPAM {
		t.Error("enableLocalIPAM after SetEnableLocalIPAM(true) = false, want true")
	}

	// Setting back to false should work.
	SetEnableLocalIPAM(false)
	if enableLocalIPAM {
		t.Error("enableLocalIPAM after SetEnableLocalIPAM(false) = true, want false")
	}
}

// ---- lookupBGPRouter -----------------------------------------------------

func TestLookupBGPRouter(t *testing.T) {
	ctx := context.Background()
	const (
		nodeName  = "node1"
		namespace = "default"
	)

	matchingRouter := routerForNode("overlay-router", nodeName, namespace, 65000)

	tests := []struct {
		name    string
		objects []client.Object
		wantErr string
		check   func(t *testing.T, cfg bgpConfig)
	}{
		{
			name:    "no router for node",
			objects: nil,
			wantErr: "no BGPRouter found",
		},
		{
			name:    "single matching router returns correct config",
			objects: []client.Object{matchingRouter},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.asNumber != 65000 {
					t.Errorf("asNumber = %d, want 65000", cfg.asNumber)
				}
				if cfg.routerName != "overlay-router" {
					t.Errorf("routerName = %q, want %q", cfg.routerName, "overlay-router")
				}
			},
		},
		{
			name: "router in different namespace is ignored",
			objects: []client.Object{
				routerForNode("other-ns-router", nodeName, "other-ns", 65001),
			},
			wantErr: "no BGPRouter found",
		},
		{
			name: "non-matching node router is ignored",
			objects: []client.Object{
				routerForNode("other-node-router", "node2", namespace, 65001),
				matchingRouter,
			},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.routerName != "overlay-router" {
					t.Errorf("routerName = %q, want %q", cfg.routerName, "overlay-router")
				}
			},
		},
		{
			name: "ambiguous: two routers target same node",
			objects: []client.Object{
				routerForNode("router-a", nodeName, namespace, 65000),
				routerForNode("router-b", nodeName, namespace, 65001),
			},
			wantErr: "ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)

			cfg, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
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

// ---- buildResult ---------------------------------------------------------

func TestBuildResult(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gateway := net.ParseIP("fd00:10:ff01::1")
	route := mustParseCIDR(t, "::/0")
	netns := "/proc/1234/ns/net"

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: cniVersion100},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}

	tests := []struct {
		name       string
		ipRes      *ipamResult
		wantInts   int
		wantIPs    int
		wantRoutes int
		wantIFace  int // 0 means no Interface field expected
	}{
		{
			name:       "with IPAM config",
			ipRes:      &ipamResult{subnet: subnet, gateway: gateway, routes: []*net.IPNet{route}},
			wantInts:   2,
			wantIPs:    1,
			wantRoutes: 1,
			wantIFace:  1,
		},
		{
			name:       "without IPAM config",
			ipRes:      nil,
			wantInts:   2,
			wantIPs:    0,
			wantRoutes: 0,
			wantIFace:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildResult(
				conf, tt.ipRes,
				"G09-vpc03-vpcAttH", "eth0",
				"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:11",
				1500, 1500,
				netns,
			)

			if result.CNIVersion != cniVersion100 {
				t.Errorf("CNIVersion = %q, want %q", result.CNIVersion, cniVersion100)
			}

			if len(result.Interfaces) != tt.wantInts {
				t.Errorf("Interfaces count = %d, want %d", len(result.Interfaces), tt.wantInts)
				return
			}

			// Host interface (index 0)
			if result.Interfaces[0].Name != "G09-vpc03-vpcAttH" {
				t.Errorf("Interfaces[0].Name = %q, want %q", result.Interfaces[0].Name, "G09-vpc03-vpcAttH")
			}
			if result.Interfaces[0].Mac != "aa:bb:cc:dd:ee:ff" {
				t.Errorf("Interfaces[0].Mac = %q, want %q", result.Interfaces[0].Mac, "aa:bb:cc:dd:ee:ff")
			}
			if result.Interfaces[0].Mtu != 1500 {
				t.Errorf("Interfaces[0].Mtu = %d, want 1500", result.Interfaces[0].Mtu)
			}
			if result.Interfaces[0].Sandbox != "" {
				t.Errorf("Interfaces[0].Sandbox = %q, want empty", result.Interfaces[0].Sandbox)
			}

			// Guest interface (index 1)
			if result.Interfaces[1].Name != "eth0" {
				t.Errorf("Interfaces[1].Name = %q, want %q", result.Interfaces[1].Name, "eth0")
			}
			if result.Interfaces[1].Mac != "aa:bb:cc:dd:ee:11" {
				t.Errorf("Interfaces[1].Mac = %q, want %q", result.Interfaces[1].Mac, "aa:bb:cc:dd:ee:11")
			}
			if result.Interfaces[1].Mtu != 1500 {
				t.Errorf("Interfaces[1].Mtu = %d, want 1500", result.Interfaces[1].Mtu)
			}
			if result.Interfaces[1].Sandbox != netns {
				t.Errorf("Interfaces[1].Sandbox = %q, want %q", result.Interfaces[1].Sandbox, netns)
			}

			if len(result.IPs) != tt.wantIPs {
				t.Errorf("IPs count = %d, want %d", len(result.IPs), tt.wantIPs)
				return
			}

			if tt.wantIPs > 0 {
				if result.IPs[0].Address.String() != subnet.String() {
					t.Errorf("IPs[0].Address = %q, want %q", result.IPs[0].Address, subnet)
				}
				if !result.IPs[0].Gateway.Equal(gateway) {
					t.Errorf("IPs[0].Gateway = %v, want %v", result.IPs[0].Gateway, gateway)
				}
				if tt.wantIFace == 0 {
					if result.IPs[0].Interface != nil {
						t.Errorf("IPs[0].Interface = %v, want nil", *result.IPs[0].Interface)
					}
				} else {
					if result.IPs[0].Interface == nil {
						t.Errorf("IPs[0].Interface = nil, want %d", tt.wantIFace)
					} else if *result.IPs[0].Interface != tt.wantIFace {
						t.Errorf("IPs[0].Interface = %d, want %d", *result.IPs[0].Interface, tt.wantIFace)
					}
				}
				if len(result.Routes) != tt.wantRoutes {
					t.Errorf("Routes count = %d, want %d", len(result.Routes), tt.wantRoutes)
				}
			}
		})
	}
}

// ---- buildTapResult ------------------------------------------------------

func TestBuildTapResult(t *testing.T) {
	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: cniVersion100},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}

	result := buildTapResult(conf, "H0abc123", "aa:bb:cc:dd:ee:ff", 1500)

	if result.CNIVersion != cniVersion100 {
		t.Errorf("CNIVersion = %q, want %q", result.CNIVersion, cniVersion100)
	}

	if len(result.Interfaces) != 1 {
		t.Fatalf("Interfaces count = %d, want 1", len(result.Interfaces))
	}

	if result.Interfaces[0].Name != "H0abc123" {
		t.Errorf("Interfaces[0].Name = %q, want %q", result.Interfaces[0].Name, "H0abc123")
	}
	if result.Interfaces[0].Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Interfaces[0].Mac = %q, want %q", result.Interfaces[0].Mac, "aa:bb:cc:dd:ee:ff")
	}
	if result.Interfaces[0].Mtu != 1500 {
		t.Errorf("Interfaces[0].Mtu = %d, want 1500", result.Interfaces[0].Mtu)
	}
	if result.Interfaces[0].Sandbox != "" {
		t.Errorf("Interfaces[0].Sandbox = %q, want empty", result.Interfaces[0].Sandbox)
	}

	if len(result.IPs) != 0 {
		t.Errorf("IPs count = %d, want 0", len(result.IPs))
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}
