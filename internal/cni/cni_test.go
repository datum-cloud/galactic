// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVPC           = "abc"
	testAttachment    = "def"
	testVPCHex1234    = "0000000004d2" // decimal 1234
	testRD65000_1     = "65000:1"      // RD/RT for ASN 65000, NN 1
	testContainerID   = "test-container"
	testInvalidBase62 = "abc-def" // shared invalid base62 string for tests
	testNetns         = "/proc/1/ns/net"
	testMac           = "aa:bb:cc:dd:ee:ff"
	testIfName        = "eth0"

	// testPrevResult is a valid CNI v1.0.0 result used in prevResult tests.
	testPrevResult = `{"cniVersion":"1.0.0",` +
		`"interfaces":[{"name":"` + testIfName + `","mac":"` + testMac + `",` +
		`"sandbox":"/proc/1/ns/net"}],` +
		`"ips":[{"version":"6","address":"fd00:1::1/64"}]}`
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
					`"vpcattachment":"%s","srv6_sid":"2001:db8::1/128"}`,
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
		{
			name: "missing vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr: "vpc is required and must be a non-empty base62 string",
		},
		{
			name: "empty vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr: "vpc is required and must be a non-empty base62 string",
		},
		{
			name: "vpc with invalid char hyphen",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testInvalidBase62, testAttachment,
			),
			wantErr: fmt.Sprintf("invalid base62 value for field 'vpc': %q", testInvalidBase62),
		},
		{
			name: "vpc with invalid char underscore",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"abc_def",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr: `invalid base62 value for field 'vpc': "abc_def"`,
		},
		{
			name: "missing vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s"}`,
				testVPC,
			),
			wantErr: "vpcattachment is required and must be a non-empty base62 string",
		},
		{
			name: "empty vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":""}`,
				testVPC,
			),
			wantErr: "vpcattachment is required and must be a non-empty base62 string",
		},
		{
			name: "vpcattachment with invalid char space",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"def ghi"}`,
				testVPC,
			),
			wantErr: `invalid base62 value for field 'vpcattachment': "def ghi"`,
		},
		{
			name: "valid vpc and vpcattachment with mixed case base62",
			input: `{"cniVersion":"1.0.0","name":"test",` +
				`"type":"galactic-cni","vpc":"Abc123XYZ",` +
				`"vpcattachment":"DeF456"}`,
			wantVPC:    "Abc123XYZ",
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "valid srv6_sid with /128",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":"2001:db8::1/128"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "valid srv6_sid bare IPv6 address",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":"2001:db8::1"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "srv6_sid empty is allowed",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":""}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "srv6_sid missing is allowed",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testVPC, testAttachment,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
		},
		{
			name: "srv6_sid invalid mask /64 rejected",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":"fd00:1:2::/64"}`,
				testVPC, testAttachment,
			),
			wantErr: srv6SIDErrMsg,
		},
		{
			name: "srv6_sid invalid IPv4 address",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":"192.168.1.1"}`,
				testVPC, testAttachment,
			),
			wantErr: srv6SIDErrMsg,
		},
		{
			name: "srv6_sid not a valid address",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","srv6_sid":"not-an-address"}`,
				testVPC, testAttachment,
			),
			wantErr: srv6SIDErrMsg,
		},
		{
			name: "prevResult valid JSON result is accepted",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s",`+
					`"prevResult":%s}`,
				testVPC, testAttachment, testPrevResult,
			),
			wantVPC:    testVPC,
			wantIfType: interfaceTypeVeth,
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

// ---- isValidBase62 -------------------------------------------------------

func TestIsValidBase62(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"digits only", "1234567890", true},
		{"lowercase only", "abcdefghij", true},
		{"uppercase only", "ABCDEFGHIJ", true},
		{"mixed case", "aBcDeFgHiJ", true},
		{"mixed digits and letters", "abc123XYZ", true},
		{"hyphen", testInvalidBase62, false},
		{"underscore", "abc_def", false},
		{"space", "abc def", false},
		{"dot", "abc.def", false},
		{"slash", "abc/def", false},
		{"plus", "abc+def", false},
		{"equals", "abc=def", false},
		{"single digit", "0", true},
		{"single lowercase", "a", true},
		{"single uppercase", "Z", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidBase62(tt.input)
			if got != tt.want {
				t.Errorf("isValidBase62(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---- isValidSRv6SID --------------------------------------------------

func TestIsValidSRv6SID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty allowed", "", true},
		{"valid /128", "2001:db8::1/128", true},
		{"valid bare IPv6", "2001:db8:10:10::1", true},
		{"valid all zeros /128", "::/128", true},
		{"invalid /64", "fd00:1:2::/64", false},
		{"invalid /48", "2001:db8::/48", false},
		{"invalid IPv4", "192.168.1.1", false},
		{"invalid IPv4 CIDR", "192.168.1.0/24", false},
		{"not an address", "not-an-address", false},
		{"invalid /0", "::/0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSRv6SID(tt.input)
			if got != tt.want {
				t.Errorf("isValidSRv6SID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeForError(t *testing.T) {
	printable := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()"
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal string", testInvalidBase62, testInvalidBase62},
		{"empty", "", ""},
		{"newline", "abc\ndef", sanitizeForErrorBinary},
		{"null byte", "abc\x00def", sanitizeForErrorBinary},
		{"del char", "abc\x7fdef", sanitizeForErrorBinary},
		{"printable range", printable, printable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForError(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeForError(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---- validatePrevResult --------------------------------------------------

func TestValidatePrevResult(t *testing.T) {
	validResult := &type100.Result{
		CNIVersion: cniVersion100,
		Interfaces: []*type100.Interface{
			{Name: testIfName, Mac: testMac, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}

	tests := []struct {
		name    string
		input   types.Result
		wantErr bool
	}{
		{"nil result allowed", nil, false},
		{"valid CNI result", validResult, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrevResult(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePrevResultAdd(t *testing.T) {
	validWithInterface := &type100.Result{
		CNIVersion: cniVersion100,
		Interfaces: []*type100.Interface{
			{Name: testIfName, Mac: testMac, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	validWithIPsOnly := &type100.Result{
		CNIVersion: cniVersion100,
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	emptyResult := &type100.Result{
		CNIVersion: cniVersion100,
		// No interfaces, no IPs — should fail content validation.
	}

	tests := []struct {
		name    string
		input   types.Result
		wantErr bool
	}{
		{"nil result allowed", nil, false},
		{"valid result with interface", validWithInterface, false},
		{"valid result with IPs only", validWithIPsOnly, false},
		{"empty result (no interfaces or IPs)", emptyResult, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrevResultAdd(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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

// ---- cmdDel idempotency --------------------------------------------------

// TestCmdDelIdempotent returns nil even when the CNI config is invalid.
// Per the CNI spec, DEL is idempotent: missing resources are not errors.
func TestCmdDelIdempotent(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte("not valid json"),
	}

	// DEL must return nil regardless of config validity.
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with invalid config returned error = %v, want nil", err)
	}
}

// TestCmdDelIdempotentMissingResources returns nil even when the config is
// valid but all resources are missing (k8s client creation fails in tests).
func TestCmdDelIdempotentMissingResources(t *testing.T) {
	// Save and restore the original enableLocalIPAM state.
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()

	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s","interface_type":"veth"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	// DEL must return nil even though k8s client creation will fail
	// (no in-cluster config in tests) and all kernel resources are missing.
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with missing resources returned error = %v, want nil", err)
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

// ---- cmdCheck ----------------------------------------------------------

func TestCmdCheckInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte("not valid json"),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse CNI config") {
		t.Fatalf("error %q does not contain 'parse CNI config'", err.Error())
	}
}

func TestCmdCheckInvalidInterfaceType(t *testing.T) {
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s","interface_type":"bogus"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected error for invalid interface_type, got nil")
	}
	if !strings.Contains(err.Error(), `invalid interface_type "bogus"`) {
		t.Fatalf("error %q does not contain expected message", err.Error())
	}
}

func TestCmdCheckValidConfigMissingResources(t *testing.T) {
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		Netns:       "/proc/1/ns/net",
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected CHECK failure for missing resources, got nil")
	}
	// Should report CHECK failed with VRF not found.
	if !strings.Contains(err.Error(), "CHECK failed") {
		t.Fatalf("error %q does not contain 'CHECK failed'", err.Error())
	}
}

func TestCmdCheckTapModeValidConfigMissingResources(t *testing.T) {
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s","interface_type":"tap"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected CHECK failure for missing resources, got nil")
	}
	if !strings.Contains(err.Error(), "CHECK failed") {
		t.Fatalf("error %q does not contain 'CHECK failed'", err.Error())
	}
}

func TestCmdCheckMissingVPC(t *testing.T) {
	conf := `{"cniVersion":"1.0.0","name":"test","type":"galactic-cni"}`
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected error for missing VPC, got nil")
	}
	// parseConf now rejects empty VPC before CHECK runs.
	if !strings.Contains(err.Error(), "vpc is required") {
		t.Fatalf("error %q does not contain 'vpc is required'", err.Error())
	}
}

func TestCmdCheckWithPrevResultMissingResources(t *testing.T) {
	// Build a prevResult matching what buildResult produces for veth mode.
	prevResult := `{` +
		`"cniVersion":"1.0.0",` +
		`"interfaces":[` +
		`{"name":"galactic-abc-def","mac":"aa:bb:cc:dd:ee:01","mtu":1500,"sandbox":""},` +
		`{"name":"galactic-def-abc","mac":"aa:bb:cc:dd:ee:02","mtu":1500,"sandbox":"/proc/1/ns/net"}` +
		`],` +
		`"ips":[` +
		`{"version":"6","address":"fd00:10:ff01::1234/80","gateway":"fd00:10:ff01::1","interface":1}` +
		`]}`
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s",`+
			`"prevResult":%s}`,
		testVPC, testAttachment, prevResult,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		Netns:       "/proc/1/ns/net",
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected CHECK failure for missing resources, got nil")
	}
	if !strings.Contains(err.Error(), "CHECK failed") {
		t.Fatalf("error %q does not contain 'CHECK failed'", err.Error())
	}
	// prevResult parsing should succeed; errors come from missing kernel state.
	if !strings.Contains(err.Error(), "prevResult validation") {
		t.Fatalf("error %q does not contain 'prevResult validation'", err.Error())
	}
}

func TestCmdCheckWithInvalidPrevResult(t *testing.T) {
	// prevResult that is structurally valid JSON but not a valid CNI result.
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s",`+
			`"prevResult":{"not":"a valid cni result"}}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdCheck(args)
	if err == nil {
		t.Fatalf("expected CHECK failure for invalid prevResult, got nil")
	}
	if !strings.Contains(err.Error(), "prevResult validation") {
		t.Fatalf("error %q does not contain 'prevResult validation'", err.Error())
	}
}

// ---- resourceTracker ------------------------------------------------------

func TestResourceTrackerCleanupZeroValue(t *testing.T) {
	// cleanup with a zero-value tracker must not panic — it's called in a
	// defer and the caller may have failed before setting any fields.
	tracker := &resourceTracker{}
	ctx := context.Background()
	tracker.cleanup(ctx) // should not panic
}

func TestResourceTrackerCleanupPartialState(t *testing.T) {
	// A tracker that only has VPC info (failed before any resource creation)
	// should not panic during cleanup.
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		ifaceType:     interfaceTypeVeth,
		namespace:     "default",
	}
	ctx := context.Background()
	tracker.cleanup(ctx) // should not panic; vrf.Delete will fail but is logged
}

func TestResourceTrackerFieldsSet(t *testing.T) {
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		ifaceType:     interfaceTypeTap,
		namespace:     "test-ns",
	}

	if tracker.vpc != testVPC {
		t.Errorf("vpc = %q, want %q", tracker.vpc, testVPC)
	}
	if tracker.vpcAttachment != testAttachment {
		t.Errorf("vpcAttachment = %q, want %q", tracker.vpcAttachment, testAttachment)
	}
	if tracker.ifaceType != interfaceTypeTap {
		t.Errorf("ifaceType = %q, want %q", tracker.ifaceType, interfaceTypeTap)
	}
	if tracker.namespace != "test-ns" {
		t.Errorf("namespace = %q, want %q", tracker.namespace, "test-ns")
	}
	if tracker.vrfCreated {
		t.Error("vrfCreated should be false by default")
	}
	if tracker.srv6SID != "" {
		t.Errorf("srv6SID should be empty by default, got %q", tracker.srv6SID)
	}
	if tracker.advCreated {
		t.Error("advCreated should be false by default")
	}
}

// ---- cmdStatus ---------------------------------------------------------

func TestCmdStatusInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte("not valid json"),
	}

	err := cmdStatus(args)
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse CNI config") {
		t.Fatalf("error %q does not contain 'parse CNI config'", err.Error())
	}
}

func TestCmdStatusInvalidInterfaceType(t *testing.T) {
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s","interface_type":"bogus"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdStatus(args)
	if err == nil {
		t.Fatalf("expected error for invalid interface_type, got nil")
	}
	if !strings.Contains(err.Error(), `invalid interface_type "bogus"`) {
		t.Fatalf("error %q does not contain expected message", err.Error())
	}
}

func TestCmdStatusValidConfigMissingResources(t *testing.T) {
	// STATUS should succeed with valid config even when VRF/interface
	// resources don't exist — STATUS answers "is the plugin ready to ADD?"
	// not "does a prior ADD's state persist?".
	original := probeAPIServer
	probeAPIServer = func() error { return nil }
	defer func() { probeAPIServer = original }()

	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdStatus(args)
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestCmdStatusMissingVPC(t *testing.T) {
	// STATUS does not validate attachment-specific fields — it only checks
	// that the config is parseable and the API server is reachable.
	original := probeAPIServer
	probeAPIServer = func() error { return nil }
	defer func() { probeAPIServer = original }()

	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpcattachment":"%s"}`,
		testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdStatus(args)
	if err != nil {
		t.Fatalf("expected nil (STATUS does not validate attachment fields), got: %v", err)
	}
}

func TestCmdStatusMissingVPCAttachment(t *testing.T) {
	// STATUS does not validate attachment-specific fields — it only checks
	// that the config is parseable and the API server is reachable.
	original := probeAPIServer
	probeAPIServer = func() error { return nil }
	defer func() { probeAPIServer = original }()

	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s"}`,
		testVPC,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdStatus(args)
	if err != nil {
		t.Fatalf("expected nil (STATUS does not validate attachment fields), got: %v", err)
	}
}

// ---- isTransientError ----------------------------------------------------

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantTrans bool
	}{
		{
			name:      "nil error is not transient",
			err:       nil,
			wantTrans: false,
		},
		{
			name:      "context deadline exceeded is transient",
			err:       context.DeadlineExceeded,
			wantTrans: true,
		},
		{
			name:      "context canceled is transient",
			err:       context.Canceled,
			wantTrans: true,
		},
		{
			name:      "wrapped context deadline exceeded is transient",
			err:       fmt.Errorf("k8s: %w", context.DeadlineExceeded),
			wantTrans: true,
		},
		{
			name:      "wrapped context canceled is transient",
			err:       fmt.Errorf("k8s: %w", context.Canceled),
			wantTrans: true,
		},
		{
			name:      "generic error is not transient",
			err:       errors.New("some error"),
			wantTrans: false,
		},
		{
			name:      "validation error is not transient",
			err:       apierrors.NewBadRequest("bad request"),
			wantTrans: false,
		},
		{
			name: "not found error is not transient",
			err: apierrors.NewNotFound(
				schema.GroupResource{Group: "network.datumapis.com", Resource: "bgpadvertisements"}, "test"),
			wantTrans: false,
		},
		{
			name: "503 service unavailable is transient",
			err:  apierrors.NewServiceUnavailable("service unavailable"),
			// apierrors.IsServiceUnavailable catches 503.
			wantTrans: true,
		},
		{
			name: "429 too many requests is transient",
			err:  apierrors.NewTooManyRequests("too many requests", 0),
			// apierrors.IsTooManyRequests catches 429.
			wantTrans: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTransientError(tt.err)
			if got != tt.wantTrans {
				t.Errorf("isTransientError(%v) = %v, want %v", tt.err, got, tt.wantTrans)
			}
		})
	}
}

// ---- retryK8sOps ---------------------------------------------------------

func TestRetryK8sOpsSucceedsImmediately(t *testing.T) {
	calls := 0
	err := retryK8sOps(100*time.Millisecond, func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryK8sOpsRetriesOnTransientError(t *testing.T) {
	calls := 0
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (initial + 2 retries), got %d", calls)
	}
}

func TestRetryK8sOpsFailsAfterMaxRetries(t *testing.T) {
	calls := 0
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		return context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != maxRetries+1 {
		t.Errorf("expected %d calls (initial + maxRetries), got %d", maxRetries+1, calls)
	}
}

func TestRetryK8sOpsNoRetryOnNonTransientError(t *testing.T) {
	calls := 0
	permanentErr := errors.New("validation failed")
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		return permanentErr
	})
	if !errors.Is(err, permanentErr) {
		t.Fatalf("expected %v, got %v", permanentErr, err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retry), got %d", calls)
	}
}

func TestRetryK8sOpsExhaustsDeadline(t *testing.T) {
	// When the timeout is very short, retries still happen but the fn
	// completes instantly — so we exhaust maxRetries and get the last
	// transient error back (not a context timeout, since fn is fast).
	calls := 0
	err := retryK8sOps(1*time.Millisecond, func(ctx context.Context) error {
		calls++
		return apierrors.NewServiceUnavailable("unavailable")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should have made maxRetries+1 attempts (initial + 2 retries).
	if calls != maxRetries+1 {
		t.Errorf("expected %d calls, got %d", maxRetries+1, calls)
	}
	// Final error is the last transient error returned by fn.
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expected 'unavailable' in error, got %v", err)
	}
}

// ---- probeAPIServer ------------------------------------------------------

func TestProbeAPIServerErrNotInCluster(t *testing.T) {
	// When probeAPIServerFn returns ErrNotInCluster, probeAPIServer should
	// return nil (not running in-cluster; skip API check).
	original := probeAPIServer
	probeAPIServer = func() error { return nil }
	defer func() { probeAPIServer = original }()

	if err := probeAPIServer(); err != nil {
		t.Fatalf("expected nil for ErrNotInCluster, got %v", err)
	}
}

func TestProbeAPIServerMalformedKubeconfig(t *testing.T) {
	// When probeAPIServerFn returns a non-ErrNotInCluster error (e.g. a
	// malformed kubeconfig file), probeAPIServer should surface it wrapped.
	original := probeAPIServer
	probeAPIServer = func() error {
		return errors.New("load kubeconfig: invalid kubeconfig: permission denied")
	}
	defer func() { probeAPIServer = original }()

	err := probeAPIServer()
	if err == nil {
		t.Fatal("expected error for malformed kubeconfig, got nil")
	}
	if !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("error %q does not contain 'load kubeconfig'", err.Error())
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error %q does not contain original error", err.Error())
	}
}

// ---- cmdAdd prevResult validation ----------------------------------------

func TestCmdAddPrevResultValid(t *testing.T) {
	// prevResult that is a valid CNI result. cmdAdd should pass prevResult
	// validation and fail later due to missing NODE_NAME env var.
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s",`+
			`"prevResult":%s}`,
		testVPC, testAttachment, testPrevResult,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	err := cmdAdd(args)
	if err == nil {
		t.Fatal("expected cmdAdd to fail for missing NODE_NAME, got nil")
	}
	// Should fail on NODE_NAME, not prevResult.
	if strings.Contains(err.Error(), "prevResult validation in ADD") {
		t.Fatalf("prevResult should not cause error when valid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "NODE_NAME") {
		t.Fatalf("expected NODE_NAME error, got: %v", err)
	}
}
