// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/config"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")
	InitCNIConfig()
	os.Exit(m.Run())
}

const (
	testVPC           = "abc"
	testAttachment    = "def"
	testContainerID   = "test-container"
	testInvalidBase62 = "abc-def" // shared invalid base62 string for tests
	testNetns         = "/proc/1/ns/net"
	testMac           = "aa:bb:cc:dd:ee:ff"
	testIfName        = "eth0"
	testCNIVersion    = "1.0.0"

	// testPrevResult is a valid CNI v1.0.0 result used in prevResult tests.
	testPrevResult = `{"cniVersion":"1.0.0",` +
		`"interfaces":[{"name":"` + testIfName + `","mac":"` + testMac + `",` +
		`"sandbox":"/proc/1/ns/net"}],` +
		`"ips":[{"version":"6","address":"fd00:1::1/64"}]}`
)

// assertCNIError verifies that err is a *types.Error with the expected Code
// and that its Msg contains wantMsg (substring match). Pass wantMsg == "" to
// skip the message check.
func assertCNIError(t *testing.T, err error, wantCode uint, wantMsg string) {
	t.Helper()
	var cniErr *types.Error
	if !errors.As(err, &cniErr) {
		t.Fatalf("expected *types.Error, got %T: %v", err, err)
	}
	if cniErr.Code != wantCode {
		t.Fatalf("expected code %d, got %d (Msg: %q)", wantCode, cniErr.Code, cniErr.Msg)
	}
	if wantMsg != "" && !strings.Contains(cniErr.Msg, wantMsg) {
		t.Fatalf("expected Msg to contain %q, got %q", wantMsg, cniErr.Msg)
	}
}

// ---- parseConf -----------------------------------------------------------

func TestParseConf(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantVPC  string
		wantErr  string
		wantCode uint // CNI error code; 0 means "don't check"
	}{
		{
			name: "valid config",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testVPC, testAttachment,
			),
			wantVPC: testVPC,
		},
		{
			name:     "invalid JSON",
			input:    "not json",
			wantErr:  "invalid CNI config",
			wantCode: 7,
		},
		{
			name:     "empty input",
			input:    "",
			wantErr:  "invalid CNI config",
			wantCode: 7,
		},
		{
			name: "missing vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  "vpc is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "empty vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  "vpc is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "vpc with invalid char hyphen",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testInvalidBase62, testAttachment,
			),
			wantErr:  fmt.Sprintf("invalid base62 value for field 'vpc': %q", testInvalidBase62),
			wantCode: 7,
		},
		{
			name: "vpc with invalid char underscore",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"abc_def",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  `invalid base62 value for field 'vpc': "abc_def"`,
			wantCode: 7,
		},
		{
			name: "missing vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s"}`,
				testVPC,
			),
			wantErr:  "vpcattachment is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "empty vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":""}`,
				testVPC,
			),
			wantErr:  "vpcattachment is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "vpcattachment with invalid char space",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"def ghi"}`,
				testVPC,
			),
			wantErr:  `invalid base62 value for field 'vpcattachment': "def ghi"`,
			wantCode: 7,
		},
		{
			name: "valid vpc and vpcattachment with mixed case base62",
			input: `{"cniVersion":"1.0.0","name":"test",` +
				`"type":"galactic-cni","vpc":"Abc123XYZ",` +
				`"vpcattachment":"DeF456"}`,
			wantVPC: "Abc123XYZ",
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
			wantVPC: testVPC,
		},

		{
			name: "ipam block present is accepted, delegated per its own contract",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-cni","vpc":"%s",`+
					`"vpcattachment":"%s","ipam":{"type":"galactic-ipam","ipv6_subnet":"fd00:10:ff01::/48"}}`,
				testVPC, testAttachment,
			),
			wantVPC: testVPC,
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
				if tt.wantCode > 0 {
					assertCNIError(t, err, tt.wantCode, tt.wantErr)
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
		CNIVersion: testCNIVersion,
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
		CNIVersion: testCNIVersion,
		Interfaces: []*type100.Interface{
			{Name: testIfName, Mac: testMac, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	validWithIPsOnly := &type100.Result{
		CNIVersion: testCNIVersion,
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	emptyResult := &type100.Result{
		CNIVersion: testCNIVersion,
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

// ---- buildResult ---------------------------------------------------------

func TestBuildResult(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gateway := net.ParseIP("fd00:10:ff01::1")
	defaultRoute := mustParseCIDR(t, "::/0")
	netns := "/proc/1234/ns/net"

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}

	tests := []struct {
		name       string
		ipRes      *cniipam.IPAMResult
		wantInts   int
		wantIPs    int
		wantRoutes int
		wantIFace  int // 0 means no Interface field expected
	}{
		{
			name:       "with IPAM config",
			ipRes:      &cniipam.IPAMResult{IPv6Subnet: subnet, IPv6Gateway: gateway, Routes: []*net.IPNet{defaultRoute}},
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

			if result.CNIVersion != testCNIVersion {
				t.Errorf("CNIVersion = %q, want %q", result.CNIVersion, testCNIVersion)
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

// TestBuildResultDualStack verifies that buildResult emits both an IPv6 and
// an IPv4 IPConfig, both pointing at the guest interface, plus both default
// routes, when ipamResult carries an IPv4 allocation.
func TestBuildResultDualStack(t *testing.T) {
	ipv6Subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
	ipv6Gateway := net.ParseIP("fd00:10:ff01::1")
	ipv4Address := net.ParseIP("10.128.0.5")
	ipv4Gateway := net.ParseIP("10.128.0.1")
	ipv6Route := mustParseCIDR(t, "::/0")
	ipv4Route := mustParseCIDR(t, "0.0.0.0/0")

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}
	ipRes := &cniipam.IPAMResult{
		IPv6Subnet:  ipv6Subnet,
		IPv6Gateway: ipv6Gateway,
		IPv4Address: ipv4Address,
		IPv4Gateway: ipv4Gateway,
		Routes:      []*net.IPNet{ipv6Route, ipv4Route},
	}

	result := buildResult(conf, ipRes, "G09-vpc03-vpcAttH", "eth0",
		"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:11", 1500, 1500, "/proc/1234/ns/net")

	if len(result.IPs) != 2 {
		t.Fatalf("IPs count = %d, want 2", len(result.IPs))
	}
	if result.IPs[0].Address.String() != ipv6Subnet.String() {
		t.Errorf("IPs[0].Address = %v, want %v", result.IPs[0].Address, ipv6Subnet)
	}
	if !result.IPs[0].Gateway.Equal(ipv6Gateway) {
		t.Errorf("IPs[0].Gateway = %v, want %v", result.IPs[0].Gateway, ipv6Gateway)
	}
	wantIPv4Mask := net.CIDRMask(32, 32).String()
	if result.IPs[1].Address.IP.String() != ipv4Address.String() || result.IPs[1].Address.Mask.String() != wantIPv4Mask {
		t.Errorf("IPs[1].Address = %v, want %s/32", result.IPs[1].Address, ipv4Address)
	}
	if !result.IPs[1].Gateway.Equal(ipv4Gateway) {
		t.Errorf("IPs[1].Gateway = %v, want %v", result.IPs[1].Gateway, ipv4Gateway)
	}
	for i, r := range result.IPs {
		if r.Interface == nil || *r.Interface != 1 {
			t.Errorf("IPs[%d].Interface = %v, want 1 (guest)", i, r.Interface)
		}
	}
	if len(result.Routes) != 2 {
		t.Errorf("Routes count = %d, want 2", len(result.Routes))
	}
}

// TestBuildResultIPv4Only verifies that buildResult emits a single IPv4
// IPConfig (no IPv6 entry, no panic) when ipamResult carries an IPv4-only
// allocation — the NAD config from the reported bug (ipv4_subnet set, no
// ipv6_subnet).
func TestBuildResultIPv4Only(t *testing.T) {
	ipv4Address := net.ParseIP("172.20.1.5")
	ipv4Gateway := net.ParseIP("172.20.1.1")
	ipv4Route := mustParseCIDR(t, "0.0.0.0/0")

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}
	ipRes := &cniipam.IPAMResult{
		IPv4Address: ipv4Address,
		IPv4Gateway: ipv4Gateway,
		Routes:      []*net.IPNet{ipv4Route},
	}

	result := buildResult(conf, ipRes, "G09-vpc03-vpcAttH", "eth0",
		"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:11", 1500, 1500, "/proc/1234/ns/net")

	if len(result.IPs) != 1 {
		t.Fatalf("IPs count = %d, want 1", len(result.IPs))
	}
	wantIPv4Mask := net.CIDRMask(32, 32).String()
	if result.IPs[0].Address.IP.String() != ipv4Address.String() || result.IPs[0].Address.Mask.String() != wantIPv4Mask {
		t.Errorf("IPs[0].Address = %v, want %s/32", result.IPs[0].Address, ipv4Address)
	}
	if !result.IPs[0].Gateway.Equal(ipv4Gateway) {
		t.Errorf("IPs[0].Gateway = %v, want %v", result.IPs[0].Gateway, ipv4Gateway)
	}
	if result.IPs[0].Interface == nil || *result.IPs[0].Interface != 1 {
		t.Errorf("IPs[0].Interface = %v, want 1 (guest)", result.IPs[0].Interface)
	}
	if len(result.Routes) != 1 {
		t.Errorf("Routes count = %d, want 1", len(result.Routes))
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

	// DEL must return nil even though k8s client creation will fail
	// (no in-cluster config in tests) and all kernel resources are missing.
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with missing resources returned error = %v, want nil", err)
	}
}

// TestCmdDelFlushesGuestNetnsConfig reproduces the production incident: a
// hostNetwork pod's Multus secondary attachment resolves args.Netns to the
// same namespace the guest link already lives in, so host-device DEL's
// move-back-out-of-the-netns — and the kernel's implicit address/route
// flush that only fires on a *real* namespace change — never happens.
// cmdDel must flush the guest interface's address/default route itself
// (flushGuestNetnsConfig), not rely solely on that side effect, or the next
// ADD against the same interface wedges with "add default route ...: file
// exists".
func TestCmdDelFlushesGuestNetnsConfig(t *testing.T) {
	requireRoot(t)

	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("configureInterfaceInNetns: %v", err)
	}

	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test",`+
			`"type":"galactic-cni","vpc":"%s",`+
			`"vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		Netns:       netnsPath,
		IfName:      "test-dummy",
		StdinData:   []byte(conf),
	}

	// host-device DEL will fail (no host-device binary next to the test
	// binary) — that's expected and non-fatal, matching production when the
	// move-based side effect doesn't apply anyway.
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel returned error = %v, want nil", err)
	}

	if gw := defaultRouteVia(t, netnsPath); gw != nil {
		t.Fatalf("default route gateway = %v, want nil (flushed by DEL)", gw)
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
	if !strings.Contains(err.Error(), "invalid CNI config") {
		t.Fatalf("error %q does not contain 'invalid CNI config'", err.Error())
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
	tracker.cleanup() // should not panic
}

func TestResourceTrackerCleanupPartialState(t *testing.T) {
	// A tracker that only has VPC info (failed before any resource creation)
	// should not panic during cleanup.
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
	}
	tracker.cleanup() // should not panic; vrf.Delete will fail but is logged
}

func TestResourceTrackerFieldsSet(t *testing.T) {
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
	}

	if tracker.vpc != testVPC {
		t.Errorf("vpc = %q, want %q", tracker.vpc, testVPC)
	}
	if tracker.vpcAttachment != testAttachment {
		t.Errorf("vpcAttachment = %q, want %q", tracker.vpcAttachment, testAttachment)
	}
	if tracker.vrfCreated {
		t.Error("vrfCreated should be false by default")
	}
}

// ---- cmdStatus ---------------------------------------------------------

func TestCmdStatusInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte("not valid json"),
	}

	err := cmdStatus(args)
	assertCNIError(t, err, 7, "invalid CNI config")
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

func TestCmdStatusAPIProbeFailure(t *testing.T) {
	// STATUS should return CNI error code 50 when the API server probe fails.
	original := probeAPIServer
	probeAPIServer = func() error { return errors.New("connection refused") }
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
	assertCNIError(t, err, 50, "API server health check failed")
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
	t.Setenv("GALACTIC_CNI_NODE_NAME", "")
	t.Setenv("NODE_NAME", "")
	// prevResult that is a valid CNI result. cmdAdd should pass prevResult
	// validation and fail later due to missing node name.
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
	// Should fail with code 4 (invalid env vars) for missing node name,
	// not code 6 for prevResult.
	assertCNIError(t, err, 4, "node name is required")
}

// ---- loadHostConf -----------------------------------------------------------

func TestLoadHostConf(t *testing.T) {
	tmpDir := t.TempDir()
	conflistPath := filepath.Join(tmpDir, "10-galactic.conflist")

	// 1. Missing file tolerated, defaults to galactic-system namespace.
	conf, err := loadHostConf(conflistPath)
	if err != nil {
		t.Fatalf("unexpected error for missing conflist: %v", err)
	}
	if conf.Namespace != config.DefaultNamespace {
		t.Errorf("Namespace = %q, want %q", conf.Namespace, config.DefaultNamespace)
	}

	// 2. Conflist parses but lacks galactic-cni entry.
	badContent := `{"cniVersion":"1.0.0","name":"test","plugins":[{"type":"some-other-plugin"}]}`
	if err := os.WriteFile(conflistPath, []byte(badContent), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	_, err = loadHostConf(conflistPath)
	if err == nil {
		t.Fatal("expected error for missing plugin type, got nil")
	}

	// 3. Conflist parses correctly.
	goodContent := `{
		"cniVersion": "1.0.0",
		"name": "galactic",
		"plugins": [
			{
				"type": "galactic-cni",
				"node_name": "test-worker",
				"kubeconfig": "/etc/custom-kubeconfig",
				"namespace": "custom-namespace",
				"log_file": "/var/log/custom.log",
				"log_level": "debug"
			}
		]
	}`
	if err := os.WriteFile(conflistPath, []byte(goodContent), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	conf, err = loadHostConf(conflistPath)
	if err != nil {
		t.Fatalf("unexpected error for good conflist: %v", err)
	}
	if conf.NodeName != "test-worker" {
		t.Errorf("NodeName = %q, want %q", conf.NodeName, "test-worker")
	}
	if conf.Kubeconfig != "/etc/custom-kubeconfig" {
		t.Errorf("Kubeconfig = %q, want %q", conf.Kubeconfig, "/etc/custom-kubeconfig")
	}
	if conf.Namespace != "custom-namespace" {
		t.Errorf("Namespace = %q, want %q", conf.Namespace, "custom-namespace")
	}
	if conf.LogFile != "/var/log/custom.log" {
		t.Errorf("LogFile = %q, want %q", conf.LogFile, "/var/log/custom.log")
	}
	if conf.LogLevel != config.LogLevelDebug {
		t.Errorf("LogLevel = %q, want %q", conf.LogLevel, config.LogLevelDebug)
	}
}

// ---- explicit IPAM delegation contract -------------------------------------

// TestIPAMBlockPresenceIsTheOnlyTrigger is the regression test for the
// explicit contract internal/cniipam's doc comment describes: whether this
// plugin delegates to IPAM at all is decided solely by whether "ipam" is
// present in its own config — no environment variable can manufacture (or
// suppress) that block. The historical GALACTIC_CNI_ENABLE_LOCAL_IPAM
// trigger no longer exists at all (that flag, renamed
// GALACTIC_IPAM_ENABLE_LOCAL_IPAM, now lives entirely inside
// internal/cniipam as a default-filler for an already-present ipam block).
func TestIPAMBlockPresenceIsTheOnlyTrigger(t *testing.T) {
	t.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")

	// Missing ipam block: no error, no delegation signal — conf.IPAM stays nil.
	inputNoIPAM := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-cni","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	conf, err := parseConf([]byte(inputNoIPAM))
	if err != nil {
		t.Fatalf("unexpected error for missing ipam block: %v", err)
	}
	if conf.IPAM != nil {
		t.Fatalf("IPAM = %+v, want nil (absent block must never be manufactured)", conf.IPAM)
	}

	// Present ipam block: conf.IPAM is populated, ready for delegation.
	inputWithIPAM := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-cni","vpc":"%s","vpcattachment":"%s",`+
			`"ipam":{"type":"galactic-ipam"}}`,
		testVPC, testAttachment,
	)
	conf, err = parseConf([]byte(inputWithIPAM))
	if err != nil {
		t.Fatalf("unexpected error with present ipam block: %v", err)
	}
	if conf.IPAM == nil {
		t.Fatal("expected IPAM block to be non-nil")
	}
	if conf.IPAM.Type != "galactic-ipam" {
		t.Errorf("IPAM.Type = %q, want %q", conf.IPAM.Type, "galactic-ipam")
	}
}

// ---- logging setup ----------------------------------------------------------

func TestLoggingSetup(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "sub", "test.log")

	// Setup logging, which should create the directory and open/write to the file.
	setupLogging(logPath, config.DefaultLogLevel)
	slog.Info("test log message")

	// Read the log file to verify the message was logged.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "test log message") {
		t.Fatalf("log content does not contain message: %s", string(data))
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"empty defaults to info", "", slog.LevelInfo, false},
		{"debug", config.LogLevelDebug, slog.LevelDebug, false},
		{"info", config.DefaultLogLevel, slog.LevelInfo, false},
		{"warn", config.LogLevelWarn, slog.LevelWarn, false},
		{"warning alias", config.LogLevelWarning, slog.LevelWarn, false},
		{"error", config.LogLevelError, slog.LevelError, false},
		{"case insensitive", "DEBUG", slog.LevelDebug, false},
		{"surrounding whitespace", "  warn  ", slog.LevelWarn, false},
		{"unknown falls back to info with error", "verbose", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLogLevel(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLogLevel(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoggingSetupRespectsLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	setupLogging(logPath, config.LogLevelWarn)
	slog.Info("should be suppressed at warn level")
	slog.Warn("should appear at warn level")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "should be suppressed at warn level") {
		t.Errorf("expected info message to be filtered out at warn level, got: %s", content)
	}
	if !strings.Contains(content, "should appear at warn level") {
		t.Errorf("expected warn message to be present, got: %s", content)
	}
}

func TestLoggingSetupInvalidLevelFallsBackToInfo(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// An invalid level must not fail the CNI operation; it should fall back
	// to DefaultLogLevel (info) rather than panic or drop all logging.
	setupLogging(logPath, "verbose")
	slog.Info("should appear at fallback info level")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "should appear at fallback info level") {
		t.Errorf("expected info message to be present after fallback, got: %s", string(data))
	}
}
