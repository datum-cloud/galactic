// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/cnimaster"
)

const (
	testVPC           = "abc"
	testAttachment    = "def"
	testContainerID   = "test-container"
	testInvalidBase62 = "abc-def"
	testCNIVersion    = "1.0.0"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")
	InitCNIConfig()
	os.Exit(m.Run())
}

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

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

// movedKeyConf builds an otherwise-valid galactic-tap config carrying
// the supplied raw JSON member(s) at the top level, for the addressing keys
// that belong inside the "ipam" block.
func movedKeyConf(members string) string {
	return fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s",%s}`,
		testVPC, testAttachment, members,
	)
}

// ---- parseConf -----------------------------------------------------------

func TestParseConf(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantVPC  string
		wantErr  string
		wantCode uint
	}{
		{
			name: "valid config",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s"}`,
				testVPC, testAttachment,
			),
			wantVPC: testVPC,
		},
		{name: "invalid JSON", input: "not json", wantErr: "invalid CNI config", wantCode: 7},
		{
			name: "missing vpc",
			input: fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpcattachment":"%s"}`,
				testAttachment),
			wantErr:  "vpc is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "vpc with invalid char",
			input: fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s"}`,
				testInvalidBase62, testAttachment),
			wantErr:  fmt.Sprintf("invalid base62 value for field 'vpc': %q", testInvalidBase62),
			wantCode: 7,
		},
		{
			name:     "top-level ipv6_subnet is rejected",
			input:    movedKeyConf(`"ipv6_subnet":"fd00:10:ff01::/48"`),
			wantErr:  "addressing field 'ipv6_subnet' belongs inside the 'ipam' block",
			wantCode: 7,
		},
		{
			name:     "top-level ipv4_subnet is rejected",
			input:    movedKeyConf(`"ipv4_subnet":"172.20.1.0/24"`),
			wantErr:  "addressing field 'ipv4_subnet' belongs inside the 'ipam' block",
			wantCode: 7,
		},
		{
			name:     "top-level address_families is rejected",
			input:    movedKeyConf(`"address_families":["ipv6"]`),
			wantErr:  "addressing field 'address_families' belongs inside the 'ipam' block",
			wantCode: 7,
		},
		{
			name:     "top-level static_ip is rejected",
			input:    movedKeyConf(`"static_ip":"fd00::1234"`),
			wantErr:  "addressing field 'static_ip' belongs inside the 'ipam' block",
			wantCode: 7,
		},
		{
			name: "every moved key is named at once",
			input: movedKeyConf(`"ipv6_subnet":"fd00::/48","ipv4_subnet":"172.20.1.0/24",` +
				`"address_families":["ipv6"],"static_ip":"fd00::1"`),
			wantErr: "addressing fields 'ipv6_subnet', 'ipv4_subnet', 'address_families', " +
				"'static_ip' belong inside the 'ipam' block",
			wantCode: 7,
		},
		{
			name: "same keys inside the ipam block still parse",
			input: movedKeyConf(`"ipam":{"type":"galactic-ipam","ipv6_subnet":"fd00:10:ff01::/48",` +
				`"ipv4_subnet":"172.20.1.0/24","address_families":["ipv6","ipv4"],"static_ip":"fd00::1234"}`),
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

// ---- buildTapResult ------------------------------------------------------

func TestBuildTapResult(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gateway := net.ParseIP("fd00:10:ff01::1")
	defaultRoute := mustParseCIDR(t, "::/0")

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}

	tests := []struct {
		name       string
		ipRes      *cniipam.IPAMResult
		wantIPs    int
		wantRoutes int
	}{
		{
			name:       "with IPAM config",
			ipRes:      &cniipam.IPAMResult{IPv6Subnet: subnet, IPv6Gateway: gateway, Routes: []*net.IPNet{defaultRoute}},
			wantIPs:    1,
			wantRoutes: 1,
		},
		{name: "without IPAM config", ipRes: nil, wantIPs: 0, wantRoutes: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTapResult(conf, tt.ipRes, "H0abc123", "aa:bb:cc:dd:ee:ff", 1500)

			if result.CNIVersion != testCNIVersion {
				t.Errorf("CNIVersion = %q, want %q", result.CNIVersion, testCNIVersion)
			}
			if len(result.Interfaces) != 1 {
				t.Fatalf("Interfaces count = %d, want 1", len(result.Interfaces))
			}
			if result.Interfaces[0].Name != "H0abc123" {
				t.Errorf("Interfaces[0].Name = %q, want %q", result.Interfaces[0].Name, "H0abc123")
			}
			if result.Interfaces[0].Sandbox != "" {
				t.Errorf("Interfaces[0].Sandbox = %q, want empty", result.Interfaces[0].Sandbox)
			}
			if len(result.IPs) != tt.wantIPs {
				t.Errorf("IPs count = %d, want %d", len(result.IPs), tt.wantIPs)
			}
			if tt.wantIPs > 0 {
				if result.IPs[0].Interface == nil || *result.IPs[0].Interface != 0 {
					t.Errorf("IPs[0].Interface = %v, want 0", result.IPs[0].Interface)
				}
			}
			if len(result.Routes) != tt.wantRoutes {
				t.Errorf("Routes count = %d, want %d", len(result.Routes), tt.wantRoutes)
			}
		})
	}
}

// TestBuildTapResultIPv4Mask verifies that buildTapResult reports the IPv4
// address with a /25 mask (matching the host gateway mask
// cnibgp.ConfigureHostGateway installs on the tap interface), not the /32
// used for veth.
func TestBuildTapResultIPv4Mask(t *testing.T) {
	ipv4Address := net.ParseIP("172.20.1.5")
	ipv4Gateway := net.ParseIP("172.20.1.1")
	ipv4Route := mustParseCIDR(t, "0.0.0.0/0")

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}
	ipRes := &cniipam.IPAMResult{IPv4Address: ipv4Address, IPv4Gateway: ipv4Gateway, Routes: []*net.IPNet{ipv4Route}}

	result := buildTapResult(conf, ipRes, "H0abc123", "aa:bb:cc:dd:ee:ff", 1500)

	if len(result.IPs) != 1 {
		t.Fatalf("IPs count = %d, want 1", len(result.IPs))
	}
	wantIPv4Mask := net.CIDRMask(25, 32).String()
	if result.IPs[0].Address.IP.String() != ipv4Address.String() || result.IPs[0].Address.Mask.String() != wantIPv4Mask {
		t.Errorf("IPs[0].Address = %v, want %s/25", result.IPs[0].Address, ipv4Address)
	}
}

// TestBuildTapResultHostNetns verifies that the tap path produces a valid
// CNI result when args.Netns is the host network namespace. Kraftlet/
// unikraft workloads pass the host netns because they don't have a Linux
// network namespace. main.go's own CNI_NETNS_OVERRIDE handles bypassing the
// CNI library's same-netns rejection check. The tap result must not
// reference a sandbox.
func TestBuildTapResultHostNetns(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gateway := net.ParseIP("fd00:10:ff01::1")
	defaultRoute := mustParseCIDR(t, "::/0")

	conf := &PluginConf{
		PluginConf:    types.PluginConf{CNIVersion: testCNIVersion},
		VPC:           testVPC,
		VPCAttachment: testAttachment,
	}
	ipRes := &cniipam.IPAMResult{IPv6Subnet: subnet, IPv6Gateway: gateway, Routes: []*net.IPNet{defaultRoute}}

	result := buildTapResult(conf, ipRes, "H0abc123", "aa:bb:cc:dd:ee:ff", 1500)

	if result.Interfaces[0].Sandbox != "" {
		t.Errorf("Interfaces[0].Sandbox = %q, want empty (host netns, no sandbox)", result.Interfaces[0].Sandbox)
	}
}

// ---- cmdDel / cmdCheck / cmdStatus ----------------------------------------

func TestCmdDelIdempotent(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with invalid config returned error = %v, want nil", err)
	}
}

func TestCmdDelIdempotentMissingResources(t *testing.T) {
	conf := fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment)
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with missing resources returned error = %v, want nil", err)
	}
}

func TestCmdCheckInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	err := cmdCheck(args)
	if err == nil || !strings.Contains(err.Error(), "invalid CNI config") {
		t.Fatalf("expected 'invalid CNI config' error, got: %v", err)
	}
}

func TestCmdCheckValidConfigMissingResources(t *testing.T) {
	conf := fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment)
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	err := cmdCheck(args)
	if err == nil || !strings.Contains(err.Error(), "CHECK failed") {
		t.Fatalf("expected 'CHECK failed', got: %v", err)
	}
}

func TestCmdStatusInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	err := cmdStatus(args)
	assertCNIError(t, err, 7, "invalid CNI config")
}

func TestCmdStatusAPIProbeFailure(t *testing.T) {
	original := cnimaster.ProbeAPIServer
	cnimaster.ProbeAPIServer = func() error { return errors.New("connection refused") }
	defer func() { cnimaster.ProbeAPIServer = original }()

	conf := fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test","type":"galactic-tap","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment)
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	err := cmdStatus(args)
	assertCNIError(t, err, 50, "API server health check failed")
}

// ---- resourceTracker ------------------------------------------------------

func TestResourceTrackerCleanupZeroValue(t *testing.T) {
	tracker := &resourceTracker{}
	tracker.cleanup() // should not panic
}
