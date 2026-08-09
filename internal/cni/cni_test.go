// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

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
	original := cnimaster.ProbeAPIServer
	cnimaster.ProbeAPIServer = func() error { return nil }
	defer func() { cnimaster.ProbeAPIServer = original }()

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
	original := cnimaster.ProbeAPIServer
	cnimaster.ProbeAPIServer = func() error { return nil }
	defer func() { cnimaster.ProbeAPIServer = original }()

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
	original := cnimaster.ProbeAPIServer
	cnimaster.ProbeAPIServer = func() error { return nil }
	defer func() { cnimaster.ProbeAPIServer = original }()

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
	original := cnimaster.ProbeAPIServer
	cnimaster.ProbeAPIServer = func() error { return errors.New("connection refused") }
	defer func() { cnimaster.ProbeAPIServer = original }()

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
