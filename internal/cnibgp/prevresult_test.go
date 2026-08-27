// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"encoding/json"
	"net"
	"testing"

	type100 "github.com/containernetworking/cni/pkg/types/100"
)

const (
	testCNIVersion100 = "1.0.0"
	testTapMAC        = "aa:bb:cc:dd:ee:ff"
	testVethHostMAC   = "aa:bb:cc:dd:ee:f0"
	testVethGuestMAC  = "aa:bb:cc:dd:ee:f1"
	testTapIfaceName  = "tap0"
	testVethHostName  = "veth0"
	testVethGuestName = "eth0"
)

// rawPrevResultFrom round-trips result through JSON, the same way the CNI
// runtime hands prevResult to a chained plugin's stdin (skel.CmdArgs.StdinData
// -> PluginConf.RawPrevResult), so tests exercise inferFromPrevResult exactly
// as it receives real input.
func rawPrevResultFrom(t *testing.T, result *type100.Result) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return raw
}

func TestInferFromPrevResult_TapMaster(t *testing.T) {
	// A tap master's own result declares one host-only interface — no
	// Sandbox — see internal/cnitap/result.go's buildTapResult.
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: testCNIVersion100,
		Interfaces: []*type100.Interface{
			{Name: testTapIfaceName, Mac: testTapMAC, Sandbox: ""},
		},
	})

	ifaceType, ipamResult, _, err := inferFromPrevResult(raw)
	if err != nil {
		t.Fatalf("inferFromPrevResult() error = %v", err)
	}
	if ifaceType != ifaceTypeTap {
		t.Errorf("ifaceType = %q, want %q", ifaceType, ifaceTypeTap)
	}
	if ipamResult != nil {
		t.Errorf("ipamResult = %+v, want nil (no IPAM in this result)", ipamResult)
	}
}

func TestInferFromPrevResult_VethMaster(t *testing.T) {
	// A veth master's own result declares two interfaces: host (no Sandbox)
	// and guest (Sandbox = the container netns it was moved into) — see
	// internal/cni/result.go's buildResult.
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: testCNIVersion100,
		Interfaces: []*type100.Interface{
			{Name: testVethHostName, Mac: testVethHostMAC, Sandbox: ""},
			{Name: testVethGuestName, Mac: testVethGuestMAC, Sandbox: testNetns},
		},
	})

	ifaceType, _, _, err := inferFromPrevResult(raw)
	if err != nil {
		t.Fatalf("inferFromPrevResult() error = %v", err)
	}
	if ifaceType != ifaceTypeVeth {
		t.Errorf("ifaceType = %q, want %q", ifaceType, ifaceTypeVeth)
	}
}

func TestInferFromPrevResult_ExtraHostInterfaceStillClassifiesCorrectly(t *testing.T) {
	// A hypothetical extra host-side interface appended by a later
	// chain-invoked plugin (e.g. #306's galactic-route) must not flip a tap
	// master's classification to veth just because len(Interfaces) grew
	// from 1 to 2 — only Sandbox-carrying interfaces count.
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: testCNIVersion100,
		Interfaces: []*type100.Interface{
			{Name: testTapIfaceName, Mac: testTapMAC, Sandbox: ""},
			{Name: "route0", Mac: "aa:bb:cc:dd:ee:fe", Sandbox: ""},
		},
	})

	ifaceType, _, _, err := inferFromPrevResult(raw)
	if err != nil {
		t.Fatalf("inferFromPrevResult() error = %v", err)
	}
	if ifaceType != ifaceTypeTap {
		t.Errorf("ifaceType = %q, want %q", ifaceType, ifaceTypeTap)
	}
}

func TestInferFromPrevResult_MultipleSandboxedInterfacesIsHardError(t *testing.T) {
	// More than one Sandbox-carrying interface is genuinely ambiguous — no
	// known master plugin produces this — and must fail loudly rather than
	// guess.
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: testCNIVersion100,
		Interfaces: []*type100.Interface{
			{Name: testVethHostName, Mac: testVethHostMAC, Sandbox: ""},
			{Name: testVethGuestName, Mac: testVethGuestMAC, Sandbox: testNetns},
			{Name: "eth1", Mac: "aa:bb:cc:dd:ee:f2", Sandbox: testNetns},
		},
	})

	if _, _, _, err := inferFromPrevResult(raw); err == nil {
		t.Fatal("inferFromPrevResult() error = nil, want error for ambiguous interface shape")
	}
}

func TestInferFromPrevResult_NoInterfacesIsError(t *testing.T) {
	raw := rawPrevResultFrom(t, &type100.Result{CNIVersion: testCNIVersion100})

	if _, _, _, err := inferFromPrevResult(raw); err == nil {
		t.Fatal("inferFromPrevResult() error = nil, want error for empty Interfaces")
	}
}

func TestInferFromPrevResult_NilRawPrevResult(t *testing.T) {
	if _, _, _, err := inferFromPrevResult(nil); err == nil {
		t.Fatal("inferFromPrevResult() error = nil, want error for nil rawPrevResult")
	}
}

// TestInferFromPrevResult_RejectsOlderCNIVersion documents (and locks in)
// the hard cniVersion requirement described in this function's doc comment
// and docs/cni/conflist-reference.md: type100.NewResult only accepts a Result
// whose own CNIVersion is exactly "1.0.0" or "1.1.0", and the master
// plugin's printed Result carries the conflist's cniVersion straight
// through, so an older value must fail loudly here rather than proceed with
// stale/wrong assumptions about the Result's shape.
func TestInferFromPrevResult_RejectsOlderCNIVersion(t *testing.T) {
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: "0.4.0",
		Interfaces: []*type100.Interface{
			{Name: testTapIfaceName, Mac: testTapMAC, Sandbox: ""},
		},
	})

	if _, _, _, err := inferFromPrevResult(raw); err == nil {
		t.Fatal("inferFromPrevResult() error = nil, want error for cniVersion \"0.4.0\"")
	}
}

func TestInferFromPrevResult_CarriesIPAMResult(t *testing.T) {
	ipv6 := net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}
	raw := rawPrevResultFrom(t, &type100.Result{
		CNIVersion: testCNIVersion100,
		Interfaces: []*type100.Interface{
			{Name: testVethHostName, Mac: testVethHostMAC, Sandbox: ""},
			{Name: testVethGuestName, Mac: testVethGuestMAC, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: ipv6, Interface: type100.Int(1)},
		},
	})

	ifaceType, ipamResult, _, err := inferFromPrevResult(raw)
	if err != nil {
		t.Fatalf("inferFromPrevResult() error = %v", err)
	}
	if ifaceType != ifaceTypeVeth {
		t.Errorf("ifaceType = %q, want %q", ifaceType, ifaceTypeVeth)
	}
	if ipamResult == nil || ipamResult.IPv6Subnet == nil {
		t.Fatalf("ipamResult = %+v, want a non-nil IPv6Subnet", ipamResult)
	}
	if ipamResult.IPv6Subnet.String() != "2001:db8::1/64" {
		t.Errorf("ipamResult.IPv6Subnet = %s, want 2001:db8::1/64", ipamResult.IPv6Subnet.String())
	}
}
