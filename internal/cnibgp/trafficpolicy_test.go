// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func TestInterfaceAddrs(t *testing.T) {
	_, v6, _ := net.ParseCIDR("2001:db8::5/64")
	v6.IP = net.ParseIP("2001:db8::5")
	got := interfaceAddrs(&cniipam.IPAMResult{IPv6Subnet: v6, IPv4Address: net.ParseIP("192.0.2.5")})
	want := []netip.Addr{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("192.0.2.5")}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("interfaceAddrs = %v, want %v", got, want)
	}
	if got := interfaceAddrs(nil); got != nil {
		t.Errorf("interfaceAddrs(nil) = %v, want none", got)
	}
}

// activationFixture is a VRF, a veth attachment and a loaded datapath under a
// throwaway pin directory, with the datapath registered for the attachment.
func activationFixture(t *testing.T, state tpmap.State, quarantined bool) (pinDir, host string, maps *tpmap.Maps) {
	t.Helper()
	requireRoot(t)
	saved := veth.HostQuarantined
	veth.HostQuarantined = func() bool { return quarantined }
	t.Cleanup(func() { veth.HostQuarantined = saved })

	if err := vrf.Add(testVPC); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC) })
	if _, err := veth.Add(testVPC, testAttachment, testContainerID, 1500); err != nil {
		t.Fatalf("veth.Add: %v", err)
	}
	t.Cleanup(func() { _ = veth.Delete(testVPC, testAttachment, testContainerID) })
	host = intf.GenerateInterfaceNameHost(testVPC, testAttachment)

	pinDir = fmt.Sprintf("/sys/fs/bpf/galactic-tp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	maps = tpmap.FromObjects(objs)
	if err := maps.SetState(state); err != nil {
		t.Fatal(err)
	}
	cfg := bgpConfig{srv6Locator: "2001:db8:1::/48", nodeID: 5}
	if _, err := registerEBPFDatapath(cfg, testVPC, testAttachment, ifaceTypeVeth, 42, pinDir, nil); err != nil {
		t.Fatalf("registerEBPFDatapath: %v", err)
	}
	return pinDir, host, maps
}

func linkUp(t *testing.T, name string) bool {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Flags&net.FlagUp != 0
}

// TestActivateTrafficPolicyEnforce brings a quarantined interface up only
// after writing its row and attaching tp_deliver.
func TestActivateTrafficPolicyEnforce(t *testing.T) {
	pinDir, host, maps := activationFixture(t, tpmap.State{Mode: tpmap.ModeEnforce, Capable: true}, true)
	if linkUp(t, host) {
		t.Fatal("the master plugin left the host side up while policy is on")
	}
	_, ipv6, _ := net.ParseCIDR("2001:db8::5/64")
	ipam := &cniipam.IPAMResult{IPv6Subnet: ipv6}
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, ipam); err != nil {
		t.Fatalf("activateTrafficPolicy: %v", err)
	}
	if !linkUp(t, host) {
		t.Error("host side still down after activation")
	}
	if ok, err := attach.HasDeliver(host); err != nil || !ok {
		t.Errorf("tp_deliver attached = %v, %v; want true", ok, err)
	}
	link, _ := netlink.LinkByName(host)
	var row prog.UsidTpIfaceValue
	if err := maps.Interfaces.Lookup(uint32(link.Attrs().Index), &row); err != nil || row.PolicyToken == 0 ||
		row.Kind != tpmap.KindTenant {
		t.Errorf("policy row = %+v, %v; want a tenant row with a token", row, err)
	}
}

// TestActivateTrafficPolicyModeChangedSinceMaster covers both races between
// the master plugin's reading of the mode and galactic-bgp's: a link left up
// while policy turned on is quarantined before anything can refuse the ADD,
// and a link left down while policy turned off comes up.
func TestActivateTrafficPolicyModeChangedSinceMaster(t *testing.T) {
	pinDir, host, maps := activationFixture(t, tpmap.State{Mode: tpmap.ModeEnforce}, false)
	if !linkUp(t, host) {
		t.Fatal("the master plugin quarantined although the mode was off when it ran")
	}
	err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil)
	if !errors.Is(err, errNoEnforcement) {
		t.Fatalf("not capable: err = %v, want errNoEnforcement", err)
	}
	if linkUp(t, host) {
		t.Error("an interface the node cannot enforce on was left up")
	}

	if err := maps.SetState(tpmap.State{Mode: tpmap.ModeOff}); err != nil {
		t.Fatal(err)
	}
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil); err != nil {
		t.Fatalf("mode off: %v", err)
	}
	if !linkUp(t, host) {
		t.Error("a link quarantined while policy was on stayed down after it turned off")
	}
}
