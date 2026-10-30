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
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
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
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, ipam, nil); err != nil {
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

// podRoutes returns the destinations of the unicast routes on host in the
// test VPC's VRF table, leaving out the ones the kernel adds itself.
func podRoutes(t *testing.T, host string) map[string]bool {
	t.Helper()
	link, err := netlink.LinkByName(host)
	if err != nil {
		t.Fatal(err)
	}
	table, err := vrf.TableID(testVPC)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: int(table), LinkIndex: link.Attrs().Index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range routes {
		if r.Dst != nil && r.Type == unix.RTN_UNICAST && r.Protocol != unix.RTPROT_KERNEL {
			got[r.Dst.String()] = true
		}
	}
	return got
}

// TestActivateTrafficPolicyRestoresHostGateway covers the host gateway across
// activation. A quarantined host side gets its pod-subnet routes, which the
// kernel refuses on a down link, once activation brings it up. A link
// quarantined after the master left it up, which drops its routes, its IPv6
// gateway address and its neighbor entries, gets all of them back. With policy
// off, a route a later chained plugin added on the link survives activation.
func TestActivateTrafficPolicyRestoresHostGateway(t *testing.T) {
	_, ipv6, _ := net.ParseCIDR("2001:db8::5/64")
	ipv6.IP = net.ParseIP("2001:db8::5")
	ipam := &cniipam.IPAMResult{
		IPv6Subnet:  ipv6,
		IPv6Gateway: net.ParseIP("2001:db8::1"),
		IPv4Address: net.ParseIP("192.0.2.5"),
		IPv4Gateway: net.ParseIP("192.0.2.1"),
	}
	guestMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x05}
	_, termination, _ := net.ParseCIDR("198.51.100.0/24")
	for _, tt := range []struct {
		name        string
		mode        uint32
		quarantined bool
	}{
		{"enforced, master left the link down", tpmap.ModeEnforce, true},
		{"enforced, master left the link up", tpmap.ModeEnforce, false},
		{"off, with a later plugin's route", tpmap.ModeOff, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pinDir, host, _ := activationFixture(t, tpmap.State{Mode: tt.mode, Capable: true}, tt.quarantined)
			if err := hostgw.ConfigureHostGateway(testVPC, testAttachment, ipam, guestMAC); err != nil {
				t.Fatalf("ConfigureHostGateway: %v", err)
			}
			if got := podRoutes(t, host); tt.quarantined && len(got) != 0 {
				t.Errorf("routes on a down link = %v, want none", got)
			}
			want := []string{"2001:db8::/64", "192.0.2.5/32"}
			if tt.mode == tpmap.ModeOff {
				// Stands in for galactic-route, which runs between the
				// master and galactic-bgp and adds routes on the same link.
				table, err := vrf.TableID(testVPC)
				if err != nil {
					t.Fatal(err)
				}
				link, _ := netlink.LinkByName(host)
				if err := netlink.RouteAdd(&netlink.Route{
					Dst: termination, LinkIndex: link.Attrs().Index, Table: int(table),
				}); err != nil {
					t.Fatalf("add a later plugin's route: %v", err)
				}
				want = append(want, termination.String())
			}
			if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, ipam, guestMAC); err != nil {
				t.Fatalf("activateTrafficPolicy: %v", err)
			}
			if !linkUp(t, host) {
				t.Fatal("host side still down after activation")
			}
			got := podRoutes(t, host)
			for _, dst := range want {
				if !got[dst] {
					t.Errorf("route to %s missing after activation; routes %v", dst, got)
				}
			}
			link, _ := netlink.LinkByName(host)
			addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				t.Fatal(err)
			}
			var gateway bool
			for _, a := range addrs {
				gateway = gateway || a.IP.Equal(ipam.IPv6Gateway)
			}
			if !gateway {
				t.Errorf("IPv6 gateway %s missing after activation; addresses %v", ipam.IPv6Gateway, addrs)
			}
			for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					t.Fatal(err)
				}
				var found bool
				for _, n := range neighs {
					found = found || (n.State == netlink.NUD_PERMANENT && n.HardwareAddr.String() == guestMAC.String())
				}
				if !found {
					t.Errorf("family %d: permanent neighbor for %s missing after activation; %v", family, guestMAC, neighs)
				}
			}
		})
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
	err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil, nil)
	if !errors.Is(err, errNoEnforcement) {
		t.Fatalf("not capable: err = %v, want errNoEnforcement", err)
	}
	if linkUp(t, host) {
		t.Error("an interface the node cannot enforce on was left up")
	}

	if err := maps.SetState(tpmap.State{Mode: tpmap.ModeOff}); err != nil {
		t.Fatal(err)
	}
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil, nil); err != nil {
		t.Fatalf("mode off: %v", err)
	}
	if !linkUp(t, host) {
		t.Error("a link quarantined while policy was on stayed down after it turned off")
	}
}

// TestActivateTrafficPolicyRefusesUnfencedHostOnlyPorts covers a router with
// no SRv6 locator, which attaches no tp_deliver: an interface listing
// host-only ports there is left down rather than brought up with nothing
// enforcing them, and one listing none comes up as before.
func TestActivateTrafficPolicyRefusesUnfencedHostOnlyPorts(t *testing.T) {
	pinDir, host, _ := activationFixture(t, tpmap.State{Mode: tpmap.ModeOff}, false)
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, false, nil, nil); err != nil {
		t.Fatalf("no host-only ports: %v", err)
	}
	if !linkUp(t, host) {
		t.Fatal("an interface listing no host-only ports did not come up")
	}

	link, err := netlink.LinkByName(host)
	if err != nil {
		t.Fatal(err)
	}
	table, closer, err := ifindexvrfmap.OpenPinnedHostOnlyPorts(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	if err := table.Register(uint32(link.Attrs().Index), []uint16{20000}); err != nil { //nolint:gosec // a kernel ifindex
		t.Fatal(err)
	}

	err = activateTrafficPolicy(pinDir, testVPC, testAttachment, false, nil, nil)
	if !errors.Is(err, errHostOnlyUnenforced) {
		t.Fatalf("unregistered: err = %v, want errHostOnlyUnenforced", err)
	}
	if linkUp(t, host) {
		t.Error("an interface whose host-only ports nothing enforces was left up")
	}

	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil, nil); err != nil {
		t.Fatalf("registered: %v", err)
	}
	if !linkUp(t, host) {
		t.Error("an interface with tp_deliver attached did not come up")
	}
}

// TestActivateTrafficPolicyKeepsTheToken checks a repeated ADD on a live
// interface keeps its policy token, so its published bindings stay valid.
func TestActivateTrafficPolicyKeepsTheToken(t *testing.T) {
	pinDir, host, maps := activationFixture(t, tpmap.State{Mode: tpmap.ModeEnforce, Capable: true}, true)
	link, _ := netlink.LinkByName(host)
	ifindex := uint32(link.Attrs().Index)
	tokenOf := func() uint64 {
		var row prog.UsidTpIfaceValue
		if err := maps.Interfaces.Lookup(ifindex, &row); err != nil {
			t.Fatal(err)
		}
		return row.PolicyToken
	}
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	first := tokenOf()
	if err := activateTrafficPolicy(pinDir, testVPC, testAttachment, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := tokenOf(); got != first {
		t.Errorf("token = %#x after a repeated ADD, want %#x kept", got, first)
	}
}
