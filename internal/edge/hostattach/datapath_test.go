// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const (
	dpLocator = "fc00:0:1::/48"
	dpNodeX   = int32(0x10)
	dpNodeY   = int32(0x20)
	dpArgA    = int32(0x101)
	dpArgB    = int32(0x102)

	// Attachment IDs, base62 values that fit the 16-bit VPCAttachment
	// field byte accounting decodes.
	dpWorkloadAtt = "001"
	dpSocketAtt   = "011"
	dpPacketAtt   = "013"

	// siteMTU is the MTU of VPC A's site TUN, below tenantMTU.
	siteMTU = 1400
)

var remoteWorkloadAddr = netip.MustParseAddr("fd00:10::20")

// datapathFixture is node X, running galactic's uSID datapath with host-owned
// attachments registered through attachreg, and node Y, an independent SRv6
// peer built from the kernel's own seg6 encapsulation and End.DT6 decap. Both
// nodes carry VPC A and VPC B with identical addresses.
type datapathFixture struct {
	x, y       testNS
	xH         *Namespace
	pods       map[string]testNS
	handles    map[string]*Namespace
	atts       map[string]Attachment
	results    map[string]Result
	wlXA, wlXB testNS
	wlYA, wlYB testNS
	tunA, tunB *tunResponder
	pinDir     string
	hostKeys   map[uint32]string
}

func sid(t *testing.T, node, arg int32) netip.Addr {
	t.Helper()
	s, err := srv6.ComputeSID(dpLocator, node, arg, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// linkUplinks joins x and y with a transit veth carrying the underlay.
func linkUplinks(t *testing.T, x, y testNS) {
	t.Helper()
	x.do(t, func() error {
		return netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: uplinkName}, PeerName: uplinkName,
			PeerNamespace: netlink.NsFd(int(y.Fd())),
		})
	})
	for _, n := range []struct {
		ns          testNS
		self, peer  string
		peerLocator string
	}{
		{x, "2001:db8:f::1", "2001:db8:f::2", "fc00:0:1:20::/64"},
		{y, "2001:db8:f::2", "2001:db8:f::1", "fc00:0:1:10::/64"},
	} {
		n.ns.do(t, func() error {
			if err := enableSysctl("net/ipv6/conf/all/forwarding"); err != nil {
				return err
			}
			link, err := netlink.LinkByName(uplinkName)
			if err != nil {
				return err
			}
			if err := addAddr(link, n.self+"/64"); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return err
			}
			return netlink.RouteReplace(&netlink.Route{
				LinkIndex: link.Attrs().Index, Dst: ip6Net(n.peerLocator), Gw: net.ParseIP(n.peer),
			})
		})
	}
}

// setupNodeY builds the independent peer: a canonical VRF per VPC, a workload
// with the same address in each, kernel seg6 routes toward X's SIDs and
// End.DT6 decap of its own SIDs into the VPC's VRF.
func (f *datapathFixture) setupNodeY(t *testing.T) {
	t.Helper()
	f.y.do(t, func() error {
		for _, k := range []string{
			"net/vrf/strict_mode", "net/ipv6/conf/all/seg6_enabled", "net/ipv6/conf/" + uplinkName + "/seg6_enabled",
		} {
			if err := enableSysctl(k); err != nil {
				return err
			}
		}
		for _, vpc := range []string{vpcA, vpcB} {
			if err := vrf.Add(vpc); err != nil {
				return err
			}
		}
		return nil
	})
	f.wlYA = newWorkload(t, f.y, vrfA, "wlA", remoteWorkloadAddr.String())
	f.wlYB = newWorkload(t, f.y, vrfB, "wlB", remoteWorkloadAddr.String())
	f.y.do(t, func() error {
		uplink, err := netlink.LinkByName(uplinkName)
		if err != nil {
			return err
		}
		for _, v := range []struct {
			vpc  string
			name string
			arg  int32
		}{{vpcA, vrfA, dpArgA}, {vpcB, vrfB, dpArgB}} {
			table, err := vrf.TableID(v.vpc)
			if err != nil {
				return err
			}
			vrfLink, err := netlink.LinkByName(v.name)
			if err != nil {
				return err
			}
			remote := sid(t, dpNodeX, v.arg)
			// The kernel resolves a seg6 encapsulation's outer destination in
			// the table the inner packet was routed in, so the VRF needs the
			// underlay route to X's locator too.
			if err := netlink.RouteReplace(&netlink.Route{
				LinkIndex: uplink.Attrs().Index, Table: int(table), Dst: ip6Net("fc00:0:1:10::/64"),
				Gw: net.ParseIP("2001:db8:f::1"),
			}); err != nil {
				return fmt.Errorf("underlay route in VRF table %d: %w", table, err)
			}
			for _, dst := range []string{"fd00:aa::/64", sitePrefix.String()} {
				if err := netlink.RouteReplace(&netlink.Route{
					LinkIndex: uplink.Attrs().Index, Table: int(table), Dst: ip6Net(dst),
					Encap: &netlink.SEG6Encap{Mode: nl.SEG6_IPTUN_MODE_ENCAP_RED, Segments: []net.IP{remote.AsSlice()}},
				}); err != nil {
					return fmt.Errorf("seg6 encap route %s: %w", dst, err)
				}
			}
			local := sid(t, dpNodeY, v.arg)
			encap := &netlink.SEG6LocalEncap{Action: nl.SEG6_LOCAL_ACTION_END_DT6, VrfTable: int(table)}
			encap.Flags[nl.SEG6_LOCAL_ACTION] = true
			encap.Flags[nl.SEG6_LOCAL_VRFTABLE] = true
			if err := netlink.RouteReplace(&netlink.Route{
				LinkIndex: vrfLink.Attrs().Index, Dst: prefixNet(netip.PrefixFrom(local, 128)), Encap: encap,
			}); err != nil {
				return fmt.Errorf("End.DT6 for %s: %w", local, err)
			}
		}
		return nil
	})
}

// register registers one attachment's host link with X's datapath the way the
// CNI registers a workload: host ifindex and canonical table only.
func (f *datapathFixture) register(t *testing.T, vpc, att string, arg int32, local []string) {
	t.Helper()
	f.x.do(t, func() error {
		_, err := attachreg.RegisterDatapath(f.pinDir, attachreg.Registration{
			Node: attachreg.Node{Locator: dpLocator, NodeID: dpNodeX}, VPC: vpc, VPCAttachment: att,
			InterfaceType: attachreg.InterfaceTypeVeth, Argument: uint16(arg), LocalPrefixes: local,
		})
		if err != nil {
			return fmt.Errorf("register %s/%s: %w", vpc, att, err)
		}
		link, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(vpc, att))
		if err != nil {
			return err
		}
		f.hostKeys[uint32(link.Attrs().Index)] = vpc + "/" + att
		return nil
	})
}

func newDatapathFixture(t *testing.T) *datapathFixture {
	t.Helper()
	f := &datapathFixture{
		pods: map[string]testNS{}, handles: map[string]*Namespace{},
		atts: map[string]Attachment{}, results: map[string]Result{}, hostKeys: map[uint32]string{},
		pinDir: fmt.Sprintf("/sys/fs/bpf/galactic-edge-hostattach-%d", os.Getpid()),
	}
	t.Cleanup(func() { _ = os.RemoveAll(f.pinDir) })
	t.Setenv(config.EnvCNIEBPFInterfaces, uplinkName)
	attach.InvalidateUplinkIndexes()
	t.Cleanup(attach.InvalidateUplinkIndexes)

	f.x = newTestNS(t)
	f.y = newTestNS(t)
	linkUplinks(t, f.x, f.y)
	f.x.do(t, func() error {
		for _, vpc := range []string{vpcA, vpcB} {
			if err := vrf.Add(vpc); err != nil {
				return err
			}
		}
		objs, err := attach.Load(f.pinDir)
		if err != nil {
			return fmt.Errorf("load uSID datapath: %w", err)
		}
		t.Cleanup(func() { _ = objs.Close() })
		return attach.Attach(objs.UsidIngress, []string{uplinkName})
	})
	f.xH = f.x.open(t)
	f.setupNodeY(t)

	wlA, wlB := intf.GenerateInterfaceNameHost(vpcA, dpWorkloadAtt), intf.GenerateInterfaceNameHost(vpcB, dpWorkloadAtt)
	f.wlXA = newWorkload(t, f.x, vrfA, wlA, workloadAddr.String())
	f.wlXB = newWorkload(t, f.x, vrfB, wlB, workloadAddr.String())
	f.register(t, vpcA, dpWorkloadAtt, dpArgA, []string{workloadAddr.String() + "/128"})
	f.register(t, vpcB, dpWorkloadAtt, dpArgB, []string{workloadAddr.String() + "/128"})

	for i, name := range []string{"pod1", "pod3", "pod4"} {
		f.pods[name] = newPod(t, f.x, "mgmt-"+name, i+1)
		f.handles[name] = f.pods[name].open(t)
	}
	att := func(vpc, vrfName, attID, podLink string, table uint32, index int, addr string) Attachment {
		return Attachment{
			ID: "uid-" + vpc + attID, HostVRF: vrfName, HostLink: intf.GenerateInterfaceNameHost(vpc, attID),
			PodVRF: vrfName, PodTable: table, PodLink: podLink, PodIndex: index, MTU: tenantMTU,
			Address: netip.MustParseAddr(addr),
		}
	}
	f.atts[pod1A] = att(vpcA, vrfA, dpSocketAtt, "a0", podTable, podIndex, "fd00:aa::1")
	f.atts[pod1B] = att(vpcB, vrfB, dpSocketAtt, "b0", podTable+1, podIndex+1, "fd00:aa::1")
	for key, v := range map[string][2]string{pod3A: {vpcA, vrfA}, pod4B: {vpcB, vrfB}} {
		a := att(v[0], v[1], dpPacketAtt, "a0", podTable, podIndex, "fd00:aa::3")
		a.Prefixes = []netip.Prefix{sitePrefix}
		a.TUN = &TUN{Name: tunName, Owner: 65534, Group: 65534}
		f.atts[key] = a
	}
	// VPC A's site is behind a session that carries less than the tenant
	// MTU, so the pod's own forwarding must report Packet Too Big.
	f.atts[pod3A].TUN.MTU = siteMTU
	for _, key := range []string{pod1A, pod1B, pod3A, pod4B} {
		a := f.atts[key]
		res, err := Provision(f.xH, f.handles[key[:4]], a)
		if err != nil {
			t.Fatalf("provision %s: %v", key, err)
		}
		f.results[key] = res
		vpc, arg, attID := vpcA, dpArgA, dpSocketAtt
		if a.HostVRF == vrfB {
			vpc, arg = vpcB, dpArgB
		}
		if a.TUN != nil {
			attID = dpPacketAtt
		}
		local := make([]string, 0, 1+len(a.Prefixes))
		local = append(local, a.Address.String()+"/128")
		for _, p := range a.Prefixes {
			local = append(local, p.String())
		}
		f.register(t, vpc, attID, arg, local)
	}

	// What galactic-router installs for a remote EVPN route: Y's workload,
	// encapsulated toward Y's SID for the VPC.
	f.x.do(t, func() error {
		table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(f.pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		for _, v := range []struct {
			vpc string
			arg int32
		}{{vpcA, dpArgA}, {vpcB, dpArgB}} {
			tableID, err := vrf.TableID(v.vpc)
			if err != nil {
				return err
			}
			dst := ip6Net(remoteWorkloadAddr.String() + "/128")
			if err := table.Register(tableID, dst, sid(t, dpNodeY, v.arg).AsSlice()); err != nil {
				return err
			}
		}
		return nil
	})

	serveIdentity(t, f.pods["pod1"], vrfA, podPort, "pod1-A")
	serveIdentity(t, f.pods["pod1"], vrfB, podPort, "pod1-B")
	f.tunA = newTUNResponder(t, f.pods["pod3"])
	f.tunB = newTUNResponder(t, f.pods["pod4"])
	return f
}

// TestHostAttachmentDatapath runs host-owned attachments through galactic's
// uSID datapath on a real kernel. Node X registers each attachment by host
// ifindex and canonical table only; node Y is an independent kernel SRv6
// peer. Both VPCs reuse every address and the pods reuse pod-local IDs.
func TestHostAttachmentDatapath(t *testing.T) {
	requireRoot(t)
	f := newDatapathFixture(t)
	for _, sub := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"SharedMapsHoldOnlyHostKeys", f.testSharedMapsHoldOnlyHostKeys},
		{"RemoteSocketForwardAndReturn", f.testRemoteSocketForwardAndReturn},
		{"RemotePacketConsumerIsolation", f.testRemotePacketConsumerIsolation},
		{"RemoteMinimumIPv6MTU", f.testRemoteMinimumIPv6MTU},
		{"RemotePacketTooBigFromNarrowerTUN", f.testRemotePacketTooBig},
		{"SameNodeDoesNotHairpin", f.testSameNodeDoesNotHairpin},
		{"TenantMTUAboveLinkDefault", f.testTenantMTUAboveLinkDefault},
	} {
		t.Run(sub.name, sub.fn)
	}
}

func (f *datapathFixture) testSharedMapsHoldOnlyHostKeys(t *testing.T) {
	var tables map[uint32]bool
	f.x.do(t, func() error {
		tables = map[uint32]bool{}
		for _, vpc := range []string{vpcA, vpcB} {
			id, err := vrf.TableID(vpc)
			if err != nil {
				return err
			}
			tables[id] = true
		}
		ifTable, ifMap, err := ifindexvrfmap.OpenPinned(f.pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = ifMap.Close() }()
		entries, err := ifTable.List()
		if err != nil {
			return err
		}
		if len(entries) != len(f.hostKeys) {
			t.Errorf("ifindex_vrf_table has %d rows, want %d: %+v", len(entries), len(f.hostKeys), entries)
		}
		for _, e := range entries {
			if _, ok := f.hostKeys[e.Ifindex]; !ok {
				t.Errorf("ifindex_vrf_table row for ifindex %d is not a host attachment link", e.Ifindex)
			}
		}
		reg, closer, err := usidmap.OpenPinnedRegistry(f.pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		vrfs, err := reg.VRF.List()
		if err != nil {
			return err
		}
		for _, e := range vrfs {
			if !tables[e.VRFTableID] {
				t.Errorf("vrf_table row resolves to table %d, which is not a canonical host table", e.VRFTableID)
			}
		}
		return nil
	})
	for key, res := range f.results {
		if f.hostKeys[uint32(res.HostIndex)] == "" {
			t.Errorf("%s host ifindex %d not registered", key, res.HostIndex)
		}
	}
}

func (f *datapathFixture) testRemoteSocketForwardAndReturn(t *testing.T) {
	dst := netip.MustParseAddrPort("[fd00:aa::1]:8000")
	expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	expectIdentity(t, f.wlYB, "", dst, "pod1-B")
}

func (f *datapathFixture) testRemotePacketConsumerIsolation(t *testing.T) {
	a0, b0 := f.tunA.echoes.Load(), f.tunB.echoes.Load()
	if err := ping(f.wlYA, siteHost, 128); err != nil {
		t.Fatalf("remote VPC A workload to site: %v", err)
	}
	if err := ping(f.wlYB, siteHost, 128); err != nil {
		t.Fatalf("remote VPC B workload to site: %v", err)
	}
	if f.tunA.echoes.Load() != a0+1 || f.tunB.echoes.Load() != b0+1 {
		t.Fatalf("echoes TUN A %d->%d, TUN B %d->%d; want one each", a0, f.tunA.echoes.Load(), b0, f.tunB.echoes.Load())
	}
}

func (f *datapathFixture) testRemoteMinimumIPv6MTU(t *testing.T) {
	if err := ping(f.wlYA, siteHost, 1280); err != nil {
		t.Fatalf("1280-byte packet from the remote node to the site: %v", err)
	}
}

func (f *datapathFixture) testRemotePacketTooBig(t *testing.T) {
	err := ping(f.wlYA, siteHost, siteMTU+50)
	var tooBig *packetTooBigError
	if !errors.As(err, &tooBig) || tooBig.MTU != siteMTU {
		t.Fatalf("remote %d-byte packet to a %d-byte site = %v, want Packet Too Big with MTU %d",
			siteMTU+50, siteMTU, err, siteMTU)
	}
	if err := ping(f.wlYA, siteHost, siteMTU); err != nil {
		t.Fatalf("remote %d-byte packet after Packet Too Big: %v", siteMTU, err)
	}
}

func (f *datapathFixture) testSameNodeDoesNotHairpin(t *testing.T) {
	toAttachment := watchLeaks(t, f.x, uplinkName, netip.MustParseAddr("fd00:aa::1"))
	toSite := watchLeaks(t, f.x, uplinkName, siteHost)
	expectIdentity(t, f.wlXA, "", netip.MustParseAddrPort("[fd00:aa::1]:8000"), "pod1-A")
	if err := ping(f.wlXB, siteHost, 128); err != nil {
		t.Fatalf("same-node VPC B workload to site: %v", err)
	}
	if a, b := toAttachment.stop(), toSite.stop(); a != 0 || b != 0 {
		t.Fatalf("same-node traffic left the uplink: %d packets to the attachment, %d to the site", a, b)
	}
}

// testTenantMTUAboveLinkDefault raises the tenant MTU above the 1500-byte
// veth default and checks that a packet that large reaches the attachment
// over the fabric only because the attachment link carries the tenant MTU:
// with the host link left at the default, the datapath drops the
// decapsulated packet and the sender hears nothing.
func (f *datapathFixture) testTenantMTUAboveLinkDefault(t *testing.T) {
	const jumbo = 1800
	for _, n := range []struct {
		ns    testNS
		links []string
	}{
		{f.x, []string{uplinkName}},
		{f.y, []string{uplinkName, "wlA"}},
		{f.wlYA, []string{podEth0}},
	} {
		n.ns.do(t, func() error {
			for _, name := range n.links {
				l, err := netlink.LinkByName(name)
				if err != nil {
					return err
				}
				mtu := jumbo
				if name == uplinkName {
					mtu = 9000
				}
				if err := netlink.LinkSetMTU(l, mtu); err != nil {
					return err
				}
			}
			return nil
		})
	}
	a := f.atts[pod1A]
	a.MTU = jumbo
	if _, err := Provision(f.xH, f.handles["pod1"], a); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("fd00:aa::1")
	if err := ping(f.wlYA, dst, jumbo); err != nil {
		t.Fatalf("%d-byte packet to an attachment carrying the tenant MTU: %v", jumbo, err)
	}
	f.x.do(t, func() error {
		l, err := netlink.LinkByName(a.HostLink)
		if err != nil {
			return err
		}
		return netlink.LinkSetMTU(l, tenantMTU)
	})
	if err := ping(f.wlYA, dst, jumbo); !errors.Is(err, errNoReply) {
		t.Fatalf("%d-byte packet with the host link at the default MTU = %v, want no reply", jumbo, err)
	}
	if _, err := Provision(f.xH, f.handles["pod1"], f.atts[pod1A]); err != nil {
		t.Fatal(err)
	}
}
