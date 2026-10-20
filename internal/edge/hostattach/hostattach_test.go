// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const (
	vpcA = "vpcA00001"
	vpcB = "vpcB00001"

	// Pod-local identifiers every consumer pod uses, deliberately equal.
	podTable = 100
	podIndex = 42

	pod3A = "pod3/A"
	pod4B = "pod4/B"

	// tunName is every packet pod's TUN device.
	tunName = "tun0"

	workloadPort = 7000
	podPort      = 8000
)

var (
	// Both VPCs use the same workload address, attachment addresses and
	// site prefix.
	workloadAddr = netip.MustParseAddr("fd00:10::10")
	sitePrefix   = netip.MustParsePrefix("fd00:5::/48")
	siteHost     = netip.MustParseAddr("fd00:5::1")
	wlDst        = netip.AddrPortFrom(workloadAddr, workloadPort)

	vrfA = intf.GenerateInterfaceNameVRF(vpcA)
	vrfB = intf.GenerateInterfaceNameVRF(vpcB)
)

// edgeFixture is one node with two VPCs that use identical addresses, an
// ordinary workload in each, two socket-access pods and one
// packet-access pod (connect-like) per VPC.
type edgeFixture struct {
	host     testNS
	hostH    *Namespace
	wlA, wlB testNS
	pods     map[string]testNS
	handles  map[string]*Namespace
	atts     map[string]Attachment
	results  map[string]Result
	tunA     *tunResponder
	tunB     *tunResponder
}

func newEdgeFixture(t *testing.T) *edgeFixture {
	t.Helper()
	f := &edgeFixture{
		pods: map[string]testNS{}, handles: map[string]*Namespace{},
		atts: map[string]Attachment{}, results: map[string]Result{},
	}
	f.host = newHost(t, vpcA, vpcB)
	f.hostH = f.host.open(t)
	f.wlA = newWorkload(t, f.host, vrfA, "wlA", workloadAddr.String())
	f.wlB = newWorkload(t, f.host, vrfB, "wlB", workloadAddr.String())

	for i, name := range []string{"pod1", "pod2", "pod3", "pod4"} {
		f.pods[name] = newPod(t, f.host, "mgmt-"+name, i+1)
		f.handles[name] = f.pods[name].open(t)
	}
	// The pod VRFs keep the canonical VRF's name, as Envoy's sockets bind to
	// G<vpc>V inside its pod.
	att := func(id, hostVRF, hostLink, podLink string, addr string) Attachment {
		return Attachment{
			ID: id, HostVRF: hostVRF, HostLink: hostLink, PodVRF: hostVRF, PodTable: podTable,
			PodLink: podLink, PodIndex: podIndex, Address: netip.MustParseAddr(addr),
		}
	}
	f.atts["pod1/A"] = att("uid-pod1-a", vrfA, "p1a", "a0", "fd00:aa::1")
	f.atts["pod1/B"] = att("uid-pod1-b", vrfB, "p1b", "b0", "fd00:aa::1")
	pod1B := f.atts["pod1/B"]
	pod1B.PodTable, pod1B.PodIndex = podTable+1, podIndex+1
	f.atts["pod1/B"] = pod1B
	f.atts["pod2/A"] = att("uid-pod2-a", vrfA, "p2a", "a0", "fd00:aa::2")
	for key, vrfName := range map[string]string{pod3A: vrfA, pod4B: vrfB} {
		a := att("uid-"+key, vrfName, "p"+key[3:4]+"t", "a0", "fd00:aa::3")
		a.Prefixes = []netip.Prefix{sitePrefix}
		a.TUN = &TUN{Name: "tun0", Owner: 65534, Group: 65534}
		f.atts[key] = a
	}
	for _, key := range []string{"pod1/A", "pod1/B", "pod2/A", pod3A, pod4B} {
		res, err := Provision(f.hostH, f.handles[key[:4]], f.atts[key])
		if err != nil {
			t.Fatalf("provision %s: %v", key, err)
		}
		f.results[key] = res
		t.Logf("provisioned %s: host ifindex %d table %d, pod ifindex %d table %d",
			key, res.HostIndex, res.HostTable, res.PodIndex, f.atts[key].PodTable)
	}

	serveIdentity(t, f.wlA, "", workloadPort, "workload-A")
	serveIdentity(t, f.wlB, "", workloadPort, "workload-B")
	serveIdentity(t, f.pods["pod1"], vrfA, podPort, "pod1-A")
	serveIdentity(t, f.pods["pod1"], vrfB, podPort, "pod1-B")
	serveIdentity(t, f.pods["pod2"], vrfA, podPort, "pod2-A")
	f.tunA = newTUNResponder(t, f.pods["pod3"], "tun0")
	f.tunB = newTUNResponder(t, f.pods["pod4"], "tun0")
	return f
}

func (f *edgeFixture) provision(t *testing.T, key string) {
	t.Helper()
	if _, err := Provision(f.hostH, f.handles[key[:4]], f.atts[key]); err != nil {
		t.Fatalf("re-provision %s: %v", key, err)
	}
}

func expectIdentity(t *testing.T, n testNS, dev string, dst netip.AddrPort, want string) {
	t.Helper()
	got, err := dialIdentity(n, dev, dst)
	if err != nil {
		t.Fatalf("dial %s via %q: %v", dst, dev, err)
	}
	if got != want {
		t.Fatalf("dial %s via %q reached %q, want %q", dst, dev, got, want)
	}
}

// TestHostAttachmentFixture exercises host-owned attachments on a real kernel:
// overlapping VPCs, equal pod-local identifiers, several socket consumers and
// a packet consumer on one node, explicit neighbors, failures that must stay
// inside the tenant VRF, ownership checks and sandbox replacement.
func TestHostAttachmentFixture(t *testing.T) {
	requireRoot(t)
	f := newEdgeFixture(t)
	// The subtests share one topology and run in order: later ones repair or
	// remove state earlier ones rely on.
	for _, sub := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"EqualPodLocalIdentifiersHostOnlyKeys", f.testEqualPodLocalIdentifiersHostOnlyKeys},
		{"SocketForwardIsolation", f.testSocketForwardIsolation},
		{"SocketReturnUsesEachPodsNextHop", f.testSocketReturnUsesEachPodsNextHop},
		{"PacketConsumerIsolation", f.testPacketConsumerIsolation},
		{"NoNeighborDiscoveryPerSiteAddress", f.testNoNeighborDiscoveryPerSiteAddress},
		{"ColdNeighborResolves", f.testColdNeighborResolves},
		{"MinimumIPv6MTU", f.testMinimumIPv6MTU},
		{"MissingHostRouteFailsInsideVRF", f.testMissingHostRouteFailsInsideVRF},
		{"MissingPodRouteFailsInsidePodVRF", f.testMissingPodRouteFailsInsidePodVRF},
		{"DetachedInterfaceFailsInsideVRF", f.testDetachedInterfaceFailsInsideVRF},
		{"OwnershipIsChecked", f.testOwnershipIsChecked},
		{"ReleaseRemovesOnlyItsOwnState", f.testReleaseRemovesOnlyItsOwnState},
		{"SharedPrefixInOneVPCIsRefused", f.testSharedPrefixInOneVPCIsRefused},
		{"TakenTUNNameIsRefused", f.testTakenTUNNameIsRefused},
		{"UnstampedPairIsAdopted", f.testUnstampedPairIsAdopted},
		{"ForwardingDriftIsRepaired", f.testForwardingDriftIsRepaired},
		{"ReplacedSandboxIsRejected", f.testReplacedSandboxIsRejected},
	} {
		t.Run(sub.name, sub.fn)
	}
}

func (f *edgeFixture) testEqualPodLocalIdentifiersHostOnlyKeys(t *testing.T) {
	hostIdx := map[int]string{}
	for _, key := range []string{"pod1/A", "pod2/A", pod3A, pod4B} {
		res := f.results[key]
		if res.PodIndex != podIndex {
			t.Errorf("%s pod ifindex %d, want the shared pod-local %d", key, res.PodIndex, podIndex)
		}
		if prev, dup := hostIdx[res.HostIndex]; dup {
			t.Errorf("%s and %s share host ifindex %d", key, prev, res.HostIndex)
		}
		hostIdx[res.HostIndex] = key
	}
	var tableA, tableB uint32
	f.host.do(t, func() error {
		var err error
		if tableA, err = vrf.TableID(vpcA); err != nil {
			return err
		}
		tableB, err = vrf.TableID(vpcB)
		return err
	})
	if f.results[pod3A].HostTable != tableA || f.results[pod4B].HostTable != tableB || tableA == tableB {
		t.Errorf("host tables A=%d B=%d, results %d/%d", tableA, tableB,
			f.results[pod3A].HostTable, f.results[pod4B].HostTable)
	}
}

func (f *edgeFixture) testSocketForwardIsolation(t *testing.T) {
	expectIdentity(t, f.pods["pod1"], vrfA, wlDst, "workload-A")
	expectIdentity(t, f.pods["pod1"], vrfB, wlDst, "workload-B")
	expectIdentity(t, f.pods["pod2"], vrfA, wlDst, "workload-A")
}

func (f *edgeFixture) testSocketReturnUsesEachPodsNextHop(t *testing.T) {
	expectIdentity(t, f.wlA, "", netip.MustParseAddrPort("[fd00:aa::1]:8000"), "pod1-A")
	expectIdentity(t, f.wlA, "", netip.MustParseAddrPort("[fd00:aa::2]:8000"), "pod2-A")
	expectIdentity(t, f.wlB, "", netip.MustParseAddrPort("[fd00:aa::1]:8000"), "pod1-B")
}

func (f *edgeFixture) testPacketConsumerIsolation(t *testing.T) {
	a0, b0 := f.tunA.echoes.Load(), f.tunB.echoes.Load()
	if err := ping(f.wlA, siteHost, 128); err != nil {
		t.Fatalf("VPC A workload to site: %v", err)
	}
	if f.tunA.echoes.Load() != a0+1 || f.tunB.echoes.Load() != b0 {
		t.Fatalf("VPC A echo reached TUN A %d->%d, TUN B %d->%d", a0, f.tunA.echoes.Load(), b0, f.tunB.echoes.Load())
	}
	if err := ping(f.wlB, siteHost, 128); err != nil {
		t.Fatalf("VPC B workload to site: %v", err)
	}
	if f.tunA.echoes.Load() != a0+1 || f.tunB.echoes.Load() != b0+1 {
		t.Fatalf("VPC B echo reached TUN A %d, TUN B %d", f.tunA.echoes.Load(), f.tunB.echoes.Load())
	}
}

func (f *edgeFixture) testNoNeighborDiscoveryPerSiteAddress(t *testing.T) {
	for _, d := range []string{"fd00:5::2", "fd00:5::3", "fd00:5:0:1::9"} {
		if err := ping(f.wlA, netip.MustParseAddr(d), 128); err != nil {
			t.Fatalf("ping %s: %v", d, err)
		}
	}
	got := neighborsOn(t, f.host, "p3t")
	want := netip.MustParseAddr("fd00:aa::3")
	if len(got) != 1 || got[want] != netlink.NUD_PERMANENT {
		t.Fatalf("neighbors on p3t = %v, want only %s permanent", got, want)
	}
}

func (f *edgeFixture) testColdNeighborResolves(t *testing.T) {
	next := netip.MustParseAddr("fd00:aa::3")
	f.host.do(t, func() error {
		link, err := netlink.LinkByName("p3t")
		if err != nil {
			return err
		}
		return netlink.NeighDel(&netlink.Neigh{LinkIndex: link.Attrs().Index, Family: unix.AF_INET6, IP: next.AsSlice()})
	})
	if err := Readback(f.hostH, f.handles["pod3"], f.atts[pod3A]); !errors.Is(err, ErrDrift) {
		t.Fatalf("readback with neighbor removed = %v, want ErrDrift", err)
	}
	if err := ping(f.wlA, netip.MustParseAddr("fd00:5::7"), 128); err != nil {
		t.Fatalf("ping with cold neighbor: %v", err)
	}
	got := neighborsOn(t, f.host, "p3t")
	if _, ok := got[next]; !ok || len(got) != 1 {
		t.Fatalf("neighbors on p3t after resolution = %v, want only %s", got, next)
	}
	f.provision(t, pod3A)
	if got := neighborsOn(t, f.host, "p3t"); got[next] != netlink.NUD_PERMANENT {
		t.Fatalf("re-provision left neighbor state %#x, want permanent", got[next])
	}
}

func (f *edgeFixture) testMinimumIPv6MTU(t *testing.T) {
	if err := ping(f.wlA, siteHost, 1280); err != nil {
		t.Fatalf("1280-byte packet to site: %v", err)
	}
	if got := f.tunA.largest.Load(); got < 1280 {
		t.Fatalf("largest packet seen on TUN A = %d, want 1280", got)
	}
}

func (f *edgeFixture) testMissingHostRouteFailsInsideVRF(t *testing.T) {
	leaks := watchLeaks(t, f.host, "uplink0", siteHost)
	f.host.do(t, func() error {
		return netlink.RouteDel(&netlink.Route{Table: int(f.results[pod3A].HostTable), Dst: prefixNet(sitePrefix)})
	})
	if err := ping(f.wlA, siteHost, 128); !errors.Is(err, errUnreachable) {
		t.Fatalf("ping with site route removed = %v, want unreachable", err)
	}
	if got := leaks.stop(); got != 0 {
		t.Fatalf("uplink transmitted %d packets for the site while the VRF had no route", got)
	}
	f.provision(t, pod3A)
	if err := ping(f.wlA, siteHost, 128); err != nil {
		t.Fatalf("ping after repair: %v", err)
	}
}

func (f *edgeFixture) testMissingPodRouteFailsInsidePodVRF(t *testing.T) {
	leaks := watchLeaks(t, f.pods["pod1"], podEth0, workloadAddr)
	f.pods["pod1"].do(t, func() error {
		return netlink.RouteDel(&netlink.Route{Table: podTable, Dst: ip6Net("::/0"), Gw: net.ParseIP("fe80::1")})
	})
	if _, err := dialIdentity(f.pods["pod1"], vrfA, wlDst); err == nil {
		t.Fatal("VRF-bound dial succeeded with the pod VRF default removed")
	}
	if got := leaks.stop(); got != 0 {
		t.Fatalf("pod eth0 transmitted %d packets for a VRF-bound socket", got)
	}
	f.provision(t, "pod1/A")
	expectIdentity(t, f.pods["pod1"], vrfA, wlDst, "workload-A")
}

func (f *edgeFixture) testDetachedInterfaceFailsInsideVRF(t *testing.T) {
	leaks := watchLeaks(t, f.host, "uplink0", netip.MustParseAddr("fd00:aa::2"))
	f.pods["pod2"].do(t, func() error {
		link, err := netlink.LinkByName("a0")
		if err != nil {
			return err
		}
		return netlink.LinkDel(link)
	})
	if _, err := dialIdentity(f.wlA, "", netip.MustParseAddrPort("[fd00:aa::2]:8000")); err == nil {
		t.Fatal("dial to a detached attachment succeeded")
	}
	if got := leaks.stop(); got != 0 {
		t.Fatalf("uplink transmitted %d packets for a detached attachment", got)
	}
	f.provision(t, "pod2/A")
	expectIdentity(t, f.wlA, "", netip.MustParseAddrPort("[fd00:aa::2]:8000"), "pod2-A")
}

func (f *edgeFixture) testOwnershipIsChecked(t *testing.T) {
	impostor := f.atts["pod2/A"]
	impostor.ID = "uid-replacement"
	if err := Release(f.hostH, f.handles["pod2"], impostor); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release by another owner = %v, want ErrNotOwned", err)
	}
	if _, err := Provision(f.hostH, f.handles["pod2"], impostor); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("provision over another owner's link = %v, want ErrNotOwned", err)
	}
	expectIdentity(t, f.wlA, "", netip.MustParseAddrPort("[fd00:aa::2]:8000"), "pod2-A")
}

func (f *edgeFixture) testReleaseRemovesOnlyItsOwnState(t *testing.T) {
	if err := Release(f.hostH, f.handles["pod4"], f.atts[pod4B]); err != nil {
		t.Fatal(err)
	}
	if err := ping(f.wlB, siteHost, 128); !errors.Is(err, errUnreachable) {
		t.Fatalf("VPC B site after release = %v, want unreachable", err)
	}
	if err := ping(f.wlA, siteHost, 128); err != nil {
		t.Fatalf("VPC A site after releasing VPC B's attachment: %v", err)
	}
	if err := Release(f.hostH, f.handles["pod4"], f.atts[pod4B]); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func (f *edgeFixture) testReplacedSandboxIsRejected(t *testing.T) {
	replacement := newTestNS(t)
	path := f.pods["pod2"].Path()
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		t.Fatalf("unmount %s: %v", path, err)
	}
	if err := unix.Mount(replacement.Path(), path, "none", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind replacement namespace: %v", err)
	}
	if err := f.handles["pod2"].Verify(); !errors.Is(err, ErrNamespaceReplaced) {
		t.Fatalf("verify after replacement = %v, want ErrNamespaceReplaced", err)
	}
	fresh := f.atts["pod2/A"]
	fresh.ID, fresh.HostLink = "uid-pod2-a-new", "p2n"
	if _, err := Provision(f.hostH, f.handles["pod2"], fresh); !errors.Is(err, ErrNamespaceReplaced) {
		t.Fatalf("provision into a replaced sandbox = %v, want ErrNamespaceReplaced", err)
	}
	replacement.do(t, func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			if l.Attrs().Name != "lo" {
				t.Errorf("replacement namespace gained link %q", l.Attrs().Name)
			}
		}
		return nil
	})
}

func (f *edgeFixture) testSharedPrefixInOneVPCIsRefused(t *testing.T) {
	pod := newPod(t, f.host, "mgmt-pod5", 5)
	h := pod.open(t)
	a := f.atts[pod3A]
	a.ID, a.HostLink, a.Address = "uid-pod5-a", "p5t", netip.MustParseAddr("fd00:aa::5")
	a.TUN = &TUN{Name: tunName, Owner: 65534, Group: 65534}
	if _, err := Provision(f.hostH, h, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("second attachment for VPC A's site prefix = %v, want ErrNotOwned", err)
	}
	if err := Release(f.hostH, h, a); err != nil {
		t.Fatal(err)
	}
	if err := ping(f.wlA, siteHost, 128); err != nil {
		t.Fatalf("site behind the first attachment after the refused one was released: %v", err)
	}
}

func (f *edgeFixture) testTakenTUNNameIsRefused(t *testing.T) {
	pod := newPod(t, f.host, "mgmt-pod6", 6)
	h := pod.open(t)
	pod.do(t, func() error { return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: tunName}}) })
	a := f.atts["pod2/A"]
	a.ID, a.HostLink, a.Address = "uid-pod6-a", "p6t", netip.MustParseAddr("fd00:aa::6")
	a.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:7::/48")}
	a.TUN = &TUN{Name: tunName, Owner: 65534, Group: 65534}
	if _, err := Provision(f.hostH, h, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("TUN over an existing non-TUN link = %v, want ErrNotOwned", err)
	}
	pod.do(t, func() error {
		l, err := netlink.LinkByName(tunName)
		if err != nil {
			return err
		}
		if l.Type() != "dummy" || l.Attrs().Alias != "" || l.Attrs().MasterIndex != 0 {
			t.Errorf("existing %q was changed: type %s alias %q master %d",
				tunName, l.Type(), l.Attrs().Alias, l.Attrs().MasterIndex)
		}
		return nil
	})
	if err := Release(f.hostH, h, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release with another link at the TUN's name = %v, want ErrNotOwned", err)
	}
}

func (f *edgeFixture) testUnstampedPairIsAdopted(t *testing.T) {
	pod := newPod(t, f.host, "mgmt-pod7", 7)
	h := pod.open(t)
	a := f.atts["pod2/A"]
	a.ID, a.HostLink, a.Address = "uid-pod7-a", "p7a", netip.MustParseAddr("fd00:aa::7")
	// What a call that died between creating the pair and stamping it
	// leaves behind.
	pod.do(t, func() error {
		return netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: a.PodLink}, PeerName: a.HostLink,
			PeerNamespace: netlink.NsFd(int(f.host.Fd())),
		})
	})
	if _, err := Provision(f.hostH, h, a); err != nil {
		t.Fatalf("provision over an unstamped pair: %v", err)
	}
	t.Cleanup(func() { _ = Release(f.hostH, h, a) })
	expectIdentity(t, pod, vrfA, wlDst, "workload-A")
}

func (f *edgeFixture) testForwardingDriftIsRepaired(t *testing.T) {
	f.pods["pod3"].do(t, func() error {
		return os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("0"), 0o644)
	})
	if err := Readback(f.hostH, f.handles["pod3"], f.atts[pod3A]); !errors.Is(err, ErrDrift) {
		t.Fatalf("readback with pod forwarding off = %v, want ErrDrift", err)
	}
	f.provision(t, pod3A)
	if err := ping(f.wlA, siteHost, 128); err != nil {
		t.Fatalf("site after repairing forwarding: %v", err)
	}
}
