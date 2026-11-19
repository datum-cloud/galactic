// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/nodevpc"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
	"go.datum.net/galactic/internal/worker/hostscope"
	"go.datum.net/galactic/internal/worker/module"
)

const (
	hsNamespace = "galactic-system"
	hsRouter    = "node-a-router"
	hsLocator   = "2001:db8:10::/48"
	hsNodeID    = 7
	hsASN       = 65000
	// hsMTU is the tap MTU the test's CNI ADDs ask for.
	hsMTU = 1400
	// envoySA holds Envoy-style socket claims, a service attachment that
	// references a VPC's host VRF with no tap of its own.
	envoySA = "galactic-system/envoy"
	// sockPort is the port of the VRF-bound listener standing in for the
	// service's live socket.
	sockPort = 9000
)

// svcAtt is the service attachment of each VPC's Envoy-style claim, and
// guestAtt the guest it delivers to.
var (
	svcAtt   = map[string]string{vpcA: svcA, vpcB: svcB}
	guestAtt = map[string]string{vpcA: "guest-a1", vpcB: "guest-b1"}
)

const (
	svcA = "svc-a"
	svcB = "svc-b"
)

// tapAtt is the VPCAttachment of each VPC's guest tap. Both VPCs give their
// guest the same addresses (guestIPAM).
var tapAtt = map[string]string{vpcA: "a1", vpcB: "b1"}

// sockAddr is the address every VPC's live socket listens on; both VPCs use
// it, so only the VRF a packet travels in tells the listeners apart.
var sockAddr = netip.MustParseAddr("2001:db8:ee::1")

var guestIPAM = &cniipam.IPAMResult{
	IPv6Subnet:  &net.IPNet{IP: net.ParseIP("2001:db8:a::"), Mask: net.CIDRMask(64, 128)},
	IPv6Gateway: net.ParseIP("2001:db8:a::1"),
	IPv4Address: net.ParseIP("198.51.100.2").To4(),
	IPv4Gateway: net.ParseIP("198.51.100.1").To4(),
}

func init() {
	testCaps[envoySA] = []string{workerv1alpha1.CapabilityLocalSocket}
}

// nsHost runs another Host's calls inside a test network namespace, as the
// production Host runs in the host's, whichever goroutine Worker calls it
// from.
type nsHost struct {
	netns ns.NetNS
	inner hostscope.Host
}

func (h nsHost) do(fn func() error) error {
	var inner error
	if err := h.netns.Do(func(ns.NetNS) error { inner = fn(); return nil }); err != nil {
		return err
	}
	return inner
}

func (h nsHost) Discover(ctx context.Context) (out []string, err error) {
	err = h.do(func() error { out, err = h.inner.Discover(ctx); return err })
	return out, err
}

func (h nsHost) Plan(ctx context.Context, vpc string, claimed bool) (p hostscope.Plan, err error) {
	err = h.do(func() error { p, err = h.inner.Plan(ctx, vpc, claimed); return err })
	return p, err
}

func (h nsHost) Ensure(ctx context.Context, vpc string) error {
	return h.do(func() error { return h.inner.Ensure(ctx, vpc) })
}

func (h nsHost) Reclaim(ctx context.Context, vpc string) (gone bool, err error) {
	err = h.do(func() error { gone, err = h.inner.Reclaim(ctx, vpc); return err })
	return gone, err
}

func (h nsHost) Attachments(ctx context.Context, vpc string) (out []hostscope.Attachment, err error) {
	err = h.do(func() error { out, err = h.inner.Attachments(ctx, vpc); return err })
	return out, err
}

// hostFixture is one node's kernel, pinned maps and API objects, shared by a
// Worker under test and by the CNI and GC writes the test makes.
type hostFixture struct {
	t      *testing.T
	e      *env
	netns  ns.NetNS
	pinDir string
	k8s    client.Client
	guard  *maintenance.Guard
	// socks are the live VRF-bound listeners, by VPC.
	socks map[string]int
	node  attachreg.Node
}

func newHostFixture(t *testing.T) *hostFixture {
	t.Helper()
	requireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	netns, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Close()
		_ = testutils.UnmountNS(netns)
	})
	if err := netns.Do(func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(lo)
	}); err != nil {
		t.Fatal(err)
	}
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-worker-hostscope-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	scheme := k8sruntime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(discoveryv1.AddToScheme(scheme))
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: hsRouter, Namespace: hsNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: node},
			LocalASN:  hsASN, RouterID: "192.0.2.1", SRv6Locator: hsLocator, NodeID: hsNodeID,
			AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
		},
	}).Build()

	nodevpc.ArgumentLockDir = t.TempDir()
	e := newEnv(t)
	origDir := vpcfence.Dir
	vpcfence.Dir = e.fenceDir
	t.Cleanup(func() { vpcfence.Dir = origDir })
	e.cfg.HostGrace = 200 * time.Millisecond
	guard := &maintenance.Guard{Reader: k8s, NodeName: node, Ownership: e.fence,
		HostLinks: func() ([]hostattach.ObservedAttachment, error) { return nil, nil }}
	e.hostState = nsHost{netns: netns, inner: &hostscope.Kernel{
		K8s: k8s, Namespace: hsNamespace, Node: node, PinDir: pinDir, Edge: guard,
	}}
	f := &hostFixture{t: t, e: e, netns: netns, pinDir: pinDir, k8s: k8s, guard: guard,
		socks: map[string]int{}, node: attachreg.Node{Locator: hsLocator, NodeID: hsNodeID}}
	t.Cleanup(func() {
		for _, fd := range f.socks {
			_ = unix.Close(fd)
		}
		_ = netns.Do(func(ns.NetNS) error {
			for _, v := range []string{vpcA, vpcB, "vpcC"} {
				_ = vrf.Delete(v)
			}
			return nil
		})
	})
	return f
}

func (f *hostFixture) in(fn func() error) {
	f.t.Helper()
	if err := f.netns.Do(func(ns.NetNS) error { return fn() }); err != nil {
		f.t.Fatal(err)
	}
}

// cniAdd runs a tap-mode CNI ADD for vpc's guest as container cid: the tap
// and its VRF, the guest's host gateway, then galactic-bgp's Argument claim
// and datapath registration. fenced writes the VPC's shared state under its
// write fence, as CNI does now; unfenced is the CNI of the baseline, which
// wrote it directly.
func (f *hostFixture) cniAdd(vpc, cid string, fenced bool) error {
	write := func(fn func() error) error {
		if fenced {
			return vpcfence.Write(context.Background(), vpc, fn)
		}
		return fn()
	}
	att := tapAtt[vpc]
	return f.netns.Do(func(ns.NetNS) error {
		if err := write(func() error {
			return vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error {
				_, err := tap.Add(vpc, att, cid, hsMTU)
				return err
			})
		}); err != nil {
			return fmt.Errorf("tap ADD: %w", err)
		}
		if err := hostgw.ConfigureHostGateway(vpc, att, guestIPAM, nil); err != nil {
			return fmt.Errorf("host gateway: %w", err)
		}
		return write(func() error {
			vpcHex, err := intf.Base62ToHex(vpc)
			if err != nil {
				return err
			}
			rt, err := nodevpc.RouteTarget(hsASN, vpcHex)
			if err != nil {
				return err
			}
			id, _, err := nodevpc.ClaimArgument(context.Background(), f.k8s, hsNamespace, hsRouter,
				crdnames.BGPVRFInstanceName(vpc, node), false,
				func() ([]string, error) { return nil, nil },
				func(id int32) bgpv1alpha1.BGPVRFInstanceSpec { return nodevpc.InstanceSpec(hsRouter, rt, id) },
				func(arg int32) error { return attachreg.ReleaseArgument(f.pinDir, f.node, vpc, uint16(arg)) })
			if err != nil {
				return fmt.Errorf("claim Argument: %w", err)
			}
			_, err = attachreg.RegisterDatapath(f.pinDir, attachreg.Registration{
				Node: f.node, VPC: vpc, VPCAttachment: att, InterfaceType: attachreg.InterfaceTypeTap,
				Argument: uint16(id), LocalPrefixes: []string{"198.51.100.2/32", "2001:db8:a::/64"},
			})
			return err
		})
	})
}

// cniDel runs a tap-mode CNI DEL for vpc's guest as container cid and
// reports whether cid still owned the tap.
func (f *hostFixture) cniDel(vpc, cid string) (owned bool) {
	f.in(func() error {
		var err error
		owned, err = tap.Release(vpc, tapAtt[vpc], cid, func(ifindex uint32) error {
			return attachreg.UnregisterInterface(f.pinDir, ifindex)
		})
		return err
	})
	return owned
}

// listen opens vpc's live socket: a UDP listener bound to the VPC's host VRF
// on sockAddr, which it adds to the VRF device.
func (f *hostFixture) listen(vpc string) {
	f.t.Helper()
	f.in(func() error {
		name := intf.GenerateInterfaceNameVRF(vpc)
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: sockAddr.AsSlice(), Mask: net.CIDRMask(128, 128)},
			Flags: unix.IFA_F_NODAD}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("address %s: %w", name, err)
		}
		fd, err := vrfSocket(name)
		if err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet6{Port: sockPort, Addr: sockAddr.As16()}); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("bind in %s: %w", name, err)
		}
		f.socks[vpc] = fd
		return nil
	})
}

func vrfSocket(vrfName string) (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, vrfName); err != nil {
		_ = unix.Close(fd)
		return 0, fmt.Errorf("bind to %s: %w", vrfName, err)
	}
	return fd, nil
}

// probeSockets sends a datagram to sockAddr inside each VPC's VRF and
// requires the VPC's own live socket, opened before every step, to receive
// it and no other listener to.
func (f *hostFixture) probeSockets(step string) {
	f.t.Helper()
	for vpc := range f.socks {
		msg := []byte(step + "/" + vpc)
		f.in(func() error {
			fd, err := vrfSocket(intf.GenerateInterfaceNameVRF(vpc))
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			return unix.Sendto(fd, msg, 0, &unix.SockaddrInet6{Port: sockPort, Addr: sockAddr.As16()})
		})
		buf := make([]byte, 128)
		deadline := time.Now().Add(2 * time.Second)
		for {
			n, _, err := unix.Recvfrom(f.socks[vpc], buf, unix.MSG_DONTWAIT)
			if err == nil {
				if string(buf[:n]) != string(msg) {
					f.t.Fatalf("%s: VPC %s socket received %q, want %q", step, vpc, buf[:n], msg)
				}
				break
			}
			if !errors.Is(err, unix.EAGAIN) || time.Now().After(deadline) {
				f.t.Fatalf("%s: VPC %s live socket received nothing: %v", step, vpc, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		for other, fd := range f.socks {
			if other == vpc {
				continue
			}
			if n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err == nil {
				f.t.Fatalf("%s: VPC %s's datagram %q reached VPC %s's socket", step, vpc, buf[:n], other)
			}
		}
	}
}

// vpcState is what the test checks of one VPC after each step.
type vpcState struct {
	table    uint32
	argument uint16
	sid      netip.Addr
	// tapIndex is the guest tap's ifindex, or 0 with no tap.
	tapIndex int
	// guestRoutes are the links the VRF table routes the guest addresses
	// through.
	guestRoutes []int
}

func (f *hostFixture) state(vpc string) vpcState {
	f.t.Helper()
	var s vpcState
	f.in(func() error {
		table, err := vrf.TableID(vpc)
		if err != nil {
			return err
		}
		s.table = table
		if l, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(vpc, tapAtt[vpc])); err == nil {
			s.tapIndex = l.Attrs().Index
		}
		for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
			if err != nil {
				return err
			}
			for _, r := range routes {
				if r.Dst != nil && (r.Dst.Contains(guestIPAM.IPv4Address) || r.Dst.IP.Equal(guestIPAM.IPv6Subnet.IP)) &&
					r.Type == unix.RTN_UNICAST {
					s.guestRoutes = append(s.guestRoutes, r.LinkIndex)
				}
			}
		}
		return nil
	})
	var inst bgpv1alpha1.BGPVRFInstance
	if err := f.k8s.Get(context.Background(), client.ObjectKey{Namespace: hsNamespace,
		Name: crdnames.BGPVRFInstanceName(vpc, node)}, &inst); err != nil {
		f.t.Fatalf("BGPVRFInstance of %s: %v", vpc, err)
	}
	s.argument = uint16(inst.Spec.VRFID)
	sid, err := srv6.ComputeSID(hsLocator, hsNodeID, inst.Spec.VRFID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		f.t.Fatal(err)
	}
	s.sid = sid
	block, err := f.node.Block()
	if err != nil {
		f.t.Fatal(err)
	}
	reg, closer, err := usidmap.OpenPinnedRegistry(f.pinDir)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	row, ok, err := reg.VRF.Get(block, s.argument)
	if err != nil || !ok || row.VRFTableID != s.table {
		f.t.Fatalf("VPC %s: vrf_table row for Argument %d = %+v (present %t, %v), want table %d",
			vpc, s.argument, row, ok, err, s.table)
	}
	return s
}

// instances counts the BGPVRFInstances of vpc on the node.
func (f *hostFixture) instances(vpc string) int {
	f.t.Helper()
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := f.k8s.List(context.Background(), list, client.InNamespace(hsNamespace)); err != nil {
		f.t.Fatal(err)
	}
	n := 0
	for _, i := range list.Items {
		if i.Name == crdnames.BGPVRFInstanceName(vpc, node) {
			n++
		}
	}
	return n
}

// checkStep verifies, after a step, the table, route, SID and live socket of
// both VPCs, which use the same guest addresses: each VPC keeps the table and
// SID it had, the two never share either, each guest route goes through the
// VPC's own current tap, and each live socket still receives in its own VRF.
func (f *hostFixture) checkStep(step string, want map[string]vpcState) map[string]vpcState {
	f.t.Helper()
	got := map[string]vpcState{}
	for _, vpc := range []string{vpcA, vpcB} {
		s := f.state(vpc)
		if n := f.instances(vpc); n != 1 {
			f.t.Fatalf("%s: VPC %s has %d BGPVRFInstances, want 1", step, vpc, n)
		}
		if w, ok := want[vpc]; ok && (w.table != s.table || w.argument != s.argument || w.sid != s.sid) {
			f.t.Fatalf("%s: VPC %s moved: table %d → %d, Argument %d → %d, SID %s → %s",
				step, vpc, w.table, s.table, w.argument, s.argument, w.sid, s.sid)
		}
		for _, idx := range s.guestRoutes {
			if idx != s.tapIndex {
				f.t.Fatalf("%s: VPC %s routes its guest through ifindex %d, not its tap %d", step, vpc, idx, s.tapIndex)
			}
		}
		if (s.tapIndex != 0) != (len(s.guestRoutes) == 2) {
			f.t.Fatalf("%s: VPC %s tap %d with guest routes %v, want both families through a live tap or none",
				step, vpc, s.tapIndex, s.guestRoutes)
		}
		got[vpc] = s
	}
	if got[vpcA].table == got[vpcB].table || got[vpcA].argument == got[vpcB].argument {
		f.t.Fatalf("%s: VPCs share host state: %+v and %+v", step, got[vpcA], got[vpcB])
	}
	f.probeSockets(step)
	return got
}

// observedIndex returns the ifindex Worker's host reads for vpc's tap now.
func (f *hostFixture) observedIndex(vpc string) int {
	f.t.Helper()
	atts, err := f.e.hostState.Attachments(context.Background(), vpc)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, a := range atts {
		if a.Name == intf.GenerateInterfaceNameHost(vpc, tapAtt[vpc]) {
			return a.Index
		}
	}
	return 0
}

func socketSpec(uid string) *workerv1alpha1.ClaimSpec {
	return spec(workerv1alpha1.Handoff_HANDOFF_SOCKET, uid)
}

// TestHostScopeTwoVPCsSameGuestIP is #1434's acceptance sequence. CNI ADDs
// and Envoy-style socket claims interleave for two VPCs whose guests use the
// same addresses, and every step checks the table, route, SID and live socket
// of both:
//
//  1. Replace one tap.
//  2. Remove the last tap while an Envoy claim references the VPC.
//  3. Restart Worker.
//  4. Replay a stale DEL.
//
// A last step releases the claim and lets Worker, the scope's owner, reclaim
// the unused VPC.
func TestHostScopeTwoVPCsSameGuestIP(t *testing.T) {
	f := newHostFixture(t)
	e := f.e
	e.start()

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for _, v := range []string{vpcA, vpcB} {
		wg.Add(2)
		go func() { defer wg.Done(); errs <- f.cniAdd(v, "c1-"+v, true) }()
		go func() {
			defer wg.Done()
			errs <- e.request(envoySA, key(v, svcAtt[v]), 1, socketSpec(guestAtt[v]))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		e.mustOK(err)
	}
	e.waitReady(mkey(vpcA, svcA), 1)
	e.waitReady(mkey(vpcB, svcB), 1)
	e.idle()
	f.listen(vpcA)
	f.listen(vpcB)
	base := f.checkStep("interleaved ADDs and claims", nil)
	for _, v := range []string{vpcA, vpcB} {
		if got := f.observedIndex(v); got != base[v].tapIndex {
			t.Fatalf("Worker observes %s's tap at %d, want %d", v, got, base[v].tapIndex)
		}
		if r := e.fenceOwner(v); r.Owner != e.w.Owner() {
			t.Fatalf("VPC %s scope owner = %q, want this Worker", v, r.Owner)
		}
	}

	// 1. Replace VPC A's tap: the predecessor's DEL, then the successor's
	// ADD, which gets a new ifindex.
	if !f.cniDel(vpcA, "c1-"+vpcA) {
		t.Fatal("DEL of the tap's own container found it owned by another")
	}
	e.mustOK(f.cniAdd(vpcA, "c2-"+vpcA, true))
	e.idle()
	s1 := f.checkStep("replace a tap", base)
	if s1[vpcA].tapIndex == base[vpcA].tapIndex {
		t.Fatal("the replacement tap kept its predecessor's ifindex")
	}
	if got := f.observedIndex(vpcA); got != s1[vpcA].tapIndex {
		t.Fatalf("Worker observes the replaced tap at %d, want the new ifindex %d", got, s1[vpcA].tapIndex)
	}

	// 2. Remove VPC A's last tap while the Envoy claim references the VPC.
	// Neither galactic-router's GC, which reclaims a VPC with no tap and no
	// advertisement, nor Worker past its grace removes the VPC's state. A
	// VRF no writer owns, in the same GC pass, is reclaimed: GC ran.
	if !f.cniDel(vpcA, "c2-"+vpcA) {
		t.Fatal("DEL of the tap's own container found it owned by another")
	}
	f.in(func() error { return vrf.Add("vpcC") })
	e.clock.Advance(time.Hour)
	e.w.HostChanged(vpcA)
	time.Sleep(2 * e.cfg.HostGrace)
	e.idle()
	f.in(func() error {
		res := gc.RunGC(context.Background(), f.k8s, hsNamespace, node, f.guard)
		if res.Errors != 0 {
			return fmt.Errorf("GC pass reported %d errors", res.Errors)
		}
		return nil
	})
	f.in(func() error {
		if _, err := vrf.TableID("vpcC"); !errors.Is(err, vrf.ErrNotFound) {
			return fmt.Errorf("GC left the unowned control VRF: %w", err)
		}
		return nil
	})
	s2 := f.checkStep("remove the last tap with an Envoy reference", s1)
	if s2[vpcA].tapIndex != 0 {
		t.Fatal("VPC A's tap survived its DEL")
	}
	e.waitReady(mkey(vpcA, svcA), 1)

	// 3. Restart Worker. The new incarnation takes every scope over with a
	// snapshot that changes nothing on the host.
	before := hostSnapshot(t, f.netns, f.pinDir, f.k8s)
	oldOwner := e.w.Owner()
	e.crash()
	e.start()
	for _, v := range []string{vpcA, vpcB} {
		e.eventually("scope "+v+" taken over", func() bool {
			r := e.fenceOwner(v)
			return r.Owner == e.w.Owner() && !r.Pending
		})
	}
	if e.w.Owner() == oldOwner {
		t.Fatal("the restarted Worker reused its owner ID")
	}
	e.waitReady(mkey(vpcA, svcA), 1)
	e.waitReady(mkey(vpcB, svcB), 1)
	e.idle()
	if after := hostSnapshot(t, f.netns, f.pinDir, f.k8s); !slices.Equal(before, after) {
		t.Fatalf("restart changed host state:\n%s", diffLines(before, after))
	}
	s3 := f.checkStep("restart Worker", s2)

	// 4. Replay a stale DEL. VPC B's successor container takes the tap over
	// first; the predecessor's delayed DEL then leaves the tap, its ifindex
	// rows and its route alone.
	e.mustOK(f.cniAdd(vpcB, "c2-"+vpcB, true))
	if f.cniDel(vpcB, "c1-"+vpcB) {
		t.Fatal("the stale DEL found the successor's tap owned by its predecessor")
	}
	e.idle()
	s4 := f.checkStep("replay a stale DEL", s3)
	if s4[vpcB].tapIndex != s3[vpcB].tapIndex {
		t.Fatalf("VPC B's tap moved from %d to %d", s3[vpcB].tapIndex, s4[vpcB].tapIndex)
	}
	table, closer, err := ifindexvrfmap.OpenPinned(f.pinDir)
	e.mustOK(err)
	row, ok, err := table.Get(uint32(s4[vpcB].tapIndex))
	_ = closer.Close()
	if err != nil || !ok || row.Argument != s4[vpcB].argument {
		t.Fatalf("ifindex_vrf_table row of VPC B's tap = %+v (present %t, %v), want Argument %d",
			row, ok, err, s4[vpcB].argument)
	}

	// Release the Envoy claim: VPC A is now unused, and once the grace
	// passes Worker reclaims its VRF and BGPVRFInstance as the scope owner.
	e.mustOK(e.release(envoySA, key(vpcA, svcA), 1))
	e.waitGone(mkey(vpcA, svcA))
	e.w.HostChanged(vpcA)
	e.idle()
	e.clock.Advance(time.Hour)
	e.eventually("VPC A reclaimed", func() bool {
		var gone bool
		_ = f.netns.Do(func(ns.NetNS) error {
			_, err := vrf.TableID(vpcA)
			gone = errors.Is(err, vrf.ErrNotFound)
			return nil
		})
		return gone && f.instances(vpcA) == 0
	})
	_ = unix.Close(f.socks[vpcA])
	delete(f.socks, vpcA)
	if s := f.state(vpcB); s.table != s4[vpcB].table || s.argument != s4[vpcB].argument {
		t.Fatalf("reclaiming VPC A changed VPC B: %+v → %+v", s4[vpcB], s)
	}
	f.probeSockets("reclaim the unused VPC")
}

// TestAttachWithWorkerDown attaches a workload while no Worker runs, first on
// a scope an earlier incarnation owned and then on one it left between Fence
// and Adopt. Both ADDs succeed, the second once a Worker takes the scope
// over, and the started Worker converges on the state CNI wrote.
func TestAttachWithWorkerDown(t *testing.T) {
	f := newHostFixture(t)
	e := f.e
	dead := ownership.WorkerOwnerPrefix + node + ":dead"
	tk, err := e.fence.Claim(module.Scope{VPC: vpcA}.Name(), dead)
	e.mustOK(err)
	_, err = e.fence.CommitSnapshot(tk, func() error { return nil })
	e.mustOK(err)
	tk, err = e.fence.Claim(module.Scope{VPC: vpcB}.Name(), dead)
	e.mustOK(err)
	_, err = e.fence.CommitSnapshot(tk, func() error { return nil })
	e.mustOK(err)
	_, err = e.fence.Fence(module.Scope{VPC: vpcB}.Name())
	e.mustOK(err)

	e.mustOK(f.cniAdd(vpcA, "c1-"+vpcA, true))
	addB := make(chan error, 1)
	go func() { addB <- f.cniAdd(vpcB, "c1-"+vpcB, true) }()
	select {
	case err := <-addB:
		t.Fatalf("ADD into a transitioning scope returned %v before any Worker ran", err)
	case <-time.After(300 * time.Millisecond):
	}

	e.start()
	select {
	case err := <-addB:
		e.mustOK(err)
	case <-time.After(10 * time.Second):
		t.Fatal("ADD still waiting after Worker took the scope over")
	}
	for _, v := range []string{vpcA, vpcB} {
		e.eventually("scope "+v+" taken over", func() bool {
			r := e.fenceOwner(v)
			return r.Owner == e.w.Owner() && !r.Pending && !r.Transitioning
		})
	}
	e.idle()
	f.listen(vpcA)
	f.listen(vpcB)
	base := f.checkStep("attach with Worker down", nil)

	// The claims Worker serves once it returns converge on the VRF and
	// Argument CNI created.
	e.mustOK(e.request(envoySA, key(vpcA, svcA), 1, socketSpec("guest-a1")))
	e.mustOK(e.request(envoySA, key(vpcB, svcB), 1, socketSpec("guest-b1")))
	e.waitReady(mkey(vpcA, svcA), 1)
	e.waitReady(mkey(vpcB, svcB), 1)
	e.idle()
	f.checkStep("Worker returns", base)
}

// TestLegacyAdoptionUnchanged builds node state the way the baseline CNI did,
// writing shared state with no fence, then starts Worker. Worker takes every
// scope, and links, routes, rules, every pinned map row and the
// BGPVRFInstances stay byte-for-byte as they were.
func TestLegacyAdoptionUnchanged(t *testing.T) {
	f := newHostFixture(t)
	e := f.e
	for _, v := range []string{vpcA, vpcB} {
		e.mustOK(f.cniAdd(v, "c1-"+v, false))
	}
	before := hostSnapshot(t, f.netns, f.pinDir, f.k8s)
	for _, v := range []string{vpcA, vpcB} {
		if r := e.fenceOwner(v); r.Owner != "" || r.Revision != 0 {
			t.Fatalf("baseline CNI touched the fence of %s: %+v", v, r)
		}
	}

	e.start()
	for _, v := range []string{vpcA, vpcB} {
		e.eventually("scope "+v+" adopted", func() bool {
			r := e.fenceOwner(v)
			return r.Owner == e.w.Owner() && !r.Pending
		})
	}
	e.idle()
	if after := hostSnapshot(t, f.netns, f.pinDir, f.k8s); !slices.Equal(before, after) {
		t.Fatalf("adoption changed host state:\n%s", diffLines(before, after))
	}
}

// hostSnapshot renders every link, route, rule, pinned map row and
// BGPVRFInstance the test's node holds, sorted. Per-CPU maps, which hold
// only counters, are left out.
func hostSnapshot(t *testing.T, netns ns.NetNS, pinDir string, k8s client.Client) []string {
	t.Helper()
	var out []string
	err := netns.Do(func(ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			a := l.Attrs()
			out = append(out, fmt.Sprintf("link %d %s %s master=%d mtu=%d flags=%s alias=%q",
				a.Index, a.Name, l.Type(), a.MasterIndex, a.MTU, a.Flags, a.Alias))
		}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			out = append(out, fmt.Sprintf("route table=%d dst=%s dev=%d type=%d src=%s gw=%s",
				r.Table, r.Dst, r.LinkIndex, r.Type, r.Src, r.Gw))
		}
		rules, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, r := range rules {
			out = append(out, fmt.Sprintf("rule family=%d prio=%d table=%d", r.Family, r.Priority, r.Table))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, ent.Name()), nil)
		if err != nil {
			continue // a pinned program
		}
		switch m.Type() {
		case ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUCPUHash, ebpf.ProgramArray, ebpf.PerfEventArray,
			ebpf.RingBuf:
			_ = m.Close()
			continue
		}
		var k, v []byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			out = append(out, fmt.Sprintf("map %s %s=%s", ent.Name(), hex.EncodeToString(k), hex.EncodeToString(v)))
		}
		if err := it.Err(); err != nil {
			t.Fatalf("iterate %s: %v", ent.Name(), err)
		}
		_ = m.Close()
	}
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	for _, i := range list.Items {
		out = append(out, fmt.Sprintf("instance %s vrfID=%d rv=%s", i.Name, i.Spec.VRFID, i.ResourceVersion))
	}
	sort.Strings(out)
	return out
}

func diffLines(before, after []string) string {
	var out strings.Builder
	for _, l := range before {
		if !slices.Contains(after, l) {
			out.WriteString("- " + l + "\n")
		}
	}
	for _, l := range after {
		if !slices.Contains(before, l) {
			out.WriteString("+ " + l + "\n")
		}
	}
	return out.String()
}
