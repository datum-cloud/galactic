// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

// readyRig returns a plain native rig whose VPCs have a ready local.tap and
// local.veth_pair claim, with the NAT stand-in in place.
func readyRig(t *testing.T, cell string) *rig {
	t.Helper()
	r := newRig(t, cell, xdpmode.Native)
	for _, v := range r.vpcs {
		r.reconcile(v.vpc, r.claims(v))
		r.natStandIn(v)
		wantReady(t, r.reconcile(v.vpc, r.claims(v)), r.claims(v))
	}
	return r
}

// read reads vpc's state without planning, as after a change Worker has not
// reconciled yet.
func (r *rig) read(vpc string) module.State {
	r.t.Helper()
	var st module.State
	r.in(r.node, func() error {
		var err error
		st, err = r.mod.Read(context.Background(), module.Scope{VPC: vpc})
		return err
	})
	return st
}

// TestUntrustedEntryRoot checks that a packet that is not claimed, or claims
// a handoff it was not given, enters none: metadata with a wrong magic, as a
// sender without the dispatcher could forge it at best; metadata naming a TAP
// no claim authorizes; a NAT return toward an address no claim delivers to;
// and a packet straight to a guest address, which public ingress cannot
// reach at all.
func TestUntrustedEntryRoot(t *testing.T) {
	r := readyRig(t, "trust")
	a := r.vpcs[0]
	// A TAP in VPC A that no claim names.
	stray := &vpcRig{vpc: a.vpc, argument: 0x90, table: a.table}
	stray.tap = intf.GenerateInterfaceNameHost(a.vpc, "002")
	r.addTap(stray)
	sock := r.clientSocket(40000)

	forged := netip.MustParseAddr("2001:db8:4135:a::f0")
	r.vip(forged, a.tapIdx, 0x0bad0bad)
	before := r.stats()
	sock.send(t, forged, 7, "forged-magic")
	a.guest.absent(t, "forged-magic")

	unclaimed := netip.MustParseAddr("2001:db8:4135:a::f1")
	r.vip(unclaimed, stray.tapIdx, 0)
	sock.send(t, unclaimed, 7, "unclaimed-tap")
	stray.guest.absent(t, "unclaimed-tap")

	r.in(r.client, func() error {
		l, err := netlink.LinkByName(r.clientIf)
		if err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index,
			Dst: ipnet(netip.MustParsePrefix("fd20::/16")), Gw: net.IP(nodeAddr.AsSlice())})
	})
	sock.send(t, guestAddr, 7, "straight-to-guest")
	a.guest.absent(t, "straight-to-guest")
	r.vpcs[1].guest.absent(t, "straight-to-guest")

	after := r.stats()
	if after["rx_no_meta"] <= before["rx_no_meta"] || after["rx_unclaimed"] != before["rx_unclaimed"]+1 {
		t.Fatalf("counters before %v after %v: the forged and unclaimed packets were not refused", before, after)
	}
	if after["rx_deliver"] != before["rx_deliver"] {
		t.Fatalf("an untrusted packet was delivered: before %v after %v", before, after)
	}

	// The NAT stand-in sends a return for an address no claim names into
	// VPC A's pair; the pair delivers it nowhere.
	ghost := netip.MustParseAddr("2001:db8:4135:5::f2")
	ret, err := r.fixShard(a.shard)
	if err != nil {
		t.Fatal(err)
	}
	ret.Guest = netip.MustParseAddr("fd20:80:ff03::99").As16()
	if err := r.fixPutShard(ghost, ret); err != nil {
		t.Fatal(err)
	}
	before = r.stats()
	sock.send(t, ghost, 5555, "ghost-return")
	a.guest.absent(t, "ghost-return")
	stray.guest.absent(t, "ghost-return")
	after = r.stats()
	if after["pair_unclaimed"] <= before["pair_unclaimed"] || after["pair_deliver"] != before["pair_deliver"] {
		t.Fatalf("counters before %v after %v: the unclaimed return was not refused", before, after)
	}
}

// TestHookWithdrawalAndRepairRoot checks that each hook a handoff depends on
// withdraws readiness when it goes, and that Local's own hooks are put back.
func TestHookWithdrawalAndRepairRoot(t *testing.T) {
	r := readyRig(t, "hooks")
	a := r.vpcs[0]
	claims := r.claims(a)
	tapClaim, natClaim := claims[0], claims[1]
	pairTenant := linkName(a.vpc, a.natUID, intf.LocalRolePairTenant)
	pairNAT := linkName(a.vpc, a.natUID, intf.LocalRolePairNAT)

	// Local's program on the TAP: both handoffs lose their return.
	r.in(r.node, func() error { return attach.DetachLocal(a.tap) })
	st := r.read(a.vpc)
	wantState(t, st, tapClaim, true, true, false, workerv1alpha1.ReasonHandoffHookMissing)
	wantState(t, st, natClaim, true, true, false, workerv1alpha1.ReasonHandoffHookMissing)
	if r.planEmpty(a.vpc, claims) {
		t.Fatal("a missing Local filter planned no repair")
	}
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// local_rx on the receiving device: local.tap loses its forward path.
	r.in(r.node, func() error { return attach.DetachLocal(r.rx) })
	wantState(t, r.read(a.vpc), tapClaim, true, false, true, workerv1alpha1.ReasonHandoffHookMissing)
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// Local's program on the pair's tenant end: the pair loses its forward
	// path.
	r.in(r.node, func() error { return attach.DetachLocal(pairTenant) })
	wantState(t, r.read(a.vpc), natClaim, true, false, true, workerv1alpha1.ReasonHandoffHookMissing)
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// Local's XDP on the pair's tenant end, which receiving the NAT end's
	// redirected return needs.
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(pairTenant)
		if err != nil {
			return err
		}
		return netlink.LinkSetXdpFdWithFlags(l, -1, xdpDrvMode)
	})
	wantState(t, r.read(a.vpc), natClaim, true, false, true, workerv1alpha1.ReasonHandoffHookMissing)
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// The dispatcher's public slot: an empty or expired slot is no
	// receiving path, and Local cannot repair it.
	r.in(r.node, func() error {
		lock, err := r.disp.Lock(context.Background())
		if err != nil {
			return err
		}
		defer lock.Unlock()
		return lock.Clear(xdpdispatch.SlotGatewayLB)
	})
	wantState(t, r.reconcile(a.vpc, claims), tapClaim, true, false, true, workerv1alpha1.ReasonDispatcherSlotUnclaimed)
	r.in(r.node, func() error {
		lock, err := r.disp.Lock(context.Background())
		if err != nil {
			return err
		}
		defer lock.Unlock()
		return lock.Fill(xdpdispatch.SlotGatewayLB, r.fix.LtfGateway)
	})
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// The client's program on the NAT end: gone, then generic, which never
	// sees what Local redirects into the pair.
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(pairNAT)
		if err != nil {
			return err
		}
		return netlink.LinkSetXdpFd(l, -1)
	})
	wantState(t, r.reconcile(a.vpc, claims), natClaim, true, true, false, workerv1alpha1.ReasonHandoffHookMissing)
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(pairNAT)
		if err != nil {
			return err
		}
		return netlink.LinkSetXdpFdWithFlags(l, r.fix.LtfNat.FD(), 1<<1) // XDP_FLAGS_SKB_MODE
	})
	wantState(t, r.reconcile(a.vpc, claims), natClaim, true, true, false, workerv1alpha1.ReasonHookUnsupported)
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(pairNAT)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetXdpFdWithFlags(l, -1, 1<<1); err != nil { // XDP_FLAGS_SKB_MODE
			return err
		}
		return netlink.LinkSetXdpFdWithFlags(l, r.fix.LtfNat.FD(), xdpDrvMode)
	})
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// galactic-cni's chain, as another tc owner adopting the TAP removes
	// it: Local reports the interface missing and does not write CNI's
	// filters itself.
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(a.tap)
		if err != nil {
			return err
		}
		filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			return err
		}
		for _, f := range filters {
			if err := netlink.FilterDel(f); err != nil {
				return err
			}
		}
		return nil
	})
	wantState(t, r.reconcile(a.vpc, claims), tapClaim, true, false, false, workerv1alpha1.ReasonHandoffInterfaceMissing)
	r.in(r.node, func() error { return attach.AttachDeliver(r.usid.TpDeliver, a.tap) })
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	// A TAP whose MTU is below the receiving device's would lose what the
	// redirect does not check.
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(a.tap)
		if err != nil {
			return err
		}
		return netlink.LinkSetMTU(l, 1280)
	})
	wantState(t, r.reconcile(a.vpc, claims), tapClaim, true, false, true, workerv1alpha1.ReasonHandoffMTUTooSmall)
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(a.tap)
		if err != nil {
			return err
		}
		return netlink.LinkSetMTU(l, 1500)
	})
	wantReady(t, r.reconcile(a.vpc, claims), claims)
}

// TestColdNeighborRoot checks that delivery to a TAP whose guest has no
// neighbor entry resolves the neighbor and delivers, on both handoffs.
func TestColdNeighborRoot(t *testing.T) {
	r := readyRig(t, "neigh")
	a := r.vpcs[0]
	flush := func() {
		r.in(r.node, func() error {
			err := netlink.NeighDel(&netlink.Neigh{LinkIndex: a.tapIdx, Family: netlink.FAMILY_V6,
				IP: net.IP(guestAddr.AsSlice())})
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			return nil
		})
	}
	sock := r.clientSocket(40000)
	flush()
	sock.send(t, a.vip, 7, "cold-tap")
	a.guest.expect(t, "cold-tap")
	flush()
	sock.send(t, a.shard, 5555, "cold-nat")
	a.guest.expect(t, "cold-nat")
	r.in(r.node, func() error {
		neighs, err := netlink.NeighList(a.tapIdx, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		for _, n := range neighs {
			if n.IP.Equal(net.IP(guestAddr.AsSlice())) && n.HardwareAddr.String() == guestMAC.String() {
				return nil
			}
		}
		t.Fatalf("the guest's neighbor was not resolved: %v", neighs)
		return nil
	})
}

// TestIfindexReplacementRoot checks that a TAP CNI replaces under the same
// name, with a new ifindex, is reprogrammed and delivers again, and that the
// old ifindex's rows go.
func TestIfindexReplacementRoot(t *testing.T) {
	r := readyRig(t, "replace")
	a := r.vpcs[0]
	claims := r.claims(a)
	old := a.tapIdx
	a.guest.close()
	r.in(r.node, func() error {
		for range 50 {
			if _, err := netlink.LinkByName(a.tap); err != nil {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return errors.New("the TAP outlived its reader")
	})
	st := r.read(a.vpc)
	wantState(t, st, claims[0], false, false, false, workerv1alpha1.ReasonHandoffInterfaceMissing)
	r.addTap(a)
	if a.tapIdx == old {
		t.Fatalf("the replacement TAP kept ifindex %d", old)
	}
	r.vip(a.vip, a.tapIdx, 0)
	wantState(t, r.read(a.vpc), claims[0], false, false, false, workerv1alpha1.ReasonPending)
	if r.planEmpty(a.vpc, claims) {
		t.Fatal("a replaced TAP planned nothing")
	}
	wantReady(t, r.reconcile(a.vpc, claims), claims)

	sock := r.clientSocket(40000)
	sock.send(t, a.vip, 7, "after-replace-tap")
	a.guest.expect(t, "after-replace-tap")
	a.guest.send(t, a.vip, client, 7, 40000, "after-replace-reply", false)
	sock.expect(t, a.vip, "after-replace-reply")
	sock.send(t, a.shard, 5555, "after-replace-nat")
	a.guest.expect(t, "after-replace-nat")

	for _, name := range []string{"lt_tap", "lt_link"} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(r.pin, "local", name), nil)
		if err != nil {
			t.Fatal(err)
		}
		v, err := m.LookupBytes(uint32(old))
		_ = m.Close()
		if err != nil || v != nil {
			t.Fatalf("%s kept the old ifindex %d's row (%v)", name, old, err)
		}
	}
}

// TestPartialChecksumRoot checks the pair's tenant end finishes a guest's
// partial checksum before the NAT program rewrites the address, which a
// rewrite in XDP otherwise corrupts (docs/worker/qualification.md).
func TestPartialChecksumRoot(t *testing.T) {
	r := readyRig(t, "csum")
	a := r.vpcs[0]
	claims := r.claims(a)
	sock := r.clientSocket(40000)
	a.guest.send(t, guestAddr, client, 5555, 40000, "partial-1", true)
	sock.expect(t, a.shard, "partial-1")

	// Without the setting, the same frame reaches the client corrupted and
	// its kernel drops it.
	tenant := linkName(a.vpc, a.natUID, intf.LocalRolePairTenant)
	r.in(r.node, func() error {
		et, err := ethtool.NewEthtool()
		if err != nil {
			return err
		}
		defer et.Close()
		return et.Change(tenant, map[string]bool{featureTxChecksum: true})
	})
	a.guest.send(t, guestAddr, client, 5555, 40000, "partial-2", true)
	sock.absent(t, "partial-2")

	if r.planEmpty(a.vpc, claims) {
		t.Fatal("a changed feature planned no repair")
	}
	r.reconcile(a.vpc, claims)
	a.guest.send(t, guestAddr, client, 5555, 40000, "partial-3", true)
	sock.expect(t, a.shard, "partial-3")
}

// TestRoutedLinkRoot checks local.routed_link: the link reaches the owner's
// pod and only it, both directions route through the VPC's VRF, the guard
// drops a source the pod was not given, the client learns both ends, and the
// link follows the owner to a new pod.
func TestRoutedLinkRoot(t *testing.T) {
	r := newRig(t, "routed", xdpmode.Native)
	a := r.vpcs[0]
	pod, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pod.Close() })
	r.pods.add("pod-1", pod)
	dest := module.Destination{ID: "attachment/" + a.attUID, Mode: workerv1alpha1.Mode_MODE_LOCAL, VPC: a.vpc,
		Node: testNode, Addresses: []netip.Addr{guestAddr}, HostInterface: a.tap}
	claim := module.Claim{Key: module.ClaimKey{Node: testNode, VPC: a.vpc, AttachmentUID: "envoy-1"},
		Owner: "galactic-system/envoy", Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		OwnerPod: "pod-1", Addresses: []netip.Addr{podAddr}, Destinations: []module.Destination{dest}}
	claims := []module.Claim{claim}

	wantReady(t, r.reconcile(a.vpc, claims), claims)
	host := linkName(a.vpc, "envoy-1", intf.LocalRoleRoutedHost)
	podEnd := linkName(a.vpc, "envoy-1", intf.LocalRoleRoutedPod)
	got := r.mod.HandoffInterfaces(module.Scope{VPC: a.vpc})[claim.Key]
	if len(got) != 2 || got[0].Role != workerv1alpha1.HandoffRoleHost || got[0].Name != host ||
		got[1].Role != workerv1alpha1.HandoffRolePod || got[1].Name != podEnd {
		t.Fatalf("handoff interfaces %+v, want the host end %s and the pod end %s", got, host, podEnd)
	}
	if row, ok, err := r.routes.LookupRow(a.table, ipnet(netip.PrefixFrom(podAddr, 128))); err != nil || !ok ||
		!row.PassThrough {
		t.Fatalf("the pod address has no pass-through entry: %+v %t %v", row, ok, err)
	}

	routedTraffic(t, r, a, pod, host, podEnd)

	// The owner's pod is replaced: the link moves to the new pod and the
	// old pod keeps nothing.
	pod2, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pod2.Close() })
	r.pods.add("pod-2", pod2)
	claims[0].OwnerPod = "pod-2"
	if r.planEmpty(a.vpc, claims) {
		t.Fatal("a new pod planned nothing")
	}
	r.reconcile(a.vpc, claims)
	for p, want := range map[ns.NetNS]bool{pod: false, pod2: true} {
		if err := p.Do(func(ns.NetNS) error {
			_, err := netlink.LinkByName(podEnd)
			if (err == nil) != want {
				t.Errorf("pod end present %t in %s, want %t", err == nil, p.Path(), want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The owner's pod is gone: the claim waits for it.
	claims[0].OwnerPod = "pod-3"
	st := r.reconcile(a.vpc, claims)
	wantState(t, st, claims[0], false, false, false, workerv1alpha1.ReasonHandoffInterfaceMissing)
}

// TestWithdrawalRoot checks that releasing every claim removes everything
// Local programmed, that a claim's links are reported until they are gone,
// and that CNI's state stays.
func TestWithdrawalRoot(t *testing.T) {
	r := readyRig(t, "withdraw")
	a := r.vpcs[0]
	natKey := r.claims(a)[1].Key

	// Before Apply, the released claim's pair keeps it reported.
	var st module.State
	r.in(r.node, func() error {
		ctx := context.Background()
		if _, err := r.mod.Plan(ctx, module.Scope{VPC: a.vpc}, nil); err != nil {
			return err
		}
		var err error
		st, err = r.mod.Read(ctx, module.Scope{VPC: a.vpc})
		return err
	})
	if _, ok := st[natKey][leftoverID]; !ok {
		t.Fatalf("the released claim's pair is not reported: %v", st)
	}

	for _, v := range r.vpcs {
		if st := r.reconcile(v.vpc, nil); len(st) != 0 {
			t.Fatalf("VPC %s still reports %v after its claims were released", v.vpc, st)
		}
		if !r.planEmpty(v.vpc, nil) {
			t.Fatalf("VPC %s: a released scope would write again", v.vpc)
		}
	}
	r.in(r.node, func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			if intf.IsLocalLinkName(l.Attrs().Name) {
				t.Errorf("Local link %s outlived its claim", l.Attrs().Name)
			}
			if _, _, ok, err := attach.LocalFilter(l.Attrs().Index); err == nil && ok {
				t.Errorf("a Local filter outlived its claim on %s", l.Attrs().Name)
			}
		}
		for _, v := range r.vpcs {
			chain, err := attach.HasEgressChain(v.tap)
			if err != nil || !chain {
				t.Errorf("galactic-cni's chain on %s went with the claims (%v)", v.tap, err)
			}
		}
		return nil
	})
	for _, name := range []string{"lt_tap", "lt_link", "lt_guest", "lt_pair", "lt_guard"} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(r.pin, "local", name), nil)
		if err != nil {
			t.Fatal(err)
		}
		k := make([]byte, m.KeySize())
		if err := m.NextKey(nil, &k); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("%s keeps rows after every claim was released (%v)", name, err)
		}
		_ = m.Close()
	}
	// The NAT stand-in's own pass-through for the client's prefix stays:
	// Local removes only the entries it owns.
	if row, ok, err := r.routes.LookupRow(a.table, ipnet(clientNet)); err != nil || !ok || !row.PassThrough {
		t.Fatalf("another owner's pass-through entry went: %+v %t %v", row, ok, err)
	}
}

// routedTraffic configures the pod's end of a routed link as the
// galactic-vrf sidecar does, and checks both directions between the pod and
// VPC a's guest and the guard's drop of a source the pod was not given.
func routedTraffic(t *testing.T, r *rig, a *vpcRig, pod ns.NetNS, host, podEnd string) {
	t.Helper()
	// The pod configures its end, as the galactic-vrf sidecar does.
	var hostLL netip.Addr
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(host)
		if err != nil {
			return err
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		for _, ad := range addrs {
			if a, ok := netip.AddrFromSlice(ad.IP); ok && a.IsLinkLocalUnicast() {
				hostLL = a
			}
		}
		return nil
	})
	if !hostLL.IsValid() {
		t.Fatal("the routed link's host end has no link-local address")
	}
	spoof := netip.MustParseAddr("fd20:80:ff04::66")
	podIn := func(fn func() error) {
		if err := pod.Do(func(ns.NetNS) error { return fn() }); err != nil {
			t.Fatal(err)
		}
	}
	podIn(func() error {
		for _, p := range []netip.Addr{podAddr, spoof} {
			if err := addrOn(podEnd, netip.PrefixFrom(p, 128)); err != nil {
				return err
			}
		}
		l, err := netlink.LinkByName(podEnd)
		if err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index,
			Dst: ipnet(netip.PrefixFrom(guestAddr, 128)), Gw: net.IP(hostLL.AsSlice())})
	})
	var podConn, spoofConn *net.UDPConn
	podIn(func() error {
		var err error
		if podConn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(podAddr.AsSlice()), Port: 443}); err != nil {
			return err
		}
		spoofConn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(spoof.AsSlice()), Port: 443})
		return err
	})
	t.Cleanup(func() { _ = podConn.Close(); _ = spoofConn.Close() })

	to := &net.UDPAddr{IP: net.IP(guestAddr.AsSlice()), Port: 8080}
	if _, err := podConn.WriteToUDP([]byte("from-pod"), to); err != nil {
		t.Fatal(err)
	}
	f := a.guest.expect(t, "from-pod")
	if f.src != podAddr {
		t.Fatalf("the guest received the pod's packet from %s", f.src)
	}
	a.guest.send(t, guestAddr, podAddr, 8080, 443, "to-pod", false)
	buf := make([]byte, 64)
	_ = podConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := podConn.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "to-pod" || from.Addr().Unmap() != guestAddr {
		t.Fatalf("the pod read %q from %s (%v), want the guest's reply", buf[:n], from, err)
	}
	before := r.stats()
	if _, err := spoofConn.WriteToUDP([]byte("spoofed"), to); err != nil {
		t.Fatal(err)
	}
	a.guest.absent(t, "spoofed")
	if after := r.stats(); after["guard_drop"] <= before["guard_drop"] {
		t.Fatalf("the guard dropped nothing: before %v after %v", before, after)
	}

}
