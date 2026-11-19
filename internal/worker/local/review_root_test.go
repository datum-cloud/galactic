// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

// TestRestartKeepsReceiveHookRoot checks that a restarted Worker, which
// plans a scope with no local.tap claim before the scopes that have one,
// leaves local_rx on the receiving device while Local still authorizes a TAP.
func TestRestartKeepsReceiveHookRoot(t *testing.T) {
	r := readyRig(t, "restart")
	k2 := &Kernel{PinDir: r.kernel.PinDir, LocalPinDir: r.kernel.LocalPinDir, DispatchDir: r.kernel.DispatchDir,
		Pods: r.pods}
	t.Cleanup(func() { _ = k2.Close() })
	m2, err := New(Config{Kernel: k2, Node: testNode})
	if err != nil {
		t.Fatal(err)
	}
	r.in(r.node, func() error {
		scope := module.Scope{VPC: "0000099"}
		ch, err := m2.Plan(context.Background(), scope, nil)
		if err != nil {
			return err
		}
		if !ch.Empty() {
			if err := m2.Apply(context.Background(), scope, ch); err != nil {
				return err
			}
		}
		l, err := netlink.LinkByName(r.rx)
		if err != nil {
			return err
		}
		name, _, ok, err := attach.LocalFilter(l.Attrs().Index)
		if err != nil || !ok || name != filterRx {
			t.Fatalf("local_rx on %s after a restart: %q %t %v", r.rx, name, ok, err)
		}
		return nil
	})
	sock := r.clientSocket(40000)
	sock.send(t, r.vpcs[0].vip, 7, "after-restart")
	r.vpcs[0].guest.expect(t, "after-restart")
}

// TestRoutedLinkFaultsRoot checks a routed link's faults: one pod that
// already holds an interface of the pod end's name fails only its own claim,
// a guard taken off is put back while the link is down, and a link-local
// source toward a VPC address is dropped.
func TestRoutedLinkFaultsRoot(t *testing.T) {
	r := newRig(t, "routedfault", xdpmode.Native)
	a := r.vpcs[0]
	good, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = good.Close() })
	bad, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bad.Close() })
	r.pods.add("pod-good", good)
	r.pods.add("pod-bad", bad)
	dest := module.Destination{ID: "attachment/" + a.attUID, Mode: workerv1alpha1.Mode_MODE_LOCAL, VPC: a.vpc,
		Node: testNode, Addresses: []netip.Addr{guestAddr}, HostInterface: a.tap}
	claim := func(uid, pod string, addr netip.Addr) module.Claim {
		return module.Claim{Key: module.ClaimKey{Node: testNode, VPC: a.vpc, AttachmentUID: uid},
			Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK, OwnerPod: pod,
			Addresses: []netip.Addr{addr}, Destinations: []module.Destination{dest}}
	}
	claims := []module.Claim{claim("envoy-good", "pod-good", podAddr),
		claim("envoy-bad", "pod-bad", netip.MustParseAddr("fd20:80:ff04::51"))}
	badEnd := linkName(a.vpc, "envoy-bad", intf.LocalRoleRoutedPod)
	if err := bad.Do(func(ns.NetNS) error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: badEnd}})
	}); err != nil {
		t.Fatal(err)
	}
	st := r.reconcile(a.vpc, claims)
	wantReady(t, st, claims[:1])
	wantState(t, st, claims[1], false, false, false, workerv1alpha1.ReasonProgrammingFailed)
	host := linkName(a.vpc, "envoy-good", intf.LocalRoleRoutedHost)

	// The guard goes: the link is down until it is back.
	r.in(r.node, func() error { return attach.DetachLocal(host) })
	wantState(t, r.read(a.vpc), claims[0], true, false, false, workerv1alpha1.ReasonHandoffHookMissing)
	wantReady(t, r.reconcile(a.vpc, claims), claims[:1])

	// A link-local source reaches only the link.
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
			if v, ok := netip.AddrFromSlice(ad.IP); ok && v.IsLinkLocalUnicast() {
				hostLL = v
			}
		}
		return nil
	})
	podEnd := linkName(a.vpc, "envoy-good", intf.LocalRoleRoutedPod)
	var conn *net.UDPConn
	if err := good.Do(func(ns.NetNS) error {
		l, err := netlink.LinkByName(podEnd)
		if err != nil {
			return err
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index,
			Dst: ipnet(netip.PrefixFrom(guestAddr, 128)), Gw: net.IP(hostLL.AsSlice())}); err != nil {
			return err
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		for _, ad := range addrs {
			if v, ok := netip.AddrFromSlice(ad.IP); ok && v.IsLinkLocalUnicast() {
				// The address is tentative until the pod's duplicate
				// address detection ends.
				for range 50 {
					if conn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: ad.IP, Zone: podEnd}); err == nil {
						return nil
					}
					time.Sleep(100 * time.Millisecond)
				}
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Skip("the pod end has no link-local address to send from")
	}
	t.Cleanup(func() { _ = conn.Close() })
	before := r.stats()
	if _, err := conn.WriteToUDP([]byte("link-local-source"),
		&net.UDPAddr{IP: net.IP(guestAddr.AsSlice()), Port: 8080}); err != nil {
		t.Skipf("the pod's kernel does not send a link-local source off the link: %v", err)
	}
	a.guest.absent(t, "link-local-source")
	if after := r.stats(); after["guard_drop"] <= before["guard_drop"] {
		t.Fatalf("the guard passed a link-local source toward %s: before %v after %v", guestAddr, before, after)
	}
}
