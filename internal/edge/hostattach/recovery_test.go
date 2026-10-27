// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func recoveryAttachment() Attachment {
	return Attachment{ID: "recovery", HostVRF: vrfA, HostLink: "recover-h", PodVRF: "recover-vrf",
		MTU: 1500, PodTable: 100, PodLink: "recover-p", PodIndex: 42, Address: netip.MustParseAddr("fd00:aa::9")}
}

func TestRejectPrefixContainingAttachmentAddress(t *testing.T) {
	for _, prefix := range []string{"fd00:aa::9/128", "fd00:aa::/64", "::ffff:192.0.2.0/120"} {
		a := recoveryAttachment()
		a.Prefixes = []netip.Prefix{netip.MustParsePrefix(prefix)}
		if err := a.validate(); err == nil {
			t.Errorf("accepted prefix %s", prefix)
		}
	}
}

func TestPeerNamespaceOwnership(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA, vpcB)
	hostH := host.open(t)
	victim, impostor := newTestNS(t), newTestNS(t)
	victimH, impostorH := victim.open(t), impostor.open(t)
	a := recoveryAttachment()
	for _, pair := range []struct {
		pod  testNS
		name string
	}{{victim, a.HostLink}, {impostor, "other-h"}} {
		pair.pod.do(t, func() error {
			return netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: a.PodLink, Index: a.PodIndex},
				PeerName:  pair.name, PeerNamespace: netlink.NsFd(int(host.Fd())),
			})
		})
	}
	// Both candidate pod links have index 42, but only one is the real peer.
	if _, err := Provision(hostH, impostorH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("foreign adoption = %v", err)
	}
	if err := Release(hostH, impostorH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("foreign release = %v", err)
	}
	host.do(t, func() error {
		link, err := netlink.LinkByName(a.HostLink)
		if err != nil {
			return err
		}
		if link.Attrs().Alias != "" || link.Attrs().MasterIndex != 0 {
			t.Fatal("foreign host link mutated")
		}
		return nil
	})
	// A crash before stamping leaves a real, namespace-verified pair releasable.
	if err := Release(hostH, victimH, a); err != nil {
		t.Fatalf("release verified unstamped pair: %v", err)
	}
}

// TestPeerNamespaceOnlyImpostor offers the host link's peer from another
// namespace: a pod link with the same name and index as the real peer, whose
// own peer has the host link's ifindex in a third namespace. Every index
// matches, so only the peer namespace tells it apart.
func TestPeerNamespaceOnlyImpostor(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA)
	hostH := host.open(t)
	victim, impostor, decoy := newTestNS(t), newTestNS(t), newTestNS(t)
	victimH, impostorH := victim.open(t), impostor.open(t)
	a := recoveryAttachment()
	const hostIndex = 4000
	for _, pair := range []struct {
		from testNS
		name string
		peer testNS
	}{{host, a.HostLink, victim}, {decoy, "decoy-h", impostor}} {
		pair.from.do(t, func() error {
			return netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: pair.name, Index: hostIndex},
				PeerName:  a.PodLink, PeerNamespace: netlink.NsFd(int(pair.peer.Fd())),
			})
		})
	}
	podLink := func(n testNS) netlink.LinkAttrs {
		var attrs netlink.LinkAttrs
		n.do(t, func() error {
			l, err := netlink.LinkByName(a.PodLink)
			if err == nil {
				attrs = *l.Attrs()
			}
			return err
		})
		return attrs
	}
	realLink, fake := podLink(victim), podLink(impostor)
	if realLink.Index != fake.Index || realLink.ParentIndex != hostIndex || fake.ParentIndex != hostIndex {
		t.Fatalf("precondition: real pod link %d->%d, impostor %d->%d, want equal indexes peering with %d",
			realLink.Index, realLink.ParentIndex, fake.Index, fake.ParentIndex, hostIndex)
	}
	a.PodIndex = realLink.Index

	if _, err := Provision(hostH, impostorH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("adoption through the impostor = %v", err)
	}
	if err := Release(hostH, impostorH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release through the impostor = %v", err)
	}
	host.do(t, func() error {
		link, err := netlink.LinkByName(a.HostLink)
		if err != nil {
			return err
		}
		if link.Attrs().Alias != "" || link.Attrs().MasterIndex != 0 {
			t.Error("the impostor's offer changed the host link")
		}
		return nil
	})
	if got := podLink(impostor); got.MasterIndex != 0 || got.Alias != "" || got.Flags&net.FlagUp != 0 {
		t.Errorf("the impostor's pod link was changed: master %d, alias %q, flags %v", got.MasterIndex, got.Alias,
			got.Flags)
	}
	if _, err := Provision(hostH, victimH, a); err != nil {
		t.Fatalf("adoption through the real peer = %v", err)
	}
}

// TestPodLinkRouteDrift adds routes through the pod link to the pod VRF
// beside the default route toward the host: a stray prefix, a second default
// at a better metric, and a stray prefix written as a kernel route. Readback
// reports each, Provision removes it, and the node's own default stays.
func TestPodLinkRouteDrift(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA)
	hostH := host.open(t)
	pod := newTestNS(t)
	podH := pod.open(t)
	a := recoveryAttachment()
	if _, err := Provision(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		route func(index int) *netlink.Route
	}{
		{"stray prefix", func(index int) *netlink.Route {
			return &netlink.Route{LinkIndex: index, Table: int(a.PodTable), Dst: ip6Net("fd00:dead::/64")}
		}},
		{"second default at a better metric", func(index int) *netlink.Route {
			return &netlink.Route{LinkIndex: index, Table: int(a.PodTable), Dst: ip6Net("::/0"), Priority: 1}
		}},
		{"stray prefix written as a kernel route", func(index int) *netlink.Route {
			return &netlink.Route{LinkIndex: index, Table: int(a.PodTable), Dst: ip6Net("fd00:dead::/64"),
				Protocol: unix.RTPROT_KERNEL}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod.do(t, func() error {
				link, err := netlink.LinkByName(a.PodLink)
				if err != nil {
					return err
				}
				return netlink.RouteAdd(tc.route(link.Attrs().Index))
			})
			if err := Readback(hostH, podH, a); !errors.Is(err, ErrDrift) ||
				!strings.Contains(err.Error(), "unexpected route") {
				t.Fatalf("readback = %v, want drift reporting the route", err)
			}
			if _, err := Provision(hostH, podH, a); err != nil {
				t.Fatal(err)
			}
			if err := Readback(hostH, podH, a); err != nil {
				t.Fatalf("readback after repair = %v", err)
			}
		})
	}
}

func TestPrefixRemovalAndPartialRecovery(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA)
	hostH := host.open(t)
	pod := newTestNS(t)
	podH := pod.open(t)
	a := recoveryAttachment()
	a.TUN = &TUN{Name: "rtun", Owner: uint32(os.Getuid()), Group: uint32(os.Getgid())}
	a.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:5::/96"), netip.MustParsePrefix("fd00:6::/96")}
	if _, err := Provision(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	a.Prefixes = a.Prefixes[:1]
	if err := Readback(hostH, podH, a); !errors.Is(err, ErrDrift) {
		t.Fatalf("extra route readback = %v", err)
	}
	if _, err := Provision(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	if err := Readback(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	if err := Release(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	// Force failure after the host path has been configured.
	pod.do(t, func() error { return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: a.TUN.Name}}) })
	if _, err := Provision(hostH, podH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("partial setup = %v", err)
	}
	entries, err := List(hostH)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != a.ID {
		t.Fatalf("partial inventory = %+v", entries)
	}
	host.do(t, func() error {
		link, err := netlink.LinkByName(a.HostLink)
		if err != nil {
			return err
		}
		if link.Attrs().Flags&net.FlagUp != 0 {
			t.Fatal("partial attachment left forwarding enabled")
		}
		return nil
	})
	if err := Release(hostH, podH, a); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release with foreign TUN = %v", err)
	}
	entries, err = List(hostH)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("released host link still inventoried: %+v", entries)
	}
}

func TestRestoreFailureDoesNotPoisonCaller(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	caller := unix.Gettid()
	restoreErr := errors.New("injected restore failure")
	calls := 0
	worker := 0
	err := runInNamespaceWith(netns.NsHandle(-1), func() error { worker = unix.Gettid(); return nil },
		func(netns.NsHandle) error {
			calls++
			if calls == 2 {
				return restoreErr
			}
			return nil
		})
	if !errors.Is(err, restoreErr) {
		t.Fatalf("restore = %v", err)
	}
	if worker == caller || unix.Gettid() != caller {
		t.Fatal("namespace work ran on or changed the caller thread")
	}
}

// TestReleaseWithoutPod releases a stamped attachment whose pod namespace
// can no longer be found, and refuses an unstamped link it cannot prove.
func TestReleaseWithoutPod(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA)
	hostH := host.open(t)
	pod := newTestNS(t)
	podH := pod.open(t)
	a := recoveryAttachment()
	if _, err := Provision(hostH, podH, a); err != nil {
		t.Fatal(err)
	}
	other := a
	other.ID = "other"
	if err := Release(hostH, nil, other); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release of another ID without pod = %v", err)
	}
	if err := Release(hostH, nil, a); err != nil {
		t.Fatalf("release without pod: %v", err)
	}
	if entries, err := List(hostH); err != nil || len(entries) != 0 {
		t.Fatalf("after release: %+v, %v", entries, err)
	}
	unstamped := recoveryAttachment()
	pod.do(t, func() error {
		return netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: unstamped.PodLink},
			PeerName:  unstamped.HostLink, PeerNamespace: netlink.NsFd(int(host.Fd())),
		})
	})
	if err := Release(hostH, nil, unstamped); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("release of unstamped link without pod = %v", err)
	}
}

// TestStalePeerIsReported provisions an attachment into a second namespace
// while its link still pairs with the first, as after a sandbox replacement.
func TestStalePeerIsReported(t *testing.T) {
	requireRoot(t)
	host := newHost(t, vpcA)
	hostH := host.open(t)
	first, second := newTestNS(t), newTestNS(t)
	firstH, secondH := first.open(t), second.open(t)
	a := recoveryAttachment()
	if _, err := Provision(hostH, firstH, a); err != nil {
		t.Fatal(err)
	}
	_, err := Provision(hostH, secondH, a)
	if !errors.Is(err, ErrStalePeer) || !errors.Is(err, ErrNotOwned) {
		t.Fatalf("provision into a new namespace = %v", err)
	}
	other := a
	other.ID = "other"
	if _, err := Provision(hostH, secondH, other); errors.Is(err, ErrStalePeer) || !errors.Is(err, ErrNotOwned) {
		t.Fatalf("another ID's provision = %v", err)
	}
	if err := Release(hostH, nil, a); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(hostH, secondH, a); err != nil {
		t.Fatalf("provision after releasing the stale link: %v", err)
	}
}
