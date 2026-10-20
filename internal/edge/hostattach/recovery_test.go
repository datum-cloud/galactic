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
