// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create test network namespaces and a veth pair; re-run via sudo")
	}
}

// setUpVethPair creates two fresh, throwaway netns joined by a veth pair --
// nearNS gets nearAddr on the near end, farNS gets farAddr on the far end,
// each address added with IFA_F_NODAD so the test isn't at the mercy of
// duplicate-address-detection's ~1s default delay before either end will
// actually answer a neighbor solicitation for its own address.
//
// Unlike setUpResolvableSID in internal/plumbing/srv6 (a dummy link with a
// neighbor entry pre-added by the test itself), this deliberately adds no
// neighbor entry on either side: two real, independent network stacks
// joined by a real L2 link is what lets a test actually exercise genuine
// NDP resolution end to end, the same way production traffic would --
// which a dummy link's fabricated NUD_PERMANENT entry never does. This
// mirrors the exact bug this package's active-solicit fix addresses: a
// cold, empty neighbor cache on a link with a real, reachable peer.
func setUpVethPair(
	t *testing.T, nearIface, nearAddr, farIface, farAddr string,
) (nearNS ns.NetNS, nearLinkIndex int, farAddrIP net.IP) {
	t.Helper()

	nearNS, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create near netns: %v", err)
	}
	t.Cleanup(func() { _ = nearNS.Close() })

	farNS, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create far netns: %v", err)
	}
	t.Cleanup(func() { _ = farNS.Close() })

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: nearIface},
		PeerName:  farIface,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	nearLink, err := netlink.LinkByName(nearIface)
	if err != nil {
		t.Fatalf("look up %s: %v", nearIface, err)
	}
	farLink, err := netlink.LinkByName(farIface)
	if err != nil {
		t.Fatalf("look up %s: %v", farIface, err)
	}
	if err := netlink.LinkSetNsFd(nearLink, int(nearNS.Fd())); err != nil {
		t.Fatalf("move %s into near netns: %v", nearIface, err)
	}
	if err := netlink.LinkSetNsFd(farLink, int(farNS.Fd())); err != nil {
		t.Fatalf("move %s into far netns: %v", farIface, err)
	}

	setUpEnd := func(target ns.NetNS, iface, addr string) int {
		var idx int
		err := target.Do(func(_ ns.NetNS) error {
			link, err := netlink.LinkByName(iface)
			if err != nil {
				return fmt.Errorf("look up %s: %w", iface, err)
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("set %s up: %w", iface, err)
			}
			a, err := netlink.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("parse addr %q: %w", addr, err)
			}
			a.Flags |= unix.IFA_F_NODAD
			if err := netlink.AddrAdd(link, a); err != nil {
				return fmt.Errorf("add addr %q to %s: %w", addr, iface, err)
			}
			idx = link.Attrs().Index
			return nil
		})
		if err != nil {
			t.Fatalf("setUpEnd(%s): %v", iface, err)
		}
		return idx
	}

	nearLinkIndex = setUpEnd(nearNS, nearIface, nearAddr)
	setUpEnd(farNS, farIface, farAddr)

	farIP, _, err := net.ParseCIDR(farAddr)
	if err != nil {
		t.Fatalf("parse far addr %q: %v", farAddr, err)
	}
	return nearNS, nearLinkIndex, farIP
}

// setUpVethPairNoFarSide creates a veth pair, moves only the near end into
// a fresh throwaway netns (up, with nearAddr assigned), and leaves the far
// end exactly as LinkAdd created it -- down, unconfigured, in this
// process's own namespace. With the peer never brought up, the near end
// never gets carrier, so nothing on its /64 can ever be resolved: the
// guaranteed-unanswerable link TestResolveNeighbor_TimesOutIfNeverAnswered
// needs.
func setUpVethPairNoFarSide(t *testing.T, nearIface, nearAddr, farIface string) (nearNS ns.NetNS, nearLinkIndex int) {
	t.Helper()

	nearNS, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create near netns: %v", err)
	}
	t.Cleanup(func() { _ = nearNS.Close() })

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: nearIface},
		PeerName:  farIface,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	nearLink, err := netlink.LinkByName(nearIface)
	if err != nil {
		t.Fatalf("look up %s: %v", nearIface, err)
	}
	if err := netlink.LinkSetNsFd(nearLink, int(nearNS.Fd())); err != nil {
		t.Fatalf("move %s into near netns: %v", nearIface, err)
	}

	err = nearNS.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(nearIface)
		if err != nil {
			return fmt.Errorf("look up %s: %w", nearIface, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("set %s up: %w", nearIface, err)
		}
		a, err := netlink.ParseAddr(nearAddr)
		if err != nil {
			return fmt.Errorf("parse addr %q: %w", nearAddr, err)
		}
		a.Flags |= unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, a); err != nil {
			return fmt.Errorf("add addr %q to %s: %w", nearAddr, nearIface, err)
		}
		nearLinkIndex = link.Attrs().Index
		return nil
	})
	if err != nil {
		t.Fatalf("set up near end: %v", err)
	}
	return nearNS, nearLinkIndex
}

// TestResolveNeighbor_ActivelySolicitsColdCache reproduces the exact
// failure confirmed live in us-central-1-staging-lab: a link with a real,
// reachable peer whose neighbor cache is empty because nothing has ever
// sent traffic toward it. The pre-fix implementation (a bare
// netlink.NeighList read) fails this every time; so, empirically, does an
// administrative netlink.NeighSet(NUD_NONE, NTF_USE) solicit with no real
// packet behind it (see solicitNeighbor's own doc comment) -- only
// resolveNeighbor's actual send-a-packet solicit passes it.
func TestResolveNeighbor_ActivelySolicitsColdCache(t *testing.T) {
	requireRoot(t)

	nearNS, linkIndex, farIP := setUpVethPair(t,
		"vrfnt0", "fd00:beef:1::1/64",
		"vrfnt0p", "fd00:beef:1::2/64")

	// t.Fatalf/t.Errorf must run on the test's own goroutine, not inside
	// nearNS.Do's closure -- ns.NetNS.Do runs it on a separate,
	// newly-spawned goroutine (to switch that goroutine's OS thread's
	// netns without disturbing this one), so every check here reports
	// through a returned error instead and asserts after Do returns.
	var alreadyResolved bool
	var mac net.HardwareAddr
	err := nearNS.Do(func(_ ns.NetNS) error {
		// Confirm the starting condition this test exists to cover: no
		// neighbor entry for farIP yet -- a passive read alone, exactly
		// what the pre-fix code did, would find nothing here.
		before, lookupErr := lookupNeighbor(linkIndex, farIP)
		if lookupErr != nil {
			return fmt.Errorf("lookupNeighbor before resolve: %w", lookupErr)
		}
		alreadyResolved = before != nil

		var resolveErr error
		mac, resolveErr = resolveNeighbor(linkIndex, farIP)
		if resolveErr != nil {
			return fmt.Errorf("resolveNeighbor(%s): %w", farIP, resolveErr)
		}
		return nil
	})
	if alreadyResolved {
		t.Fatalf("neighbor for %s already resolved before resolveNeighbor ran -- setup is not exercising a cold cache", farIP)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(mac) != 6 {
		t.Errorf("resolveNeighbor(%s) returned a %d-byte address, want 6", farIP, len(mac))
	}
}

// TestResolveNeighbor_TimesOutIfNeverAnswered proves the active solicit is
// bounded: a next hop that is routable but has nothing on the other end to
// answer must fail within roughly neighborResolveTimeout, not hang the
// reconciler forever the way the pre-fix code's endless passive-retry-via
// -requeue effectively did in production.
//
// Deliberately a veth pair with the far end left down and unconfigured,
// not a dummy link: IFF_NOARP links (a dummy's own default) don't behave
// like an ordinary Ethernet-ish link for neighbor resolution purposes --
// confirmed while writing this test, an earlier version built on a dummy
// link "resolved" a destination nothing could ever have answered for.
// A real link with nothing alive on the other end is what actually
// reproduces "routable but never answers."
func TestResolveNeighbor_TimesOutIfNeverAnswered(t *testing.T) {
	requireRoot(t)

	nearNS, linkIndex := setUpVethPairNoFarSide(t, "vrfnt1", "fd00:beef:2::1/64", "vrfnt1p")
	unreachable := net.ParseIP("fd00:beef:2::dead") // same on-link /64, nothing owns this address

	var elapsed time.Duration
	var resolveErr error
	err := nearNS.Do(func(_ ns.NetNS) error {
		start := time.Now()
		_, resolveErr = resolveNeighbor(linkIndex, unreachable)
		elapsed = time.Since(start)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if resolveErr == nil {
		t.Fatalf("resolveNeighbor(%s) succeeded, want a timeout error (nothing on this link can ever answer)", unreachable)
	}
	// Generous upper bound: proves this returns instead of hanging,
	// without pinning the test to neighborResolveTimeout's exact value.
	if elapsed > 10*time.Second {
		t.Errorf("resolveNeighbor(%s) took %s to give up, want roughly neighborResolveTimeout (%s)",
			unreachable, elapsed, neighborResolveTimeout)
	}
}
