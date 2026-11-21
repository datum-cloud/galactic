// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
)

// enterNetns moves the test's thread into a new network namespace for the
// rest of the test. The test must not start subtests, which run elsewhere.
func enterNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open network namespace: %v", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Setns(orig, unix.CLONE_NEWNET)
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
	})
}

func addVeth(t *testing.T, nat, tenant string) (netlink.Link, netlink.Link) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: nat}, PeerName: tenant}); err != nil {
		t.Fatalf("add veth %s: %v", nat, err)
	}
	out := make([]netlink.Link, 0, 2)
	for _, name := range []string{nat, tenant} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", name, err)
		}
		out = append(out, l)
	}
	return out[0], out[1]
}

// xdpDriverProgram reports the native XDP program ID on ifindex, or 0.
func xdpDriverProgram(t *testing.T, ifindex int) uint32 {
	t.Helper()
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("find ifindex %d: %v", ifindex, err)
	}
	x := l.Attrs().Xdp
	if x == nil || !x.Attached || x.AttachMode != xdpAttachedDrv {
		return 0
	}
	return x.ProgId
}

func TestKernelLocal_AttachesNativePinnedAndPrunes(t *testing.T) {
	requireRoot(t)
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "galactic-nat-test-")
	if err != nil {
		t.Skipf("bpffs unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	enterNetns(t)

	objs, err := natattach.Load(pinDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	tables := natmap.LocalTables{Pair: natmap.KernelTable{Map: objs.NatLocalPair},
		Return: natmap.KernelTable{Map: objs.NatLocalReturn}}
	vlans := natmap.VLANTable{Table: natmap.KernelTable{Map: objs.NatVlanEgress}}
	k, err := newKernelLocal(objs.NatIngress, pinDir, tables, vlans)
	if err != nil {
		t.Fatalf("newKernelLocal: %v", err)
	}

	nat, tenant := addVeth(t, "gn0", "gt0")
	if peer, err := vethPeer(nat, netlink.LinkByIndex); err != nil || peer.Attrs().Index != tenant.Attrs().Index {
		t.Fatalf("vethPeer(gn0) = %v, %v; want gt0", peer, err)
	}
	sid := netip.MustParseAddr("fc00:0:1:1:123::")
	target := localTarget{VPC: "A", NATName: "gn0", NATIfindex: nat.Attrs().Index, TenantName: "gt0", TenantSID: sid}
	if err := k.Program(target); err != nil {
		t.Fatalf("Program: %v", err)
	}
	progID := xdpDriverProgram(t, nat.Attrs().Index)
	if progID == 0 {
		t.Fatal("no native XDP program on the NAT end after Program")
	}
	if _, err := os.Stat(filepath.Join(pinDir, "links", "local-gn0")); err != nil {
		t.Errorf("pinned link: %v", err)
	}
	pairs, err := tables.All()
	if err != nil || len(pairs) != 1 || pairs[0].TenantMAC.String() != tenant.Attrs().HardwareAddr.String() {
		t.Fatalf("rows = %+v, %v; want one row framed to the tenant end", pairs, err)
	}

	// Programming the same pair again keeps one attachment.
	if err := k.Program(target); err != nil {
		t.Fatalf("Program again: %v", err)
	}
	if got := xdpDriverProgram(t, nat.Attrs().Index); got != progID {
		t.Errorf("program ID after a repeat Program = %d, want %d", got, progID)
	}

	// A recreated pair of the same name is attached afresh.
	if err := netlink.LinkDel(nat); err != nil {
		t.Fatalf("delete pair: %v", err)
	}
	nat2, _ := addVeth(t, "gn0", "gt0")
	target2 := target
	target2.NATIfindex = nat2.Attrs().Index
	if err := k.Program(target2); err != nil {
		t.Fatalf("Program the recreated pair: %v", err)
	}
	if xdpDriverProgram(t, nat2.Attrs().Index) == 0 {
		t.Fatal("no native XDP program on the recreated NAT end")
	}

	// Prune keeping nothing removes the rows and the link.
	if err := k.Prune(nil); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pairs, _ := tables.All(); len(pairs) != 0 {
		t.Errorf("rows after Prune = %+v, want none", pairs)
	}
	if sids, _ := tables.ReturnSIDs(); len(sids) != 0 {
		t.Errorf("return rows after Prune = %v, want none", sids)
	}
	if xdpDriverProgram(t, nat2.Attrs().Index) != 0 {
		t.Error("NAT end still runs the program after Prune")
	}
}

// xdpAttachedDrv is IFLA_XDP_ATTACHED's value for a native program
// (XDP_ATTACHED_DRV in linux/if_link.h).
const xdpAttachedDrv = 1

// TestVethPeer checks that the NAT end's peer is found from its IFLA_LINK,
// and only when the peer names it back from this namespace.
func TestVethPeer(t *testing.T) {
	link := func(idx, peer, netnsid int) netlink.Link {
		attrs := netlink.NewLinkAttrs()
		attrs.Name, attrs.Index, attrs.ParentIndex, attrs.NetNsID = "gn0", idx, peer, netnsid
		return &netlink.Veth{LinkAttrs: attrs}
	}
	links := map[int]netlink.Link{10: link(10, 9, -1), 11: link(11, 12, -1)}
	byIndex := func(i int) (netlink.Link, error) {
		if l, ok := links[i]; ok {
			return l, nil
		}
		return nil, unix.ENODEV
	}
	for _, c := range []struct {
		name string
		nat  netlink.Link
		want int
	}{
		{"peer", link(9, 10, -1), 10},
		{"peer names another link", link(9, 11, -1), 0},
		{"peer is gone", link(9, 13, -1), 0},
		{"no peer reported", link(9, 0, -1), 0},
		{"peer in another namespace", link(9, 10, 2), 0},
	} {
		got, err := vethPeer(c.nat, byIndex)
		switch {
		case c.want == 0 && err == nil:
			t.Errorf("%s: vethPeer = %d, want an error", c.name, got.Attrs().Index)
		case c.want != 0 && (err != nil || got.Attrs().Index != c.want):
			t.Errorf("%s: vethPeer = %v, %v; want link %d", c.name, got, err, c.want)
		}
	}
}
