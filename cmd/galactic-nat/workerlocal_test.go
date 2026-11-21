// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
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

// testWorkerSocket is a Worker socket path; nothing listens on it.
const testWorkerSocket = "/run/worker.sock"

func TestSettleLocalDelivery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		socket    string
		enabled   bool
		wantStart bool
	}{
		{name: "integration on", socket: testWorkerSocket, enabled: true, wantStart: true},
		{name: "no worker socket", socket: "", enabled: true},
		{name: "datapath disabled", socket: testWorkerSocket, enabled: false},
		{name: "both off", socket: "", enabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.NATConfig{WorkerSocket: tc.socket, DatapathEnabled: tc.enabled}
			plumb := &fakePlumbing{}
			started, opened, closed := false, false, false
			err := settleLocalDelivery(cfg,
				func() error { started = true; return nil },
				func() (localPlumbing, func(), error) {
					opened = true
					return plumb, func() { closed = true }, nil
				})
			if err != nil {
				t.Fatalf("settleLocalDelivery: %v", err)
			}
			if started != tc.wantStart {
				t.Errorf("started = %v, want %v", started, tc.wantStart)
			}
			if tc.wantStart {
				if opened || len(plumb.pruned) != 0 {
					t.Errorf("opened = %v, pruned = %v; want no prune while the integration runs", opened, plumb.pruned)
				}
				return
			}
			if len(plumb.pruned) != 1 || len(plumb.pruned[0]) != 0 {
				t.Errorf("pruned = %v, want one Prune with an empty keep set", plumb.pruned)
			}
			if !closed {
				t.Error("the opened state was not closed")
			}
		})
	}
}

func TestSettleLocalDelivery_StartError(t *testing.T) {
	want := errors.New("boom")
	cfg := &config.NATConfig{WorkerSocket: testWorkerSocket, DatapathEnabled: true}
	err := settleLocalDelivery(cfg, func() error { return want },
		func() (localPlumbing, func(), error) { t.Fatal("opened with the integration on"); return nil, nil, nil })
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

func TestSettleLocalDelivery_OpenErrorIsLogged(t *testing.T) {
	cfg := &config.NATConfig{DatapathEnabled: false}
	err := settleLocalDelivery(cfg, func() error { t.Fatal("started"); return nil },
		func() (localPlumbing, func(), error) { return nil, nil, errors.New("boom") })
	if err != nil {
		t.Errorf("err = %v, want nil: a failed cleanup does not stop startup", err)
	}
}

// pinnedRows counts the rows of the map pinned at path.
func pinnedRows(t *testing.T, path string) int {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = m.Close() }()
	n := 0
	it := m.Iterate()
	key := make([]byte, m.KeySize())
	value := make([]byte, m.ValueSize())
	for it.Next(&key, &value) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate %s: %v", path, err)
	}
	return n
}

// TestSettleLocalDelivery_RemovesPinnedState starts with the integration off
// after a process that programmed a pair and exited, leaving its link and rows
// pinned.
func TestSettleLocalDelivery_RemovesPinnedState(t *testing.T) {
	requireRoot(t)
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "galactic-nat-test-")
	if err != nil {
		t.Skipf("bpffs unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	enterNetns(t)

	// The previous process.
	objs, err := natattach.Load(pinDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	k, err := newKernelLocal(objs.NatIngress, pinDir,
		natmap.LocalTables{Pair: natmap.KernelTable{Map: objs.NatLocalPair},
			Return: natmap.KernelTable{Map: objs.NatLocalReturn}},
		natmap.VLANTable{Table: natmap.KernelTable{Map: objs.NatVlanEgress}})
	if err != nil {
		t.Fatalf("newKernelLocal: %v", err)
	}
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gd0"}}); err != nil {
		t.Fatalf("add dummy: %v", err)
	}
	lower, err := netlink.LinkByName("gd0")
	if err != nil {
		t.Fatalf("find gd0: %v", err)
	}
	if err := netlink.LinkAdd(&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "gd0.42",
		ParentIndex: lower.Attrs().Index}, VlanId: 42}); err != nil {
		t.Fatalf("add VLAN: %v", err)
	}
	nat, _ := addVeth(t, "gn0", "gt0")
	target := localTarget{VPC: "A", NATName: "gn0", NATIfindex: nat.Attrs().Index, TenantName: "gt0",
		TenantSID: netip.MustParseAddr("fc00:0:1:1:123::")}
	if err := k.Program(target); err != nil {
		t.Fatalf("Program: %v", err)
	}
	if err := objs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	linkPin := filepath.Join(pinDir, "links", "local-gn0")
	maps := []string{"nat_local_pair", "nat_local_return", "nat_vlan_egress"}
	for _, m := range maps {
		if n := pinnedRows(t, filepath.Join(pinDir, m)); n != 1 {
			t.Fatalf("%s holds %d rows before the start, want 1", m, n)
		}
	}
	if xdpDriverProgram(t, nat.Attrs().Index) == 0 {
		t.Fatal("no native XDP program on the NAT end before the start")
	}

	// Two starts with the datapath disabled; the second finds nothing to do.
	cfg := &config.NATConfig{WorkerSocket: testWorkerSocket, DatapathEnabled: false}
	open := func() (localPlumbing, func(), error) { return openPinnedLocal(pinDir) }
	for i := range 2 {
		if err := settleLocalDelivery(cfg, func() error { t.Fatal("started"); return nil }, open); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if _, err := os.Stat(linkPin); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("start %d: the link pin remains: %v", i, err)
		}
		if xdpDriverProgram(t, nat.Attrs().Index) != 0 {
			t.Errorf("start %d: the NAT end still runs the program", i)
		}
		for _, m := range maps {
			if n := pinnedRows(t, filepath.Join(pinDir, m)); n != 0 {
				t.Errorf("start %d: %s holds %d rows, want 0", i, m, n)
			}
		}
	}
	plumb, closeMaps, err := openPinnedLocal(pinDir)
	if err != nil {
		t.Fatalf("openPinnedLocal: %v", err)
	}
	defer closeMaps()
	if err := plumb.Prune(nil); err != nil {
		t.Errorf("Prune with nothing left: %v", err)
	}
}

// TestOpenPinnedLocal_NothingPinned prunes on a node where galactic-nat never
// pinned anything, which must neither fail nor create anything.
func TestOpenPinnedLocal_NothingPinned(t *testing.T) {
	pinDir := filepath.Join(t.TempDir(), "galactic-nat")
	plumb, closeMaps, err := openPinnedLocal(pinDir)
	if err != nil {
		t.Fatalf("openPinnedLocal: %v", err)
	}
	defer closeMaps()
	if err := plumb.Prune(nil); err != nil {
		t.Errorf("Prune: %v", err)
	}
	if _, err := os.Stat(pinDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pin directory was created: %v", err)
	}
}

// xdpAttachedDrv is IFLA_XDP_ATTACHED's value for a native program
// (XDP_ATTACHED_DRV in linux/if_link.h).
const xdpAttachedDrv = 1
