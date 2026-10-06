// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// testPinDirs returns per-test bpffs directories for the dispatcher and the
// shard's own maps.
func testPinDirs(t *testing.T) (dispatchDir, natDir string) {
	t.Helper()
	requireRoot(t)
	name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	base := filepath.Join("/sys/fs/bpf", "natdispatch-test-"+name)
	_ = os.RemoveAll(base)
	dispatchDir, natDir = filepath.Join(base, "xdp"), filepath.Join(base, "nat")
	for _, d := range []string{dispatchDir, natDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Skipf("bpffs not writable at /sys/fs/bpf: %v", err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return dispatchDir, natDir
}

// testUplink creates an up veth pair and returns the first end's name.
func testUplink(t *testing.T, prefix string) string {
	t.Helper()
	name := fmt.Sprintf("%s%d", prefix, os.Getpid()%10000)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth %s: %v", name, err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	for _, n := range []string{name, name + "p"} {
		l, err := netlink.LinkByName(n)
		if err != nil {
			t.Fatalf("find %s: %v", n, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", n, err)
		}
	}
	return name
}

func xdpProgID(t *testing.T, name string) uint32 {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("find %s: %v", name, err)
	}
	if xdp := l.Attrs().Xdp; xdp != nil && xdp.Attached {
		return xdp.ProgId
	}
	return 0
}

// loadShard loads the real shard objects under natDir, as a process start
// does.
func loadShard(t *testing.T, natDir string) *ebpf.Program {
	t.Helper()
	objs, err := natattach.Load(natDir)
	if err != nil {
		t.Fatalf("load shard objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	if err := natattach.PopulateProgArray(objs); err != nil {
		t.Fatalf("populate nat_progs: %v", err)
	}
	return objs.NatIngress
}

// joinForTest joins the dispatcher under dispatchDir and stops the lease and
// closes the dispatcher when the test ends, in that order.
func joinForTest(t *testing.T, dispatchDir string, program *ebpf.Program) (*xdpdispatch.Dispatcher,
	*xdpattach.DispatchSet, func(),
) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d, set, leaseDone, err := joinDispatcher(ctx, dispatchDir, program)
	if err != nil {
		cancel()
		t.Fatalf("joinDispatcher: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-leaseDone
		_ = d.Close()
	}
	t.Cleanup(stop)
	return d, set, stop
}

// TestJoinDispatcher_ARestartLeavesTheUplinkAttached is issue #717's restart
// case for the shard: a new process takes over the slot and the uplink keeps
// the same root, never detached or re-attached.
func TestJoinDispatcher_ARestartLeavesTheUplinkAttached(t *testing.T) {
	dispatchDir, natDir := testPinDirs(t)
	uplink := testUplink(t, "natd")

	_, set, stopFirst := joinForTest(t, dispatchDir, loadShard(t, natDir))
	if missing := set.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("first process: missing %v", missing)
	}
	rootBefore := xdpProgID(t, uplink)
	if rootBefore == 0 {
		t.Fatal("no XDP program on the uplink after the first process joined")
	}

	// The first process exits.
	stopFirst()
	if got := xdpProgID(t, uplink); got != rootBefore {
		t.Fatalf("uplink runs program %d after the shard exited, want the root %d", got, rootBefore)
	}

	_, set2, _ := joinForTest(t, dispatchDir, loadShard(t, natDir))
	if missing := set2.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Errorf("second process: missing %v", missing)
	}
	if got := xdpProgID(t, uplink); got != rootBefore {
		t.Errorf("uplink runs program %d after the restart, want the same root %d", got, rootBefore)
	}
}

// TestReleaseIdleDispatcher_FreesTheUplinkForADirectAttach is a rollback to
// direct mode on a node only the shard used the dispatcher on.
func TestReleaseIdleDispatcher_FreesTheUplinkForADirectAttach(t *testing.T) {
	dispatchDir, natDir := testPinDirs(t)
	uplink := testUplink(t, "natr")
	program := loadShard(t, natDir)

	_, set, _ := joinForTest(t, dispatchDir, program)
	if missing := set.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}

	if err := releaseIdleDispatcher(context.Background(), dispatchDir, []string{uplink}); err != nil {
		t.Fatalf("releaseIdleDispatcher: %v", err)
	}
	if got := xdpProgID(t, uplink); got != 0 {
		t.Fatalf("uplink still runs program %d after release", got)
	}
	links, err := natattach.Attach(program, []string{uplink})
	if err != nil {
		t.Fatalf("direct attach after release: %v", err)
	}
	for _, l := range links {
		_ = l.Close()
	}
}

// TestReleaseIdleDispatcher_RefusesWhileAnotherSlotIsLive: the gateway is on
// the same uplink, so a direct attach would cut its traffic.
func TestReleaseIdleDispatcher_RefusesWhileAnotherSlotIsLive(t *testing.T) {
	dispatchDir, natDir := testPinDirs(t)
	uplink := testUplink(t, "natg")

	d, set, _ := joinForTest(t, dispatchDir, loadShard(t, natDir))
	if missing := set.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	gateway := stubXDP(t)
	lock, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	err = lock.Fill(xdpdispatch.SlotGatewayLB, gateway)
	lock.Unlock()
	if err != nil {
		t.Fatalf("fill the gateway slot: %v", err)
	}
	root := xdpProgID(t, uplink)

	if err := releaseIdleDispatcher(context.Background(), dispatchDir, []string{uplink}); err == nil {
		t.Fatal("releaseIdleDispatcher succeeded with the gateway's slot live")
	}
	if got := xdpProgID(t, uplink); got != root {
		t.Errorf("uplink runs program %d after the refusal, want the root %d untouched", got, root)
	}
}

// TestTurnOffDatapath_EmptiesOnlyTheShardsSlot: turning the shard off
// takes it out of the dispatcher at once and leaves the gateway's slot alone.
func TestTurnOffDatapath_EmptiesOnlyTheShardsSlot(t *testing.T) {
	dispatchDir, natDir := testPinDirs(t)
	uplink := testUplink(t, "natx")
	program := loadShard(t, natDir)

	d, set, _ := joinForTest(t, dispatchDir, program)
	if missing := set.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	lock, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	err = lock.Fill(xdpdispatch.SlotGatewayLB, stubXDP(t))
	lock.Unlock()
	if err != nil {
		t.Fatalf("fill the gateway slot: %v", err)
	}

	turnOffDatapath(context.Background(), dispatchDir)
	live, err := d.LiveSlots()
	if err != nil {
		t.Fatalf("LiveSlots: %v", err)
	}
	if len(live) != 1 || live[0] != xdpdispatch.SlotGatewayLB {
		t.Errorf("live slots = %v after disabling the shard, want only the gateway's", live)
	}
	if xdpProgID(t, uplink) == 0 {
		t.Error("disabling the shard detached the dispatcher")
	}
}

// stubXDP stands in for another datapath's program.
func stubXDP(t *testing.T) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.XDP,
		AttachType:   ebpf.AttachXDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load stub program: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
