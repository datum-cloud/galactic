// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load and attach XDP programs; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// pinDirs are per-test bpffs directories for the dispatcher, the gateway's
// own maps and the egress shard's.
type pinDirs struct{ dispatch, edge, nat string }

func testPinDirs(t *testing.T) pinDirs {
	t.Helper()
	requireRoot(t)
	name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	base := filepath.Join("/sys/fs/bpf", "gwdispatch-test-"+name)
	_ = os.RemoveAll(base)
	d := pinDirs{filepath.Join(base, "xdp"), filepath.Join(base, "edge"), filepath.Join(base, "nat")}
	for _, dir := range []string{d.dispatch, d.edge, d.nat} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("bpffs not writable at /sys/fs/bpf: %v", err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return d
}

func testUplink(t *testing.T, prefix string) (string, int) {
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
	l, _ := netlink.LinkByName(name)
	return name, l.Attrs().Index
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

// gatewayProcess is one gateway process joined to the dispatcher; stop is its
// exit.
type gatewayProcess struct {
	public targetSet
	stop   func()
}

func startGateway(t *testing.T, d pinDirs) gatewayProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	objs, dispatcher, public, _, leaseDone, err := joinDispatcher(ctx, d.dispatch, d.edge, false)
	if err != nil {
		cancel()
		t.Fatalf("gateway joinDispatcher: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-leaseDone
		_ = dispatcher.Close()
		_ = objs.Close()
	}
	t.Cleanup(stop)
	return gatewayProcess{public: public, stop: stop}
}

// startShard joins the egress shard to the dispatcher the way galactic-nat's
// dispatch mode does, and returns its coverage check.
func startShard(t *testing.T, d pinDirs, uplink string) func() error {
	t.Helper()
	objs, err := natattach.Load(d.nat)
	if err != nil {
		t.Fatalf("load shard objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	if err := natattach.PopulateProgArray(objs); err != nil {
		t.Fatalf("populate nat_progs: %v", err)
	}
	dispatcher, err := xdpdispatch.Open(context.Background(), d.dispatch)
	if err != nil {
		t.Fatalf("shard open dispatcher: %v", err)
	}
	t.Cleanup(func() { _ = dispatcher.Close() })
	lock, err := dispatcher.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	err = lock.Fill(xdpdispatch.SlotNAT, objs.NatIngress)
	lock.Unlock()
	if err != nil {
		t.Fatalf("fill the egress slot: %v", err)
	}
	set, err := xdpattach.NewDispatchSet(dispatcher, xdpdispatch.SlotNAT, xdpdispatch.RoleEgress, objs.NatIngress)
	if err != nil {
		t.Fatalf("NewDispatchSet: %v", err)
	}
	if missing := set.Reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("shard missing %v", missing)
	}
	l, _ := netlink.LinkByName(uplink)
	return func() error { return dispatcher.Coverage(l.Attrs().Index, xdpdispatch.SlotNAT, objs.NatIngress) }
}

// TestGatewayAndShardShareAnUplink is issue #717's acceptance case: the gateway
// and the egress shard hold one uplink through the dispatcher, and the gateway
// restarting leaves the shard's traffic and the uplink's program untouched.
func TestGatewayAndShardShareAnUplink(t *testing.T) {
	d := testPinDirs(t)
	uplink, ifindex := testUplink(t, "gwsh")

	gw := startGateway(t, d)
	if missing := gw.public.reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Fatalf("gateway missing %v", missing)
	}
	shardCovered := startShard(t, d, uplink)
	root := xdpProgID(t, uplink)

	probe, err := xdpdispatch.Open(context.Background(), d.dispatch)
	if err != nil {
		t.Fatalf("open dispatcher: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	if roles, _ := probe.Roles(ifindex); roles != xdpdispatch.RolePublicLB|xdpdispatch.RoleEgress {
		t.Errorf("uplink roles = %#x, want public and egress", roles)
	}

	// The gateway process exits and a new one starts.
	gw.stop()
	if got := xdpProgID(t, uplink); got != root {
		t.Fatalf("uplink runs %d after the gateway exited, want the root %d", got, root)
	}
	if err := shardCovered(); err != nil {
		t.Fatalf("shard lost its uplink when the gateway exited: %v", err)
	}
	gw2 := startGateway(t, d)
	if missing := gw2.public.reconcile(context.Background(), []string{uplink}); len(missing) != 0 {
		t.Errorf("restarted gateway missing %v", missing)
	}
	if got := xdpProgID(t, uplink); got != root {
		t.Errorf("uplink runs %d after the gateway restarted, want the same root %d", got, root)
	}
	if err := shardCovered(); err != nil {
		t.Errorf("shard lost its uplink across the gateway restart: %v", err)
	}
}

// TestAttachDirect_RefusesAnUplinkTheShardRunsOn: a gateway set to direct mode
// on a node whose shard runs from the dispatcher must not take the hook.
func TestAttachDirect_RefusesAnUplinkTheShardRunsOn(t *testing.T) {
	d := testPinDirs(t)
	uplink, _ := testUplink(t, "gwdr")
	startShard(t, d, uplink)
	root := xdpProgID(t, uplink)

	_, _, _, err := attachDirect(context.Background(), d.dispatch, d.edge, []string{uplink}, nil)
	if !errors.Is(err, xdpattach.ErrDispatcherInUse) {
		t.Fatalf("attachDirect over a live shard slot = %v, want ErrDispatcherInUse", err)
	}
	if got := xdpProgID(t, uplink); got != root {
		t.Errorf("uplink runs %d after the refusal, want the root %d untouched", got, root)
	}
}

func TestPublicReturnOverlap(t *testing.T) {
	const shared = "eth2"
	if got := publicReturnOverlap([]string{"eth1", shared}, []string{shared, "eth3"}); len(got) != 1 || got[0] != shared {
		t.Errorf("publicReturnOverlap = %v, want [%s]", got, shared)
	}
	if got := publicReturnOverlap([]string{"eth1"}, []string{"eth3"}); len(got) != 0 {
		t.Errorf("publicReturnOverlap = %v, want none", got)
	}
}
