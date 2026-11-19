// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabric

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/routes"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to load the datapath and create a network namespace; run task test:unit-root")
	}
}

// rootKernel is the Kernel datapath with the return path, which reads the
// node's BGPRouter and BGPVRFInstances, stubbed out.
type rootKernel struct{ *Kernel }

func (rootKernel) ReturnPath(context.Context, string) error { return nil }

const (
	uplinkName = "fab0"
	uplinkAddr = "2001:db8:ff::1/64"
)

var (
	gwB  = net.ParseIP("2001:db8:ff::b")
	gwC  = net.ParseIP("2001:db8:ff::c")
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
	macC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0c}
	macD = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0d}
)

// rootNet is a network namespace with an SRv6 uplink, a VRF for each of two
// VPCs, and underlay routes toward the locators of nodes B and C.
type rootNet struct {
	t      *testing.T
	ns     ns.NetNS
	uplink int
}

func newRootNet(t *testing.T) *rootNet {
	t.Helper()
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	t.Setenv(config.EnvCNIEBPFInterfaces, uplinkName)
	attach.InvalidateUplinkIndexes()
	t.Cleanup(attach.InvalidateUplinkIndexes)
	n := &rootNet{t: t, ns: nsObj}
	n.do(func() error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: uplinkName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return err
		}
		addr, _ := netlink.ParseAddr(uplinkAddr)
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			return err
		}
		link, err := netlink.LinkByName(uplinkName)
		if err != nil {
			return err
		}
		n.uplink = link.Attrs().Index
		for vpc, table := range map[string]uint32{vpcA: tableA, vpcB: tableB} {
			v := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)}, Table: table}
			if err := netlink.LinkAdd(v); err != nil {
				return fmt.Errorf("add VRF for %s: %w", vpc, err)
			}
		}
		return nil
	})
	n.underlay(locB, gwB, macB)
	n.underlay(locC, gwC, macC)
	return n
}

func (n *rootNet) do(fn func() error) {
	n.t.Helper()
	if err := n.ns.Do(func(ns.NetNS) error { return fn() }); err != nil {
		n.t.Fatal(err)
	}
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 128)}
}

// underlay routes loc via gw and resolves gw to mac.
func (n *rootNet) underlay(loc netip.Prefix, gw net.IP, mac net.HardwareAddr) {
	n.t.Helper()
	n.do(func() error {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: n.uplink, Dst: ipnet(loc), Gw: gw}); err != nil {
			return fmt.Errorf("route %s: %w", loc, err)
		}
		return n.neighbor(gw, mac)
	})
}

func (n *rootNet) neighbor(gw net.IP, mac net.HardwareAddr) error {
	return netlink.NeighSet(&netlink.Neigh{LinkIndex: n.uplink, Family: netlink.FAMILY_V6,
		State: netlink.NUD_PERMANENT, IP: gw, HardwareAddr: mac})
}

func TestKernelDatapathRoot(t *testing.T) {
	requireRoot(t)
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-fabric-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("load datapath: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	n := newRootNet(t)
	kernel := &Kernel{PinDir: pinDir}
	t.Cleanup(func() { _ = kernel.Close() })
	rt := routes.New()
	m, err := New(Config{Routes: rt, Datapath: rootKernel{kernel},
		OwnLocator: func(context.Context) (netip.Prefix, error) { return locOwn, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, rt: rt, m: m}
	reconcile := func(vpc string, desired []module.Claim) (st module.State) {
		n.do(func() error { _, st = f.reconcile(vpc, desired); return nil })
		return st
	}
	entry := func(table uint32, p netip.Prefix) (egressroutemap.Row, bool) {
		var (
			row egressroutemap.Row
			ok  bool
		)
		n.do(func() error {
			var err error
			row, ok, err = kernel.Lookup(table, p)
			if ok && row.Sentinel {
				ok = false
			}
			return err
		})
		return row, ok
	}
	exact := func(table uint32, p netip.Prefix, sid netip.Addr, mac net.HardwareAddr) {
		t.Helper()
		row, ok := entry(table, p)
		if !ok || !sameSID(row.SID, sid) || row.LinkIndex != n.uplink || row.DMAC.String() != mac.String() {
			t.Fatalf("table %d %s = %+v (present %t), want %s via %s", table, p, row, ok, sid, mac)
		}
	}

	rt.Apply([]routes.Route{
		route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA),
		route(vpcB, tableB, host2, sidBB),
	}, nil)
	st := reconcile(vpcA, claim())
	reconcile(vpcB, nil)
	exact(tableA, host2, sidBA, macB)
	exact(tableA, host3, sidCA, macC)
	exact(tableB, host2, sidBB, macB)
	wantState(t, st, "dB", true, true, true, "")
	wantState(t, st, "dC", true, true, true, "")

	// Requeues from now on name only the VPCs an event touches.
	var (
		mu      sync.Mutex
		changed []string
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	n.do(func() error {
		return m.Watch(ctx, func(vpc string) {
			mu.Lock()
			defer mu.Unlock()
			if !slices.Contains(changed, vpc) {
				changed = append(changed, vpc)
			}
		}, func(err error) { t.Errorf("subscription: %v", err) })
	})
	waitChanged := func(want []string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			got := slices.Clone(changed)
			mu.Unlock()
			slices.Sort(got)
			if slices.Equal(got, want) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("requeued %v, want %v", got, want)
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		if got := slices.Sorted(slices.Values(changed)); !slices.Equal(got, want) {
			t.Fatalf("requeued %v, want %v", got, want)
		}
		changed = nil
	}

	// Node C's neighbor is lost: only dC, and only VPC A, are affected; the
	// entry is kept.
	n.do(func() error {
		return netlink.NeighDel(&netlink.Neigh{LinkIndex: n.uplink, Family: netlink.FAMILY_V6, IP: gwC})
	})
	waitChanged([]string{vpcA})
	st = reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, true, "")
	wantState(t, st, "dC", true, false, true, workerv1alpha1.ReasonNeighborUnresolved)
	exact(tableA, host3, sidCA, macC)

	// It comes back with a new MAC: the entry follows it and dC recovers.
	n.do(func() error { return n.neighbor(gwC, macD) })
	waitChanged([]string{vpcA})
	st = reconcile(vpcA, claim())
	exact(tableA, host3, sidCA, macD)
	wantState(t, st, "dC", true, true, true, "")

	// The underlay route toward node B is withdrawn: both VPCs use it.
	n.do(func() error { return netlink.RouteDel(&netlink.Route{LinkIndex: n.uplink, Dst: ipnet(locB), Gw: gwB}) })
	waitChanged([]string{vpcA, vpcB})
	st = reconcile(vpcA, claim())
	wantState(t, st, "dB", true, false, true, workerv1alpha1.ReasonUnderlayUnreachable)
	wantState(t, st, "dC", true, true, true, "")
	exact(tableA, host2, sidBA, macB)

	n.underlay(locB, gwB, macB)
	waitChanged([]string{vpcA, vpcB})
	st = reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, true, "")

	// VPC A's route to the shared guest address is withdrawn; VPC B's stays.
	rt.Apply(nil, []routes.Key{{VPC: vpcA, Prefix: host2}})
	st = reconcile(vpcA, claim())
	if _, ok := entry(tableA, host2); ok {
		t.Error("withdrawn entry kept in VPC A's table")
	}
	exact(tableB, host2, sidBB, macB)
	wantState(t, st, "dB", false, false, true, workerv1alpha1.ReasonRouteWithdrawn)
}
