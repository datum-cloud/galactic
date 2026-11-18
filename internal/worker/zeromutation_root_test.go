// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF)")
	}
}

const rowTable = 1000

// netKernel mirrors each fake module row into real kernel state in a test
// network namespace: a dummy link, a route in a VRF-style table, a policy
// rule and a row in a pinned BPF map.
type netKernel struct {
	netns ns.NetNS
	rows  *ebpf.Map
}

func rowIndex(scope module.Scope, r fake.Row) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope.VPC + "/" + r.Key.String() + "/" + r.ID))
	return h.Sum32()%4000 + 1
}

func rowPrefix(i uint32) *net.IPNet {
	ip := net.ParseIP("2001:db8:ffff::").To16()
	binary.BigEndian.PutUint16(ip[6:], uint16(i))
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
}

func (k *netKernel) Add(scope module.Scope, r fake.Row) error {
	i := rowIndex(scope, r)
	if err := k.rows.Put(i, r.Generation); err != nil {
		return err
	}
	return k.netns.Do(func(ns.NetNS) error {
		name := fmt.Sprintf("wrow%d", i)
		if _, err := netlink.LinkByName(name); err != nil {
			if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
				return err
			}
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: l.Attrs().Index, Table: rowTable,
			Dst: rowPrefix(i)}); err != nil {
			return err
		}
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority, rule.Dst = unix.AF_INET6, rowTable, int(i)+100, rowPrefix(i)
		if err := netlink.RuleAdd(rule); err != nil && !os.IsExist(err) {
			return err
		}
		return nil
	})
}

func (k *netKernel) Remove(scope module.Scope, r fake.Row) error {
	i := rowIndex(scope, r)
	if err := k.rows.Delete(i); err != nil {
		return err
	}
	return k.netns.Do(func(ns.NetNS) error {
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority, rule.Dst = unix.AF_INET6, rowTable, int(i)+100, rowPrefix(i)
		_ = netlink.RuleDel(rule)
		if l, err := netlink.LinkByName(fmt.Sprintf("wrow%d", i)); err == nil {
			return netlink.LinkDel(l)
		}
		return nil
	})
}

// snapshot renders every link, route, rule and pinned map row the test can
// see in the namespace and the bpffs, sorted.
func snapshot(t *testing.T, netns ns.NetNS, pin string) []string {
	t.Helper()
	var out []string
	err := netns.Do(func(ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			a := l.Attrs()
			out = append(out, fmt.Sprintf("link %d %s %s mtu=%d flags=%s", a.Index, a.Name, l.Type(), a.MTU, a.Flags))
		}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			out = append(out, fmt.Sprintf("route table=%d dst=%s dev=%d type=%d", r.Table, r.Dst, r.LinkIndex, r.Type))
		}
		rules, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, r := range rules {
			out = append(out, fmt.Sprintf("rule family=%d prio=%d table=%d dst=%s", r.Family, r.Priority, r.Table, r.Dst))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	var k uint32
	var v uint64
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, fmt.Sprintf("map %d=%d", k, v))
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// TestCrossVPCRefusalLeavesKernelUnchanged is the acceptance test for an
// unauthorized cross-VPC claim: with a claim in VPC A programmed into real
// routes, rules, links and a pinned map, requests that would reach VPC B,
// which uses the same guest addresses, are refused, and a snapshot of the
// kernel state before and after is identical.
func TestCrossVPCRefusalLeavesKernelUnchanged(t *testing.T) {
	requireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	netns, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Close()
		_ = testutils.UnmountNS(netns)
	})
	bpffs := t.TempDir()
	if err := unix.Mount("bpf", bpffs, "bpf", 0, ""); err != nil {
		t.Fatalf("mount bpffs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(bpffs, unix.MNT_DETACH) })
	rows, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{Name: "worker_rows", Type: ebpf.Hash, KeySize: 4,
		ValueSize: 8, MaxEntries: 4096, Pinning: ebpf.PinByName}, ebpf.MapOptions{PinPath: bpffs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rows.Close() })
	pin := filepath.Join(bpffs, "worker_rows")
	kernel := &netKernel{netns: netns, rows: rows}

	e := newEnv(t)
	var local, fabric *fake.Module
	e.modules = func(h *fake.Host) []module.Module {
		local = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
		fabric = fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, h)
		local.Kernel, fabric.Kernel = kernel, kernel
		return []module.Module{local, fabric}
	}
	e.start()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a2")))
	e.waitReady(mkey(vpcA, "svc-a"), 1)
	e.idle()

	before := snapshot(t, netns, pin)
	if !slices.ContainsFunc(before, func(s string) bool { return strings.HasPrefix(s, "map ") }) ||
		!slices.ContainsFunc(before, func(s string) bool { return strings.Contains(s, fmt.Sprintf("table=%d", rowTable)) }) {
		t.Fatalf("the programmed claim is not in kernel state: %v", before)
	}
	persisted := e.persisted()
	plans, applies := local.PlanCalls.Load()+fabric.PlanCalls.Load(), local.ApplyCalls.Load()+fabric.ApplyCalls.Load()

	wantRefusal(t, e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1", "guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a2"), 1, veth("guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	wantRefusal(t, e.request(natSA, key(vpcB, "svc-a2"), 1, veth("guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	e.idle()

	after := snapshot(t, netns, pin)
	if !slices.Equal(before, after) {
		t.Fatalf("kernel state changed:\nbefore %v\nafter  %v", before, after)
	}
	if got := e.persisted(); len(got) != len(persisted) {
		t.Fatal("durable state changed")
	} else {
		for k, v := range persisted {
			if got[k] != v {
				t.Fatalf("%s changed", k)
			}
		}
	}
	if local.PlanCalls.Load()+fabric.PlanCalls.Load() != plans ||
		local.ApplyCalls.Load()+fabric.ApplyCalls.Load() != applies {
		t.Fatal("a refused claim reached a module")
	}
	// The existing generation keeps running.
	if st := e.status(mkey(vpcA, "svc-a")); st.GetGeneration() != 1 || !isTrue(st, workerv1alpha1.ConditionReady) {
		t.Fatalf("existing claim = %v", st)
	}
}
