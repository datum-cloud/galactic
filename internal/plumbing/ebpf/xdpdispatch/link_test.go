// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// testPinDir returns a fresh per-test pin directory under /sys/fs/bpf.
func testPinDir(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	dir := filepath.Join("/sys/fs/bpf", "xdpdispatch-test-"+name)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("bpffs not writable at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() {
		// Removing the link pins detaches whatever they still hold.
		_ = os.RemoveAll(dir)
	})
	return dir
}

// testVeth creates an up veth pair named after the test and returns the first
// end's ifindex.
func testVeth(t *testing.T, prefix string) int {
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
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("find %s: %v", name, err)
	}
	return l.Attrs().Index
}

// attachedProgID returns the XDP program ID attached to ifindex, 0 for none.
func attachedProgID(t *testing.T, ifindex int) uint32 {
	t.Helper()
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("find ifindex %d: %v", ifindex, err)
	}
	if xdp := l.Attrs().Xdp; xdp != nil && xdp.Attached {
		return xdp.ProgId
	}
	return 0
}

func openDispatcher(t *testing.T, dir string) *Dispatcher {
	t.Helper()
	d, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func ensureLink(t *testing.T, d *Dispatcher, ifindex int) bool {
	t.Helper()
	unlock, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer unlock()
	bounced, err := d.EnsureLink(ifindex)
	if err != nil {
		t.Fatalf("EnsureLink: %v", err)
	}
	return bounced
}

func rootID(t *testing.T, d *Dispatcher) uint32 {
	t.Helper()
	id, err := programID(d.Root())
	if err != nil {
		t.Fatalf("root ID: %v", err)
	}
	return uint32(id)
}

// TestEnsureLink_SurvivesTheOwnerClosing is issue #717's restart case: the
// process that attached the root exits, closing every descriptor it held, and
// the root stays on the interface with the other datapath's slot still
// covered.
func TestEnsureLink_SurvivesTheOwnerClosing(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpa")

	gateway, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !ensureLink(t, gateway, ifindex) {
		t.Fatal("first EnsureLink reported no attach")
	}
	want := rootID(t, gateway)

	nat := openDispatcher(t, dir)
	natProg := stubProgram(t, xdpDrop)
	if err := nat.SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := nat.Fill(SlotNAT, natProg); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if err := nat.Renew(SlotNAT); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if ensureLink(t, nat, ifindex) {
		t.Error("second datapath's EnsureLink re-attached an already pinned link")
	}

	// The gateway process exits.
	if err := gateway.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := attachedProgID(t, ifindex); got != want {
		t.Fatalf("after the owner closed, ifindex %d runs program %d, want the root %d", ifindex, got, want)
	}
	if err := nat.Coverage(ifindex, SlotNAT, natProg); err != nil {
		t.Errorf("NAT slot not covered after the owner closed: %v", err)
	}
}

// TestOpen_NewerRootReplacesThePinnedOneInPlace proves a root upgrade moves
// every link with a link update: the interface never loses its program.
func TestOpen_NewerRootReplacesThePinnedOneInPlace(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpb")

	old := openDispatcher(t, dir)
	ensureLink(t, old, ifindex)
	oldID := rootID(t, old)
	// Make the pinned root look older than this build.
	if err := old.maps.DispatchMeta.Put(metaKeyRevision, uint64(RootRevision-1)); err != nil {
		t.Fatalf("lower pinned revision: %v", err)
	}
	linkPin := old.linkPath(ifindex)
	before, err := os.Stat(linkPin)
	if err != nil {
		t.Fatalf("stat link pin: %v", err)
	}

	upgraded := openDispatcher(t, dir)
	newID := rootID(t, upgraded)
	if newID == oldID {
		t.Fatal("Open kept the older root")
	}
	if got := attachedProgID(t, ifindex); got != newID {
		t.Errorf("ifindex %d runs program %d, want the new root %d", ifindex, got, newID)
	}
	after, err := os.Stat(linkPin)
	if err != nil {
		t.Fatalf("link pin gone after the upgrade: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Error("the upgrade replaced the link instead of updating it")
	}

	// A process of the same revision keeps the pinned root.
	same := openDispatcher(t, dir)
	if got := rootID(t, same); got != newID {
		t.Errorf("same-revision Open loaded root %d, want the pinned %d", got, newID)
	}
}

// TestEnsureLink_LeavesAForeignProgramAlone is issue #717's coverage case: an
// interface held by a program that is not the root is reported, never taken,
// and never counted as covered.
func TestEnsureLink_LeavesAForeignProgramAlone(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpc")
	foreign := stubProgram(t, xdpPass)
	fl, err := link.AttachXDP(link.XDPOptions{Program: foreign, Interface: ifindex, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatalf("attach foreign program: %v", err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	foreignInfo, _ := foreign.Info()
	foreignID, _ := foreignInfo.ID()

	d := openDispatcher(t, dir)
	unlock, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	_, err = d.EnsureLink(ifindex)
	unlock()
	if !errors.Is(err, ErrForeignProgram) {
		t.Fatalf("EnsureLink over a foreign program: err = %v, want ErrForeignProgram", err)
	}
	if got := attachedProgID(t, ifindex); got != uint32(foreignID) {
		t.Errorf("foreign program replaced: ifindex runs %d, want %d", got, foreignID)
	}

	nat := stubProgram(t, xdpDrop)
	if err := d.SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := d.Fill(SlotNAT, nat); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if err := d.Renew(SlotNAT); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, nat); !errors.Is(err, ErrNoLink) {
		t.Errorf("Coverage under a foreign program = %v, want ErrNoLink", err)
	}
}

func TestSetRole_RefusesTheReturnRoleOnAPublicInterface(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)

	for _, tt := range []struct {
		name         string
		first, again Role
	}{
		{"return after public", RolePublicLB, RoleInternalReturn},
		{"public after return", RoleInternalReturn, RolePublicLB},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const ifindex = 4242
			t.Cleanup(func() { _ = d.ClearRoles(ifindex) })
			if err := d.SetRole(ifindex, tt.first); err != nil {
				t.Fatalf("SetRole(%#x): %v", tt.first, err)
			}
			if err := d.SetRole(ifindex, tt.again); !errors.Is(err, ErrRoleConflict) {
				t.Errorf("SetRole(%#x) = %v, want ErrRoleConflict", tt.again, err)
			}
			if got, _ := d.Roles(ifindex); got != tt.first {
				t.Errorf("roles = %#x after the refusal, want %#x", got, tt.first)
			}
		})
	}

	// Return and egress share an internal link that is also a NAT uplink.
	if err := d.SetRole(4243, RoleInternalReturn|RoleEgress); err != nil {
		t.Errorf("SetRole(return|egress): %v", err)
	}
}

func TestPruneDefunct_ReleasesALinkWhoseInterfaceIsGone(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpd")
	d := openDispatcher(t, dir)
	ensureLink(t, d, ifindex)
	if err := d.SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatalf("delete veth: %v", err)
	}

	pruned, err := d.PruneDefunct()
	if err != nil {
		t.Fatalf("PruneDefunct: %v", err)
	}
	if len(pruned) != 1 || pruned[0] != ifindex {
		t.Errorf("pruned %v, want [%d]", pruned, ifindex)
	}
	if _, err := os.Stat(d.linkPath(ifindex)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("defunct link pin still present: %v", err)
	}
	if got, _ := d.Roles(ifindex); got != 0 {
		t.Errorf("roles = %#x after pruning, want none", got)
	}
}

func TestRelease_DetachesTheRoot(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpe")
	d := openDispatcher(t, dir)
	ensureLink(t, d, ifindex)
	if err := d.SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	if err := d.Release(ifindex); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got := attachedProgID(t, ifindex); got != 0 {
		t.Errorf("ifindex %d still runs program %d after Release", ifindex, got)
	}
	if got, _ := d.Roles(ifindex); got != 0 {
		t.Errorf("roles = %#x after Release, want none", got)
	}
	if !ensureLink(t, d, ifindex) {
		t.Error("EnsureLink after Release did not attach again")
	}
}

func TestCoverage_FollowsTheSlotAndItsLease(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpf")
	d := openDispatcher(t, dir)
	ensureLink(t, d, ifindex)
	prog := stubProgram(t, xdpDrop)

	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrRoleMissing) {
		t.Errorf("no role: Coverage = %v, want ErrRoleMissing", err)
	}
	if err := d.SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("empty slot: Coverage = %v, want ErrSlotNotHeld", err)
	}
	if err := d.Fill(SlotNAT, prog); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrLeaseExpired) {
		t.Errorf("no lease: Coverage = %v, want ErrLeaseExpired", err)
	}
	if err := d.Renew(SlotNAT); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); err != nil {
		t.Errorf("filled and leased: Coverage = %v, want nil", err)
	}
	if live, err := d.LiveSlots(); err != nil || len(live) != 1 || live[0] != SlotNAT {
		t.Errorf("LiveSlots = %v, %v; want [%d]", live, err, SlotNAT)
	}
	if err := d.Coverage(ifindex, SlotNAT, stubProgram(t, xdpDrop)); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("another program: Coverage = %v, want ErrSlotNotHeld", err)
	}
	if err := d.Clear(SlotNAT); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("cleared: Coverage = %v, want ErrSlotNotHeld", err)
	}
}

func TestLock_WaitsForTheHolder(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)

	unlock, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := d.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second Lock while held = %v, want a deadline error", err)
	}
	unlock()
	again, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	again()
}

func TestOpen_RefusesAnotherABI(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)
	if err := d.maps.DispatchMeta.Put(metaKeyABI, uint64(ABIVersion+1)); err != nil {
		t.Fatalf("write ABI: %v", err)
	}
	if _, err := Open(context.Background(), dir); !errors.Is(err, ErrIncompatibleLayout) {
		t.Errorf("Open over another ABI = %v, want ErrIncompatibleLayout", err)
	}
}

func TestFill_RejectsAnOutOfRangeSlot(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)
	if err := d.Fill(NumSlots, stubProgram(t, xdpPass)); !errors.Is(err, errInvalidSlot) {
		t.Errorf("Fill(NumSlots) = %v, want errInvalidSlot", err)
	}
	if err := d.Fill(SlotNAT, nil); !errors.Is(err, errNilProgram) {
		t.Errorf("Fill(nil) = %v, want errNilProgram", err)
	}
}
