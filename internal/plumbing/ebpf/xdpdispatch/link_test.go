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

	"github.com/cilium/ebpf"
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

// auto runs one Locked call under its own lock, for tests that make single
// calls rather than hold the lock across several.
type auto struct {
	t *testing.T
	d *Dispatcher
}

func locked(t *testing.T, d *Dispatcher) auto { return auto{t, d} }

func (a auto) lock() *Locked {
	a.t.Helper()
	l, err := a.d.Lock(context.Background())
	if err != nil {
		a.t.Fatalf("Lock: %v", err)
	}
	return l
}

func (a auto) EnsureLink(ifindex int) (bool, error) {
	l := a.lock()
	defer l.Unlock()
	return l.EnsureLink(ifindex)
}

func (a auto) SetRole(ifindex int, role Role) error {
	l := a.lock()
	defer l.Unlock()
	return l.SetRole(ifindex, role)
}

func (a auto) RemoveRole(ifindex int, role Role) error {
	l := a.lock()
	defer l.Unlock()
	return l.RemoveRole(ifindex, role)
}

func (a auto) ClearRoles(ifindex int) error {
	l := a.lock()
	defer l.Unlock()
	return l.ClearRoles(ifindex)
}

func (a auto) Release(ifindex int) error {
	l := a.lock()
	defer l.Unlock()
	return l.Release(ifindex)
}

func (a auto) PruneDefunct() ([]int, error) {
	l := a.lock()
	defer l.Unlock()
	return l.PruneDefunct()
}

func (a auto) Clear(slot Slot) error {
	l := a.lock()
	defer l.Unlock()
	return l.Clear(slot)
}

func (a auto) ClearIfHeld(slot Slot, program *ebpf.Program) (bool, error) {
	l := a.lock()
	defer l.Unlock()
	return l.ClearIfHeld(slot, program)
}

func ensureLink(t *testing.T, d *Dispatcher, ifindex int) bool {
	t.Helper()
	bounced, err := locked(t, d).EnsureLink(ifindex)
	if err != nil {
		t.Fatalf("EnsureLink: %v", err)
	}
	return bounced
}

func rootID(t *testing.T, d *Dispatcher) uint32 {
	t.Helper()
	id, err := d.RootID()
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
	if err := locked(t, nat).SetRole(ifindex, RoleEgress); err != nil {
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
	_, err = locked(t, d).EnsureLink(ifindex)
	if !errors.Is(err, ErrForeignProgram) {
		t.Fatalf("EnsureLink over a foreign program: err = %v, want ErrForeignProgram", err)
	}
	if got := attachedProgID(t, ifindex); got != uint32(foreignID) {
		t.Errorf("foreign program replaced: ifindex runs %d, want %d", got, foreignID)
	}

	nat := stubProgram(t, xdpDrop)
	if err := locked(t, d).SetRole(ifindex, RoleEgress); err != nil {
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
			t.Cleanup(func() { _ = locked(t, d).ClearRoles(ifindex) })
			if err := locked(t, d).SetRole(ifindex, tt.first); err != nil {
				t.Fatalf("SetRole(%#x): %v", tt.first, err)
			}
			if err := locked(t, d).SetRole(ifindex, tt.again); !errors.Is(err, ErrRoleConflict) {
				t.Errorf("SetRole(%#x) = %v, want ErrRoleConflict", tt.again, err)
			}
			if got, _ := d.Roles(ifindex); got != tt.first {
				t.Errorf("roles = %#x after the refusal, want %#x", got, tt.first)
			}
		})
	}

	// Return and egress share an internal link that is also a NAT uplink.
	if err := locked(t, d).SetRole(4243, RoleInternalReturn|RoleEgress); err != nil {
		t.Errorf("SetRole(return|egress): %v", err)
	}
}

func TestPruneDefunct_ReleasesALinkWhoseInterfaceIsGone(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpd")
	d := openDispatcher(t, dir)
	ensureLink(t, d, ifindex)
	if err := locked(t, d).SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatalf("delete veth: %v", err)
	}

	pruned, err := locked(t, d).PruneDefunct()
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
	if err := locked(t, d).SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	if err := locked(t, d).Release(ifindex); err != nil {
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
	if err := locked(t, d).SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("empty slot: Coverage = %v, want ErrSlotNotHeld", err)
	}
	// Fill renews the lease, so the slot is covered at once.
	if err := d.Fill(SlotNAT, prog); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); err != nil {
		t.Errorf("filled: Coverage = %v, want nil", err)
	}
	if err := d.setLease(SlotNAT, monotonicNow()-1); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrLeaseExpired) {
		t.Errorf("expired lease: Coverage = %v, want ErrLeaseExpired", err)
	}
	if err := d.Renew(SlotNAT); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if live, err := d.LiveSlots(); err != nil || len(live) != 1 || live[0] != SlotNAT {
		t.Errorf("LiveSlots = %v, %v; want [%d]", live, err, SlotNAT)
	}
	if err := d.Coverage(ifindex, SlotNAT, stubProgram(t, xdpDrop)); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("another program: Coverage = %v, want ErrSlotNotHeld", err)
	}
	if err := locked(t, d).Clear(SlotNAT); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if err := d.Coverage(ifindex, SlotNAT, prog); !errors.Is(err, ErrSlotNotHeld) {
		t.Errorf("cleared: Coverage = %v, want ErrSlotNotHeld", err)
	}
}

func TestLock_WaitsForTheHolder(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)

	held, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := d.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second Lock while held = %v, want a deadline error", err)
	}
	held.Unlock()
	again, err := d.Lock(context.Background())
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	again.Unlock()
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

// TestEnsureLink_FollowsANewerPinnedRoot is the mixed-revision rollout: one
// process opened before another pinned a newer root. Its EnsureLink must leave
// the newer root in place, and its Coverage must accept it.
func TestEnsureLink_FollowsANewerPinnedRoot(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpg")
	older := openDispatcher(t, dir)
	ensureLink(t, older, ifindex)
	prog := stubProgram(t, xdpDrop)
	if err := locked(t, older).SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := older.Fill(SlotNAT, prog); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	// Another process pins a newer root, as Open does, and moves the link.
	var newer DispatchObjects
	if err := LoadDispatchObjects(&newer, &ebpf.CollectionOptions{MapReplacements: older.Maps()}); err != nil {
		t.Fatalf("load newer root: %v", err)
	}
	t.Cleanup(func() { _ = newer.XdpDispatch.Close() })
	staged := filepath.Join(dir, abiDirName, rootStagedPinName)
	if err := newer.XdpDispatch.Pin(staged); err != nil {
		t.Fatalf("pin newer root: %v", err)
	}
	if err := os.Rename(staged, older.rootPath()); err != nil {
		t.Fatalf("install newer root: %v", err)
	}
	if err := older.updateLinks(newer.XdpDispatch); err != nil {
		t.Fatalf("move links: %v", err)
	}
	newerID := rootID(t, older)

	if bounced := ensureLink(t, older, ifindex); bounced {
		t.Error("EnsureLink re-attached a live link")
	}
	if got := attachedProgID(t, ifindex); got != newerID {
		t.Errorf("after the older process's EnsureLink, ifindex runs %d, want the newer root %d", got, newerID)
	}
	if err := older.Coverage(ifindex, SlotNAT, prog); err != nil {
		t.Errorf("older process's Coverage under the newer root = %v, want nil", err)
	}
}

// TestSetRole_ConcurrentWritersKeepEveryBit has two processes add their roles
// to the same interfaces at the same time. Neither bit may be lost.
func TestSetRole_ConcurrentWritersKeepEveryBit(t *testing.T) {
	dir := testPinDir(t)
	gateway := openDispatcher(t, dir)
	nat := openDispatcher(t, dir)

	const base, count = 10000, 200
	done := make(chan error, 2)
	for _, w := range []struct {
		d    *Dispatcher
		role Role
	}{{gateway, RolePublicLB}, {nat, RoleEgress}} {
		go func() {
			for i := range count {
				l, err := w.d.Lock(context.Background())
				if err != nil {
					done <- err
					return
				}
				err = l.SetRole(base+i, w.role)
				l.Unlock()
				if err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("SetRole: %v", err)
		}
	}
	for i := range count {
		got, err := gateway.Roles(base + i)
		if err != nil {
			t.Fatalf("Roles: %v", err)
		}
		if got != RolePublicLB|RoleEgress {
			t.Errorf("ifindex %d roles = %#x, want %#x", base+i, got, RolePublicLB|RoleEgress)
		}
		_ = locked(t, gateway).ClearRoles(base + i)
	}
}

func TestRemoveRole_KeepsTheOtherDatapathsBits(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)
	const ifindex = 4300
	t.Cleanup(func() { _ = locked(t, d).ClearRoles(ifindex) })

	if err := locked(t, d).SetRole(ifindex, RoleInternalReturn|RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := locked(t, d).RemoveRole(ifindex, RoleInternalReturn); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if got, _ := d.Roles(ifindex); got != RoleEgress {
		t.Errorf("roles = %#x, want only egress %#x", got, RoleEgress)
	}
	// The interface can now take the public role.
	if err := locked(t, d).SetRole(ifindex, RolePublicLB); err != nil {
		t.Errorf("SetRole(public) after removing return: %v", err)
	}
	if err := locked(t, d).RemoveRole(ifindex, RolePublicLB|RoleEgress); err != nil {
		t.Fatalf("RemoveRole(all): %v", err)
	}
	var raw uint32
	if err := d.maps.IfaceRoles.Lookup(uint32(ifindex), &raw); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("row still present with roles %#x after removing every bit", raw)
	}
}

// TestClearIfHeld_LeavesASuccessorsSlot is a rollout: the new pod fills the
// slot before the old one shuts down, and the old one must not empty it.
func TestClearIfHeld_LeavesASuccessorsSlot(t *testing.T) {
	dir := testPinDir(t)
	d := openDispatcher(t, dir)
	oldProg, newProg := stubProgram(t, xdpDrop), stubProgram(t, xdpTx)

	if err := d.Fill(SlotNAT, oldProg); err != nil {
		t.Fatalf("Fill old: %v", err)
	}
	if err := d.Fill(SlotNAT, newProg); err != nil {
		t.Fatalf("Fill new: %v", err)
	}
	cleared, err := locked(t, d).ClearIfHeld(SlotNAT, oldProg)
	if err != nil || cleared {
		t.Fatalf("ClearIfHeld(old) = %v, %v; want false, nil", cleared, err)
	}
	if live, _ := d.LiveSlots(); len(live) != 1 || live[0] != SlotNAT {
		t.Errorf("LiveSlots = %v after the old pod's ClearIfHeld, want [%d]", live, SlotNAT)
	}
	cleared, err = locked(t, d).ClearIfHeld(SlotNAT, newProg)
	if err != nil || !cleared {
		t.Fatalf("ClearIfHeld(new) = %v, %v; want true, nil", cleared, err)
	}
	if live, _ := d.LiveSlots(); len(live) != 0 {
		t.Errorf("LiveSlots = %v after clearing, want none", live)
	}
}
