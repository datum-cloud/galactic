// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// tcxPassProgram loads a tc program named name that hands every packet to
// the next tcx program.
func tcxPassProgram(t *testing.T, name string) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func programIDOf(t *testing.T, p *ebpf.Program) ebpf.ProgramID {
	t.Helper()
	id, err := tcxProgramID(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestTCXGuardRoot checks the routed-link guard's tcx attachment on a real
// kernel: it goes to the head and replaces Local's clsact filter, moves back
// to the head when another program is attached ahead of it, takes over from
// an earlier load's instance, reports ErrGuardNotFirst when it cannot be
// first, and DetachTCXGuard removes every instance and nothing else.
func TestTCXGuardRoot(t *testing.T) { //nolint:gocyclo // privileged end-to-end sequence
	requireRoot(t)
	const name = "guard0"
	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-tcxguard-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nsObj.Close() }()

	guard := tcxPassProgram(t, LocalGuardProgramName)
	again := tcxPassProgram(t, LocalGuardProgramName)
	foreign := tcxPassProgram(t, "foreign_head")
	other := tcxPassProgram(t, "other_head")
	third := tcxPassProgram(t, "third_head")
	guardID, againID := programIDOf(t, guard), programIDOf(t, again)
	foreignID, otherID, thirdID := programIDOf(t, foreign), programIDOf(t, other), programIDOf(t, third)

	err = nsObj.Do(func(_ ns.NetNS) error {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			return err
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		idx := l.Attrs().Index
		chain := func() []ebpf.ProgramID {
			ids, err := tcxQueryFn(idx)
			if err != nil {
				t.Fatal(err)
			}
			return ids
		}
		objs, err := Load(pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = objs.Close() }()

		// A link guarded the clsact way, as before.
		if err := AttachLocal(objs.TpDeliver, name, LocalFilterPrefix+"link_guard"); err != nil {
			return err
		}
		if err := EnsureTCXGuard(guard, name); err != nil {
			return fmt.Errorf("first attach: %w", err)
		}
		if got := chain(); !slices.Equal(got, []ebpf.ProgramID{guardID}) {
			t.Fatalf("tcx chain = %v, want only the guard %d", got, guardID)
		}
		if _, _, ok, err := LocalFilter(idx); err != nil || ok {
			t.Fatalf("Local's clsact filter stays beside the tcx guard (%v)", err)
		}
		if st, err := TCXGuard(guard, idx); err != nil || !st.Attached || !st.First || st.Head != guardID {
			t.Fatalf("TCXGuard = %+v, %v; want attached and first", st, err)
		}

		// Another program attached at the head goes behind the guard.
		if err := tcxAttachHeadFn(idx, foreign); err != nil {
			return err
		}
		if st, err := TCXGuard(guard, idx); err != nil || !st.Attached || st.First || st.Head != foreignID {
			t.Fatalf("TCXGuard with a program ahead = %+v, %v", st, err)
		}
		if err := EnsureTCXGuard(guard, name); err != nil {
			return fmt.Errorf("re-assert: %w", err)
		}
		if got := chain(); !slices.Equal(got, []ebpf.ProgramID{guardID, foreignID}) {
			t.Fatalf("tcx chain after re-assert = %v, want the guard %d then %d", got, guardID, foreignID)
		}

		// A new load takes over, with the earlier instance attached until
		// the new one is first.
		if st, err := TCXGuard(again, idx); err != nil || st.Attached || !slices.Equal(st.Stale, []ebpf.ProgramID{guardID}) {
			t.Fatalf("TCXGuard of a new load = %+v, %v; want the earlier instance stale", st, err)
		}
		if err := EnsureTCXGuard(again, name); err != nil {
			return fmt.Errorf("take over: %w", err)
		}
		if got := chain(); !slices.Equal(got, []ebpf.ProgramID{againID, foreignID}) {
			t.Fatalf("tcx chain after take-over = %v, want %d then %d", got, againID, foreignID)
		}

		// A program goes ahead of the guard, and another agent races the
		// move back to the head.
		origAttach := tcxAttachHeadFn
		if err := origAttach(idx, other); err != nil {
			return err
		}
		tcxAttachHeadFn = func(ifindex int, p *ebpf.Program) error {
			if err := origAttach(ifindex, p); err != nil {
				return err
			}
			return origAttach(ifindex, third)
		}
		err = EnsureTCXGuard(again, name)
		tcxAttachHeadFn = origAttach
		if !errors.Is(err, ErrGuardNotFirst) {
			t.Fatalf("EnsureTCXGuard with a program kept ahead = %v, want ErrGuardNotFirst", err)
		}
		if st, err := TCXGuard(again, idx); err != nil || !st.Attached || st.First || st.Head != thirdID {
			t.Fatalf("TCXGuard behind a kept program = %+v, %v", st, err)
		}

		if err := DetachTCXGuard(name); err != nil {
			return err
		}
		if got := chain(); !slices.Equal(got, []ebpf.ProgramID{thirdID, otherID, foreignID}) {
			t.Fatalf("tcx chain after DetachTCXGuard = %v, want only the others %d, %d and %d", got, thirdID,
				otherID, foreignID)
		}
		if err := DetachTCXGuard(name + "-gone"); err != nil {
			t.Errorf("DetachTCXGuard of a missing link: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDetachEgressRoot checks that DetachEgress removes the egress chain
// and tp_deliver and leaves other filters.
func TestDetachEgressRoot(t *testing.T) {
	requireRoot(t)
	const name = "detach0"
	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-detachegress-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nsObj.Close() }()
	err = nsObj.Do(func(_ ns.NetNS) error {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			return err
		}
		objs, err := Load(pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = objs.Close() }()
		if ok, err := HasAnyEgress(name); err != nil || ok {
			t.Fatalf("HasAnyEgress before attach = %t, %v", ok, err)
		}
		if err := AttachEgress(objs.UsidServiceEgress, objs.UsidEgress, name); err != nil {
			return err
		}
		if err := AttachDeliver(objs.TpDeliver, name); err != nil {
			return err
		}
		if err := AttachLocal(objs.TpDeliver, name, LocalFilterPrefix+"link_rx"); err != nil {
			return err
		}
		if ok, err := HasAnyEgress(name); err != nil || !ok {
			t.Fatalf("HasAnyEgress after attach = %t, %v", ok, err)
		}
		if err := DetachEgress(name); err != nil {
			return err
		}
		if ok, err := HasAnyEgress(name); err != nil || ok {
			t.Fatalf("HasAnyEgress after DetachEgress = %t, %v", ok, err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		if _, _, ok, err := LocalFilter(l.Attrs().Index); err != nil || !ok {
			t.Fatalf("DetachEgress removed another filter (%v)", err)
		}
		if err := DetachEgress(name + "-gone"); err != nil {
			t.Errorf("DetachEgress of a missing link: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
