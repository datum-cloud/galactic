// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// A routed link's host end carries the uSID egress datapath at clsact, and
// the kernel runs every tcx program on a hook before any clsact filter. Worker
// attaches the link's source guard to tcx ingress, at the head of the chain,
// so it decides every packet before usid_service_egress and usid_egress can
// encapsulate one. The guard returns TC_ACT_UNSPEC (TCX_NEXT) to admit and
// TC_ACT_SHOT (TCX_DROP) to drop. The attachment is a raw BPF_PROG_ATTACH,
// which the kernel keeps for the device's lifetime with no pin or link
// descriptor, so it survives Worker.

// LocalGuardProgramName is the name of Worker's routed-link guard program.
// Every Worker load of the guard has it, so it identifies an earlier load's
// instance and lets a health check tell the guard from a foreign program.
const LocalGuardProgramName = "local_link_guard"

// bpfObjNameLen is the kernel's BPF_OBJ_NAME_LEN, including the terminating
// NUL.
const bpfObjNameLen = 16

// IsLocalGuardName reports whether name, a program's name as the kernel or
// its BTF reports it, is the routed-link guard's. The kernel keeps only the
// first bpfObjNameLen-1 bytes of a name; a reader with the program's BTF
// recovers the whole.
func IsLocalGuardName(name string) bool {
	return name == LocalGuardProgramName || name == LocalGuardProgramName[:bpfObjNameLen-1]
}

// ErrGuardNotFirst is returned by EnsureTCXGuard when the guard is attached
// but another program still runs before it on tcx ingress.
var ErrGuardNotFirst = errors.New("attach: another tcx program runs before the routed link's guard")

// tcxAttachHeadFn attaches program at the head of ifindex's tcx ingress, and
// tcxDetachFn removes it. Override points for tests.
var (
	tcxAttachHeadFn = func(ifindex int, program *ebpf.Program) error {
		return link.RawAttachProgram(link.RawAttachProgramOptions{Target: ifindex, Program: program,
			Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
	}
	tcxDetachFn = func(ifindex int, program *ebpf.Program) error {
		return link.RawDetachProgram(link.RawDetachProgramOptions{Target: ifindex, Program: program,
			Attach: ebpf.AttachTCXIngress})
	}
)

// TCXGuardState is where the routed-link guard stands on one interface's tcx
// ingress.
type TCXGuardState struct {
	// Attached is set when the program asked about is on the chain.
	Attached bool
	// First is set when it runs first.
	First bool
	// Stale are the other instances of the guard on the chain, which an
	// earlier load attached.
	Stale []ebpf.ProgramID
	// Head is the program that runs first, or 0 when the chain is empty.
	Head ebpf.ProgramID
}

// Guarded reports whether some instance of the guard is on the chain.
func (s TCXGuardState) Guarded() bool { return s.Attached || len(s.Stale) > 0 }

// TCXGuard reports where program, a load of the routed-link guard, stands on
// ifindex's tcx ingress. A kernel without tcx returns an error wrapping
// ebpf.ErrNotSupported.
func TCXGuard(program *ebpf.Program, ifindex int) (TCXGuardState, error) {
	id, err := tcxProgramID(program)
	if err != nil {
		return TCXGuardState{}, err
	}
	return tcxGuardState(id, ifindex)
}

func tcxGuardState(id ebpf.ProgramID, ifindex int) (TCXGuardState, error) {
	ids, err := tcxQueryFn(ifindex)
	if err != nil {
		return TCXGuardState{}, fmt.Errorf("attach: query tcx ingress of ifindex %d: %w", ifindex, err)
	}
	var st TCXGuardState
	if len(ids) > 0 {
		st.Head = ids[0]
	}
	for i, other := range ids {
		if other == id {
			st.Attached, st.First = true, i == 0
			continue
		}
		if isGuardProgram(other) {
			st.Stale = append(st.Stale, other)
		}
	}
	return st, nil
}

// isGuardProgram reports whether id names an instance of the routed-link
// guard. A name that cannot be read is not the guard's.
func isGuardProgram(id ebpf.ProgramID) bool {
	name, err := programNameFn(id)
	return err == nil && IsLocalGuardName(name)
}

// EnsureTCXGuard makes program, a load of the routed-link guard, the first
// program on ifaceName's tcx ingress, under galactic-cni's per-interface
// lock. It attaches program at the head when it is absent, then detaches the
// guard's other instances, so a link that carried an earlier load's guard is
// never unguarded. When another program runs first it detaches program and
// attaches it at the head again; the caller keeps the link down meanwhile.
// Once program is attached it removes Local's clsact filter from the link,
// which the tcx guard replaces. It returns ErrGuardNotFirst when program is
// attached but still not first, and an error wrapping ebpf.ErrNotSupported on a
// kernel without tcx.
func EnsureTCXGuard(program *ebpf.Program, ifaceName string) error {
	id, err := tcxProgramID(program)
	if err != nil {
		return err
	}
	return withInterfaceLockFn(ifaceName, func() error {
		l, err := linkByNameFn(ifaceName)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceName, err)
		}
		ifindex := l.Attrs().Index
		st, err := tcxGuardState(id, ifindex)
		if err != nil {
			return err
		}
		switch {
		case !st.Attached:
			if err := tcxAttachHeadFn(ifindex, program); err != nil {
				return fmt.Errorf("attach the guard to %q's tcx ingress: %w", ifaceName, err)
			}
		case !st.First && !slices.Contains(st.Stale, st.Head):
			// Another program was attached ahead of the guard: the guard
			// moves back to the head. A stale instance at the head is
			// removed below instead, which leaves this one first.
			if err := tcxDetachFn(ifindex, program); err != nil {
				return fmt.Errorf("detach the guard from %q's tcx ingress: %w", ifaceName, err)
			}
			if err := tcxAttachHeadFn(ifindex, program); err != nil {
				return fmt.Errorf("attach the guard to %q's tcx ingress: %w", ifaceName, err)
			}
		}
		if err := detachStaleGuards(ifindex, st.Stale); err != nil {
			return fmt.Errorf("detach an earlier guard from %q: %w", ifaceName, err)
		}
		if err := deleteLocalFilters(l, func(string) bool { return true }); err != nil {
			return err
		}
		if st, err = tcxGuardState(id, ifindex); err != nil {
			return err
		}
		if !st.First {
			return fmt.Errorf("%w on %q: program %d runs first", ErrGuardNotFirst, ifaceName, st.Head)
		}
		return nil
	})
}

// DetachTCXGuard removes every instance of the routed-link guard from
// ifaceName's tcx ingress. An interface that no longer exists, or a kernel
// without tcx, is not an error.
func DetachTCXGuard(ifaceName string) error {
	return withInterfaceLockFn(ifaceName, func() error {
		l, err := linkByNameFn(ifaceName)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return fmt.Errorf("find link %q: %w", ifaceName, err)
		}
		ids, err := tcxQueryFn(l.Attrs().Index)
		if err != nil {
			if errors.Is(err, ebpf.ErrNotSupported) {
				return nil
			}
			return fmt.Errorf("query tcx ingress of %q: %w", ifaceName, err)
		}
		var guards []ebpf.ProgramID
		for _, id := range ids {
			if isGuardProgram(id) {
				guards = append(guards, id)
			}
		}
		return detachStaleGuards(l.Attrs().Index, guards)
	})
}

// detachStaleGuards detaches each program in ids from ifindex's tcx ingress.
// A program already gone is not an error.
func detachStaleGuards(ifindex int, ids []ebpf.ProgramID) error {
	var errs []error
	for _, id := range ids {
		p, err := programFromIDFn(id)
		if err != nil {
			if programGone(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("open program %d: %w", id, err))
			continue
		}
		if err := tcxDetachFn(ifindex, p); err != nil && !programGone(err) {
			errs = append(errs, fmt.Errorf("detach program %d: %w", id, err))
		}
		_ = p.Close()
	}
	return errors.Join(errs...)
}

// programGone reports whether err means a program, or its attachment, no
// longer exists.
func programGone(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func tcxProgramID(program *ebpf.Program) (ebpf.ProgramID, error) {
	if program == nil {
		return 0, errors.New("attach: guard program is nil")
	}
	info, err := program.Info()
	if err != nil {
		return 0, fmt.Errorf("attach: read guard program info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("attach: kernel did not report the guard's program id")
	}
	return id, nil
}
