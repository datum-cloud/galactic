// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// DispatchSet keeps one datapath's slot reachable on a set of interfaces
// through the node's shared XDP dispatcher (xdpdispatch), in place of the
// datapath's own attachments. It is Set's counterpart for a datapath that
// shares the hook.
//
// It never attaches the datapath's program to an interface. It makes sure the
// dispatcher's root is there, and that the interface carries the datapath's
// role, and reads coverage back from the pinned state. The datapath fills its
// slot and renews the slot's lease itself.
//
// Unlike Set, nothing here is all-or-nothing and nothing is ever detached: an
// interface the dispatcher cannot hold yet is reported missing and tried again
// on the next Reconcile, and an interface that leaves the set keeps the root
// (another datapath may still use it) and its role (an auto-detected uplink
// set is often partial while routing converges).
type DispatchSet struct {
	backend dispatchBackend

	mu      sync.Mutex
	missing []string
}

// dispatchBackend is what DispatchSet needs from the dispatcher, so its tests
// can run without loading anything into the kernel.
type dispatchBackend interface {
	// linked reports whether the root already holds ifindex.
	linked(ifindex int) (bool, error)
	// ensure, under the dispatch lock, attaches the root to ifindex if it is
	// not there and adds the datapath's role. It calls guard first, under the
	// lock, when the root is not there yet, and gives up if guard fails. When
	// it attached, it calls afterBounce before releasing the lock, even if a
	// later step failed, since the interface bounced either way.
	ensure(ctx context.Context, ifindex int, guard, afterBounce func() error) (bounced bool, err error)
	// coverage is nil when the datapath's slot sees ifindex's traffic.
	coverage(ifindex int) error
	// prune releases pinned links whose interface is gone.
	prune(ctx context.Context) error
}

// NewDispatchSet returns a DispatchSet putting program's slot on interfaces
// with role.
func NewDispatchSet(d *xdpdispatch.Dispatcher, slot xdpdispatch.Slot,
	role xdpdispatch.Role, program *ebpf.Program,
) (*DispatchSet, error) {
	if d == nil {
		return nil, errors.New("xdpattach: dispatcher is nil")
	}
	if program == nil {
		return nil, errors.New("xdpattach: program is nil")
	}
	return &DispatchSet{backend: &kernelDispatch{d: d, slot: slot, role: role, program: program}}, nil
}

// Reconcile brings every interface in desired under the dispatcher with this
// datapath's role, and returns the ones its slot does not cover afterwards.
//
// The guards Set applies before an attach apply here too, and only when the
// root is not on the interface yet, since nothing else bounces it: a
// definite lack of native XDP support leaves the interface missing, and so
// does a bond member whose bounce would take the bond down. The guards, the
// attach, and the wait for a bounced bond member to rejoin its aggregate all
// run under the dispatch lock, so no other process bounces a second member of
// the same bond in between.
func (s *DispatchSet) Reconcile(ctx context.Context, desired []string) []string {
	if err := s.backend.prune(ctx); err != nil {
		slog.Warn("xdpattach: cannot prune dispatcher links of removed interfaces", "err", err)
	}

	var missing []string
	blocked := false
	for _, name := range desired {
		l, err := linkByNameFn(name)
		if err != nil {
			slog.Warn("xdpattach: cannot find interface for the XDP dispatcher, will retry", "interface", name, "err", err)
			missing = append(missing, name)
			continue
		}
		ifindex := l.Attrs().Index

		linked, err := s.backend.linked(ifindex)
		if err != nil {
			slog.Warn("xdpattach: cannot read the XDP dispatcher link, will retry", "interface", name, "err", err)
			missing = append(missing, name)
			continue
		}
		if !linked && blocked {
			missing = append(missing, name)
			continue
		}

		var bondErr error
		bounced, err := s.backend.ensure(ctx, ifindex,
			func() error { return s.attachable(name) },
			func() error {
				bondErr = waitBondSlaveReady(name, BondReadyTimeout)
				return nil
			})
		if bondErr != nil {
			slog.Warn("xdpattach: dispatcher interface has not rejoined its bond; deferring the rest",
				"interface", name, "err", bondErr)
			blocked = true
		}
		if err != nil {
			slog.Warn("xdpattach: cannot put the XDP dispatcher on interface yet, will retry",
				"interface", name, "err", err)
			missing = append(missing, name)
			continue
		}
		if bounced {
			slog.Info("xdpattach: attached the XDP dispatcher to interface", "interface", name)
		}
	}

	for _, name := range desired {
		if slices.Contains(missing, name) {
			continue
		}
		l, err := linkByNameFn(name)
		if err != nil {
			missing = append(missing, name)
			continue
		}
		if err := s.backend.coverage(l.Attrs().Index); err != nil {
			slog.Warn("xdpattach: datapath does not see this interface's traffic through the XDP dispatcher",
				"interface", name, "reason", err)
			missing = append(missing, name)
		}
	}

	s.mu.Lock()
	s.missing = slices.Clone(missing)
	s.mu.Unlock()
	return missing
}

// attachable applies the pre-attach guards to name.
func (s *DispatchSet) attachable(name string) error {
	if err := checkNativeXDPSupport([]string{name}); err != nil {
		return err
	}
	isolates, err := bounceIsolatesBond(name)
	if err != nil {
		return err
	}
	if isolates {
		return fmt.Errorf("xdpattach: %q is the only member of its bond carrying traffic; "+
			"attaching now would take the bond down", name)
	}
	return nil
}

// Missing returns what the last Reconcile reported missing.
func (s *DispatchSet) Missing() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.missing)
}

// kernelDispatch is dispatchBackend over the pinned dispatcher.
type kernelDispatch struct {
	d       *xdpdispatch.Dispatcher
	slot    xdpdispatch.Slot
	role    xdpdispatch.Role
	program *ebpf.Program
}

func (k *kernelDispatch) linked(ifindex int) (bool, error) { return k.d.Linked(ifindex) }

func (k *kernelDispatch) ensure(ctx context.Context, ifindex int, guard, afterBounce func() error) (bool, error) {
	// Nothing to do, and no reason to contend for the node-wide lock, when the
	// root is there and the interface already carries the role.
	if linked, err := k.d.Linked(ifindex); err == nil && linked {
		if roles, err := k.d.Roles(ifindex); err == nil && roles&k.role == k.role {
			return false, nil
		}
	}

	l, err := k.d.Lock(ctx)
	if err != nil {
		return false, err
	}
	defer l.Unlock()

	linked, err := k.d.Linked(ifindex)
	if err != nil {
		return false, err
	}
	if !linked {
		if err := guard(); err != nil {
			return false, err
		}
	}
	bounced, err := l.EnsureLink(ifindex)
	if bounced {
		if bounceErr := afterBounce(); bounceErr != nil && err == nil {
			err = bounceErr
		}
	}
	if err != nil {
		return bounced, err
	}
	if err := l.SetRole(ifindex, k.role); err != nil {
		return bounced, err
	}
	return bounced, nil
}

func (k *kernelDispatch) coverage(ifindex int) error { return k.d.Coverage(ifindex, k.slot, k.program) }

func (k *kernelDispatch) prune(ctx context.Context) error {
	l, err := k.d.Lock(ctx)
	if err != nil {
		return err
	}
	defer l.Unlock()
	_, err = l.PruneDefunct()
	return err
}
