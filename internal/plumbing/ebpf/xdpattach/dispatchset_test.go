// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// fakeDispatch is a dispatchBackend over in-memory state.
type fakeDispatch struct {
	linkedIdx map[int]bool
	ensureErr map[int]error
	// afterAttachErr fails ensure after the attach, as a failed pin does.
	afterAttachErr map[int]error
	coverageErr    map[int]error
	ensured        []int
	prunes         int
}

func newFakeDispatch() *fakeDispatch {
	return &fakeDispatch{
		linkedIdx: map[int]bool{}, ensureErr: map[int]error{}, afterAttachErr: map[int]error{},
		coverageErr: map[int]error{},
	}
}

func (f *fakeDispatch) linked(ifindex int) (bool, error) { return f.linkedIdx[ifindex], nil }

func (f *fakeDispatch) ensure(_ context.Context, ifindex int, guard, afterBounce func() error) (bool, error) {
	if !f.linkedIdx[ifindex] {
		if err := guard(); err != nil {
			return false, err
		}
	}
	if err := f.ensureErr[ifindex]; err != nil {
		return false, err
	}
	f.ensured = append(f.ensured, ifindex)
	if f.linkedIdx[ifindex] {
		return false, nil
	}
	f.linkedIdx[ifindex] = true
	bounceErr := afterBounce()
	if err := f.afterAttachErr[ifindex]; err != nil {
		return true, err
	}
	return true, bounceErr
}

func (f *fakeDispatch) coverage(ifindex int) error {
	if !f.linkedIdx[ifindex] {
		return xdpdispatch.ErrNoLink
	}
	return f.coverageErr[ifindex]
}

func (f *fakeDispatch) prune(context.Context) error {
	f.prunes++
	return nil
}

func TestDispatchSet_PutsTheDispatcherOnEveryInterface(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10), plainLink(testUplink1, 11))
	fake := newFakeDispatch()
	s := &DispatchSet{backend: fake}

	if missing := s.Reconcile(context.Background(), []string{testUplink0, testUplink1}); len(missing) != 0 {
		t.Fatalf("missing = %v, want none", missing)
	}
	if !slices.Equal(fake.ensured, []int{10, 11}) {
		t.Errorf("ensured %v, want [10 11]", fake.ensured)
	}
	if fake.prunes != 1 {
		t.Errorf("pruned %d times, want once per Reconcile", fake.prunes)
	}
}

// TestDispatchSet_ALinkedInterfaceSkipsTheAttachGuards: another datapath
// already put the root there, so nothing bounces and the native-support check
// has nothing to protect.
func TestDispatchSet_ALinkedInterfaceSkipsTheAttachGuards(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10))
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) {
		t.Fatal("native support checked for an interface the root already holds")
		return false, nil
	}
	fake := newFakeDispatch()
	fake.linkedIdx[10] = true
	s := &DispatchSet{backend: fake}

	if missing := s.Reconcile(context.Background(), []string{testUplink0}); len(missing) != 0 {
		t.Errorf("missing = %v, want none", missing)
	}
}

func TestDispatchSet_NoNativeSupportIsMissingAndUntouched(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10))
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) { return false, nil }
	fake := newFakeDispatch()
	s := &DispatchSet{backend: fake}

	if missing := s.Reconcile(context.Background(), []string{testUplink0}); !slices.Equal(missing, []string{testUplink0}) {
		t.Errorf("missing = %v, want [%s]", missing, testUplink0)
	}
	if len(fake.ensured) != 0 || fake.linkedIdx[10] {
		t.Errorf("ensured %v on an interface with no native XDP support", fake.ensured)
	}
}

// TestDispatchSet_AForeignProgramIsMissingUntilItGoes is issue #717's
// coverage case at this layer: an interface another XDP program holds is
// reported, then covered once that program is gone.
func TestDispatchSet_AForeignProgramIsMissingUntilItGoes(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10))
	fake := newFakeDispatch()
	fake.ensureErr[10] = xdpdispatch.ErrForeignProgram
	s := &DispatchSet{backend: fake}

	if missing := s.Reconcile(context.Background(), []string{testUplink0}); !slices.Equal(missing, []string{testUplink0}) {
		t.Fatalf("missing = %v under a foreign program, want [%s]", missing, testUplink0)
	}
	if got := s.Missing(); !slices.Equal(got, []string{testUplink0}) {
		t.Errorf("Missing() = %v, want [%s]", got, testUplink0)
	}

	delete(fake.ensureErr, 10)
	if missing := s.Reconcile(context.Background(), []string{testUplink0}); len(missing) != 0 {
		t.Errorf("missing = %v after the foreign program went, want none", missing)
	}
}

func TestDispatchSet_UncoveredSlotIsMissing(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10))
	fake := newFakeDispatch()
	fake.coverageErr[10] = xdpdispatch.ErrLeaseExpired
	s := &DispatchSet{backend: fake}

	if missing := s.Reconcile(context.Background(), []string{testUplink0}); !slices.Equal(missing, []string{testUplink0}) {
		t.Errorf("missing = %v with the slot's lease expired, want [%s]", missing, testUplink0)
	}
}

// TestDispatchSet_WaitsForABondMemberBeforeTheNext: the first member the root
// is attached to never rejoins its aggregate, so the second is left alone
// rather than bounced too.
func TestDispatchSet_WaitsForABondMemberBeforeTheNext(t *testing.T) {
	first := slaveLink(gateSlave, netlink.BondLinkUp, lacpSyncOnly)
	first.Attrs().Index = 20
	second := slaveLink(gateSlaveSib, netlink.BondLinkUp, lacpCarrying)
	second.Attrs().Index = 21
	newSetHost(t, lacpMaster(), first, second)
	orig := BondReadyTimeout
	BondReadyTimeout = 0
	t.Cleanup(func() { BondReadyTimeout = orig })

	fake := newFakeDispatch()
	s := &DispatchSet{backend: fake}
	missing := s.Reconcile(context.Background(), []string{gateSlave, gateSlaveSib})

	if !slices.Equal(fake.ensured, []int{20}) {
		t.Errorf("ensured %v, want only the first member [20]", fake.ensured)
	}
	if !slices.Equal(missing, []string{gateSlaveSib}) {
		t.Errorf("missing = %v, want the deferred member [%s]", missing, gateSlaveSib)
	}
}

func TestNewDispatchSet_RejectsNil(t *testing.T) {
	if _, err := NewDispatchSet(nil, xdpdispatch.SlotNAT, xdpdispatch.RoleEgress, nil); err == nil {
		t.Error("NewDispatchSet(nil dispatcher) succeeded")
	}
}

// TestDispatchSet_AFailedPinStillWaitsForTheBond: the attach bounced the
// member even though pinning then failed, so the bond wait must still gate
// the next member.
func TestDispatchSet_AFailedPinStillWaitsForTheBond(t *testing.T) {
	first := slaveLink(gateSlave, netlink.BondLinkUp, lacpSyncOnly)
	first.Attrs().Index = 20
	second := slaveLink(gateSlaveSib, netlink.BondLinkUp, lacpCarrying)
	second.Attrs().Index = 21
	newSetHost(t, lacpMaster(), first, second)
	orig := BondReadyTimeout
	BondReadyTimeout = 0
	t.Cleanup(func() { BondReadyTimeout = orig })

	fake := newFakeDispatch()
	fake.afterAttachErr[20] = errors.New("pin link: permission denied")
	s := &DispatchSet{backend: fake}
	missing := s.Reconcile(context.Background(), []string{gateSlave, gateSlaveSib})

	if !slices.Equal(fake.ensured, []int{20}) {
		t.Errorf("ensured %v, want only the first member [20]", fake.ensured)
	}
	if !slices.Equal(missing, []string{gateSlave, gateSlaveSib}) {
		t.Errorf("missing = %v, want both members", missing)
	}
}
