// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// TestAttachSequentially_GenericModeSkipsTheNativeCheck covers a bnxt_en host:
// generic mode runs on any interface, so a driver without native support is
// no reason to refuse it.
func TestAttachSequentially_GenericModeSkipsTheNativeCheck(t *testing.T) {
	restoreGateVars(t)
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) {
		t.Fatal("native support checked in generic mode")
		return false, nil
	}
	linkByNameFn = func(name string) (netlink.Link, error) { return plainLink(name, 2), nil }

	var attached []string
	if _, err := attachSequentially([]string{gateSlaveNoXDP}, xdpmode.Generic, func(name string) (link.Link, error) {
		attached = append(attached, name)
		return nil, nil
	}); err != nil {
		t.Fatalf("attachSequentially in generic mode: %v", err)
	}
	if !slices.Equal(attached, []string{gateSlaveNoXDP}) {
		t.Errorf("attached %v, want [%s]", attached, gateSlaveNoXDP)
	}
}

// TestSet_AttachesInItsMode covers a Set in generic mode: every later attach
// asks for generic mode, and no native-support check runs.
func TestSet_AttachesInItsMode(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) { return false, nil }
	s, err := NewSet(new(ebpf.Program), nil, nil, xdpmode.Generic)
	if err != nil {
		t.Fatal(err)
	}

	if missing := s.Reconcile([]string{testUplink0, testUplink1}); len(missing) != 0 {
		t.Fatalf("Reconcile missing = %v, want none", missing)
	}
	for _, name := range []string{testUplink0, testUplink1} {
		if got := h.modesAsked[name]; got != xdpmode.Generic {
			t.Errorf("%s attached in %s mode, want generic", name, got)
		}
	}
	if s.Mode() != xdpmode.Generic {
		t.Errorf("Mode() = %s, want generic", s.Mode())
	}
}

// TestSet_ReportsAnInterfaceHeldInTheWrongMode covers coverage read back from
// the kernel: an interface whose hook reports the other mode is neither
// attached nor covered, though the Set holds a link for it.
func TestSet_ReportsAnInterfaceHeldInTheWrongMode(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, _ := newTestSet(t, testUplink0, testUplink1)
	h.modes[testUplink0] = xdpmode.Generic

	missing := s.Reconcile([]string{testUplink0, testUplink1})
	if !slices.Equal(missing, []string{testUplink0}) {
		t.Errorf("Reconcile missing = %v, want [%s]", missing, testUplink0)
	}
	if got := s.Attached(); !slices.Equal(got, []string{testUplink1}) {
		t.Errorf("Attached() = %v, want [%s]", got, testUplink1)
	}
	if len(h.attached) != 0 {
		t.Errorf("attached %v, want nothing: a held link is never replaced by a Set", h.attached)
	}
}

// TestDispatchSet_GenericModeSkipsTheNativeCheck covers the dispatcher's
// pre-attach guard in generic mode: a driver without native support is
// attached, and the bond guard still runs.
func TestDispatchSet_GenericModeSkipsTheNativeCheck(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 10))
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) {
		t.Fatal("native support checked in generic mode")
		return false, nil
	}
	fake := newFakeDispatch()
	s := &DispatchSet{backend: fake, mode: xdpmode.Generic}

	if missing := s.Reconcile(context.Background(), []string{testUplink0}); len(missing) != 0 {
		t.Errorf("missing = %v, want none", missing)
	}
	if !slices.Equal(fake.ensured, []int{10}) {
		t.Errorf("ensured %v, want [10]", fake.ensured)
	}
}

// TestDispatchSet_MigrationKeepsTheBondGuard covers a root linked in the other
// mode: linked reports false for it, so the bond guard runs before the
// migration bounces the member, and a member whose bounce would isolate its
// bond is left for later.
func TestDispatchSet_MigrationKeepsTheBondGuard(t *testing.T) {
	newSetHost(t, lacpMaster(),
		slaveLink(gateSlave, netlink.BondLinkUp, lacpCarrying),
		slaveLink(gateSlaveSib, netlink.BondLinkDown, lacpSyncOnly),
	)
	sleepFn = func(time.Duration) {}
	fake := newFakeDispatch()
	s := &DispatchSet{backend: fake, mode: xdpmode.Generic}

	missing := s.Reconcile(context.Background(), []string{gateSlave})
	if !slices.Equal(missing, []string{gateSlave}) {
		t.Errorf("missing = %v, want [%s]: migrating the only member carrying traffic would take the bond down",
			missing, gateSlave)
	}
	if len(fake.ensured) != 0 {
		t.Errorf("ensured %v, want nothing", fake.ensured)
	}
}
