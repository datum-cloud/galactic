// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
)

// Uplink names Set's and OnNetlinkChange's tests drive.
const (
	testUplink0 = "eth0"
	testUplink1 = "eth1"
	testUplink2 = "eth2"
)

// fakeXDPLink is a link.Link that records being closed. The embedded interface
// supplies link.Link's unexported method; nothing but Close is ever called.
type fakeXDPLink struct {
	link.Link
	name   string
	closed bool
}

func (f *fakeXDPLink) Close() error {
	f.closed = true
	return nil
}

// setHost is a fake netlink view and attach step for Set's tests.
type setHost struct {
	links    map[string]netlink.Link
	attached []string
	failFor  map[string]bool
	made     map[string]*fakeXDPLink
}

// newSetHost installs a fake host holding links, every one reporting native
// XDP support, and restores every override when the test ends.
func newSetHost(t *testing.T, links ...netlink.Link) *setHost {
	t.Helper()
	restoreGateVars(t)
	origList, origAttach := linkListFn, attachFn
	t.Cleanup(func() { linkListFn, attachFn = origList, origAttach })

	h := &setHost{links: map[string]netlink.Link{}, failFor: map[string]bool{}, made: map[string]*fakeXDPLink{}}
	for _, l := range links {
		h.links[l.Attrs().Name] = l
	}
	linkByNameFn = func(name string) (netlink.Link, error) {
		if l, ok := h.links[name]; ok {
			return l, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		for _, l := range h.links {
			if l.Attrs().Index == index {
				return l, nil
			}
		}
		return nil, netlink.LinkNotFoundError{}
	}
	linkListFn = func() ([]netlink.Link, error) {
		out := make([]netlink.Link, 0, len(h.links))
		for _, l := range h.links {
			out = append(out, l)
		}
		return out, nil
	}
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) { return true, nil }
	sleepFn = func(time.Duration) {}
	attachFn = func(_ *ebpf.Program, name string) (link.Link, error) {
		if h.failFor[name] {
			return nil, errors.New("attach refused")
		}
		h.attached = append(h.attached, name)
		l := &fakeXDPLink{name: name}
		h.made[name] = l
		return l, nil
	}
	return h
}

func plainLink(name string, index int) netlink.Link {
	return &fakeSlaveLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

// newTestSet builds a Set as startup leaves it, holding a fake link for each
// of names.
func newTestSet(t *testing.T, names ...string) (*Set, []*fakeXDPLink) {
	t.Helper()
	fakes := make([]*fakeXDPLink, len(names))
	links := make([]link.Link, len(names))
	for i, name := range names {
		fakes[i] = &fakeXDPLink{name: name}
		links[i] = fakes[i]
	}
	s, err := NewSet(new(ebpf.Program), names, links)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return s, fakes
}

// TestSet_AttachesUplinkAppearingAfterStartup is issue #647's regression: a
// shard that started with only eth0 resolved must cover eth1 once routing
// resolves it too, without touching eth0.
func TestSet_AttachesUplinkAppearingAfterStartup(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, startup := newTestSet(t, testUplink0)

	if missing := s.Reconcile([]string{testUplink0, testUplink1}); len(missing) != 0 {
		t.Fatalf("Reconcile missing = %v, want none", missing)
	}
	if !slices.Equal(h.attached, []string{testUplink1}) {
		t.Errorf("attached %v after startup, want only [eth1]", h.attached)
	}
	if startup[0].closed {
		t.Error("eth0's startup link was closed; an attached uplink must be left alone")
	}
	if got := s.Attached(); !slices.Equal(got, []string{testUplink0, testUplink1}) {
		t.Errorf("Attached() = %v, want [eth0 eth1]", got)
	}
}

func TestSet_KeepsInterfaceDroppedFromDesiredWhileItExists(t *testing.T) {
	newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, startup := newTestSet(t, testUplink0, testUplink1)

	s.Reconcile([]string{testUplink0})

	if startup[1].closed {
		t.Error("eth1 was detached on a route change; detaching bounces the link and must wait for it to go away")
	}
}

func TestSet_ReleasesInterfaceThatIsGone(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, startup := newTestSet(t, testUplink0, testUplink1)

	delete(h.links, testUplink1)
	s.Reconcile([]string{testUplink0})

	if !startup[1].closed {
		t.Error("eth1's link was kept after the interface disappeared")
	}
	if got := s.Attached(); !slices.Equal(got, []string{testUplink0}) {
		t.Errorf("Attached() = %v, want [eth0]", got)
	}
}

func TestSet_ReattachesMemberReplacedUnderSameName(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink1, 3))
	s, startup := newTestSet(t, testUplink1)

	h.links[testUplink1] = plainLink(testUplink1, 9)
	if missing := s.Reconcile([]string{testUplink1}); len(missing) != 0 {
		t.Fatalf("Reconcile missing = %v, want none", missing)
	}

	if !startup[0].closed {
		t.Error("the link to the replaced device was not released")
	}
	if !slices.Equal(h.attached, []string{testUplink1}) {
		t.Errorf("attached %v, want the replacement eth1 attached", h.attached)
	}
}

func TestSet_FailureLeavesOthersAttachedAndReportsMissing(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3), plainLink(testUplink2, 4))
	s, startup := newTestSet(t, testUplink0)
	h.failFor[testUplink1] = true

	missing := s.Reconcile([]string{testUplink0, testUplink1, testUplink2})

	if !slices.Equal(missing, []string{testUplink1}) {
		t.Errorf("Reconcile missing = %v, want [eth1]", missing)
	}
	if !slices.Equal(s.Missing(), []string{testUplink1}) {
		t.Errorf("Missing() = %v, want [eth1]", s.Missing())
	}
	if startup[0].closed {
		t.Error("eth0 was detached because eth1 failed")
	}
	if !slices.Contains(h.attached, testUplink2) {
		t.Error("eth2 was not attached because eth1 failed")
	}

	delete(h.failFor, testUplink1)
	if missing := s.Reconcile([]string{testUplink0, testUplink1, testUplink2}); len(missing) != 0 {
		t.Errorf("retry Reconcile missing = %v, want none", missing)
	}
}

func TestSet_RefusesInterfaceWithoutNativeXDP(t *testing.T) {
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, _ := newTestSet(t, testUplink0)
	edgepreflight.InterfaceXDPFn = func(name string) (bool, error) { return name != testUplink1, nil }

	if missing := s.Reconcile([]string{testUplink0, testUplink1}); !slices.Equal(missing, []string{testUplink1}) {
		t.Errorf("Reconcile missing = %v, want [eth1]", missing)
	}
	if len(h.attached) != 0 {
		t.Errorf("attached %v to an interface without native XDP", h.attached)
	}
}

func TestSet_DefersBondMemberWhoseBounceWouldIsolateTheBond(t *testing.T) {
	// The new member is the only one carrying traffic; its sibling is down.
	h := newSetHost(t, lacpMaster(),
		slaveLink(gateSlave, netlink.BondLinkUp, lacpCarrying),
		slaveLink(gateSlaveSib, netlink.BondLinkDown, 0),
	)
	s, _ := newTestSet(t)

	if missing := s.Reconcile([]string{gateSlave}); !slices.Equal(missing, []string{gateSlave}) {
		t.Errorf("Reconcile missing = %v, want [%s]", missing, gateSlave)
	}
	if len(h.attached) != 0 {
		t.Errorf("attached %v, which would have taken the bond down", h.attached)
	}

	// Once the sibling carries traffic again, the member is attached.
	h.links[gateSlaveSib] = slaveLink(gateSlaveSib, netlink.BondLinkUp, lacpCarrying)
	if missing := s.Reconcile([]string{gateSlave}); len(missing) != 0 {
		t.Errorf("Reconcile missing = %v, want none once a sibling carries traffic", missing)
	}
}

func TestSet_AttachesNewlyEnslavedMemberNotYetCarryingTraffic(t *testing.T) {
	h := newSetHost(t, lacpMaster(),
		slaveLink(gateSlave, netlink.BondLinkDown, lacpSyncOnly),
		slaveLink(gateSlaveSib, netlink.BondLinkDown, 0),
	)
	s, _ := newTestSet(t)

	// Comes up once attached: the bond takes it in on the first poll.
	attach := attachFn
	attachFn = func(p *ebpf.Program, name string) (link.Link, error) {
		h.links[name] = slaveLink(name, netlink.BondLinkUp, lacpCarrying)
		return attach(p, name)
	}

	if missing := s.Reconcile([]string{gateSlave}); len(missing) != 0 {
		t.Errorf("Reconcile missing = %v, want none: a member not yet carrying traffic costs nothing to bounce", missing)
	}
}

func TestSet_WaitsForEachMemberBeforeTheNext(t *testing.T) {
	h := newSetHost(t, lacpMaster(),
		slaveLink(gateSlave, netlink.BondLinkUp, lacpCarrying),
		slaveLink(gateSlaveSib, netlink.BondLinkUp, lacpCarrying),
	)
	s, _ := newTestSet(t)

	// The first member never rejoins after its attach.
	attach := attachFn
	attachFn = func(p *ebpf.Program, name string) (link.Link, error) {
		h.links[name] = slaveLink(name, netlink.BondLinkUp, lacpSyncOnly)
		return attach(p, name)
	}
	orig := BondReadyTimeout
	BondReadyTimeout = 0
	t.Cleanup(func() { BondReadyTimeout = orig })

	missing := s.Reconcile([]string{gateSlave, gateSlaveSib})

	if !slices.Equal(h.attached, []string{gateSlave}) {
		t.Errorf("attached %v, want only %s while it has not rejoined", h.attached, gateSlave)
	}
	if !slices.Equal(missing, []string{gateSlaveSib}) {
		t.Errorf("Reconcile missing = %v, want [%s]", missing, gateSlaveSib)
	}
}

func TestNewSet_Validates(t *testing.T) {
	if _, err := NewSet(nil, nil, nil); err == nil {
		t.Error("NewSet(nil program): want an error")
	}
	if _, err := NewSet(new(ebpf.Program), []string{testUplink0}, nil); err == nil {
		t.Error("NewSet with mismatched names and links: want an error")
	}
}
