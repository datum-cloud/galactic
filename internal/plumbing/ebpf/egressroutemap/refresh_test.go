// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"net"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// answer is one stubbed resolveLinkAndL2 result.
type answer struct {
	link int
	dmac net.HardwareAddr
	smac net.HardwareAddr
	err  error
}

// resolverFor replaces resolveLinkAndL2Fn with one that answers per SID, so a
// test can move one entry's next hop and leave another's alone. A SID with no
// stubbed answer fails, which is what makes "this should never have been
// resolved at all" an assertable outcome.
func resolverFor(t *testing.T, answers map[string]answer) {
	t.Helper()
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		a, ok := answers[sid.String()]
		if !ok {
			return 0, nil, nil, errors.New("no answer stubbed for " + sid.String())
		}
		return a.link, a.dmac, a.smac, a.err
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })
}

// lookupRaw reads the whole stored value for key, unlike the exported Lookup,
// which returns only the SID -- these tests are about the resolved link and L2
// addresses stored beside it.
func lookupRaw(tbl *EgressRouteTable, key prog.UsidEgressRouteKey) (prog.UsidEgressRouteValue, error) {
	var value prog.UsidEgressRouteValue
	if err := tbl.table.Lookup(key, &value); err != nil {
		return prog.UsidEgressRouteValue{}, err
	}
	return value, nil
}

// TestRefreshRewritesAnEntryWhoseNextHopMoved is the regression test for #543:
// an egress route resolved before the fabric advertised its SID points out the
// management interface, and only a re-resolution moves it back onto the uplink.
func TestRefreshRewritesAnEntryWhoseNextHopMoved(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")

	// Written while the SID resolved out the wrong link, as a pre-convergence
	// CNI ADD would.
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	const uplinkIndex = 1060
	uplinkDmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x07, 0x6E, 0x0B}
	uplinkSmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x46, 0x3D, 0x35}
	resolverFor(t, map[string]answer{
		sid.String(): {link: uplinkIndex, dmac: uplinkDmac, smac: uplinkSmac},
	})

	result, err := tbl.Refresh(nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 1 {
		t.Errorf("Refresh() refreshed %d entries, want 1 (result: %+v)", result.Refreshed, result)
	}

	key, err := buildKey(1, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if value.LinkIfindex != uplinkIndex {
		t.Errorf("after Refresh, link_ifindex = %d, want %d", value.LinkIfindex, uplinkIndex)
	}
	if got := net.HardwareAddr(value.Dmac[:]).String(); got != uplinkDmac.String() {
		t.Errorf("after Refresh, dmac = %s, want %s", got, uplinkDmac)
	}
	if got := net.HardwareAddr(value.Smac[:]).String(); got != uplinkSmac.String() {
		t.Errorf("after Refresh, smac = %s, want %s", got, uplinkSmac)
	}
	if got := net.IP(value.Sid[:]); !got.Equal(sid) {
		t.Errorf("after Refresh, sid = %s, want it left alone at %s", got, sid)
	}
}

// TestRefreshLeavesAnUnresolvableEntryInPlace: a SID that does not resolve this
// time round is not evidence the route is wrong. Zeroing or dropping the entry
// would turn a stale next hop into no next hop at all.
func TestRefreshLeavesAnUnresolvableEntryInPlace(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	resolverFor(t, map[string]answer{
		sid.String(): {err: errors.New("no route over an SRv6 uplink")},
	})

	result, err := tbl.Refresh(nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success even with an unresolvable entry", err)
	}
	if result.Unresolved != 1 || result.Refreshed != 0 {
		t.Errorf("Refresh() = %+v, want 1 unresolved and 0 refreshed", result)
	}

	key, err := buildKey(1, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if value.LinkIfindex != fakeLinkIndex {
		t.Errorf("link_ifindex = %d, want the original %d left untouched", value.LinkIfindex, fakeLinkIndex)
	}
	if got := net.IP(value.Sid[:]); !got.Equal(sid) {
		t.Errorf("sid = %s, want the original %s left untouched", got, sid)
	}
}

// TestRefreshSkipsPassThroughEntries: a pass-through carries no SID and is
// never encapsulated toward, so resolving one would fail on an all-zero address
// and count a phantom failure every sweep.
func TestRefreshSkipsPassThroughEntries(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	local := mustCIDR(t, "fd20:10:ff01::/96")
	if err := tbl.RegisterPassThrough(1, local); err != nil {
		t.Fatalf("RegisterPassThrough = %v, want success", err)
	}

	resolverFor(t, map[string]answer{}) // any resolution attempt fails

	result, err := tbl.Refresh(nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Scanned != 1 {
		t.Errorf("Refresh() scanned %d, want 1", result.Scanned)
	}
	if result.Refreshed != 0 || result.Unresolved != 0 {
		t.Errorf("Refresh() = %+v, want a pass-through neither refreshed nor counted unresolved", result)
	}
}

// TestRefreshLeavesAnUnchangedEntryAlone keeps the sweep from rewriting every
// entry on a converged node twice a minute.
func TestRefreshLeavesAnUnchangedEntryAlone(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	// Same answer the entry was written with.
	resolverFor(t, map[string]answer{
		sid.String(): {link: fakeLinkIndex, dmac: fakeDmac, smac: fakeSmac},
	})

	result, err := tbl.Refresh(nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 0 {
		t.Errorf("Refresh() refreshed %d entries, want 0 for an unchanged next hop", result.Refreshed)
	}
}
