// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// TestRegisterHostLink registers a link under its VRF's existing uSID entry,
// with a traffic policy row that keeps its token across registrations,
// refuses a VRF with none and a node that cannot enforce the policy it has
// on, and removes only the link's own rows.
func TestRegisterHostLink(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close(); _ = netns.Set(orig) }()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-attachreg-hostlink-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	const table, otherTable = 4001, 4002
	links := map[string]int{}
	for _, name := range []string{"edge-h", "peer-h"} {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		links[name] = l.Attrs().Index
	}

	addr := netip.MustParseAddr("fd00:10::7")
	err = RegisterHostLink(pinDir, table, uint32(links["edge-h"]), "edge-h", addr)
	if !errors.Is(err, ErrVRFNotRegistered) {
		t.Fatalf("unregistered VRF = %v", err)
	}
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	const block = 0xfc0000010000
	for _, e := range []struct {
		arg   uint16
		table uint32
	}{{0x20, table}, {0x11, table}, {0x05, otherTable}} {
		if err := registry.VRF.Register(block, e.arg, e.table, usidmap.EgressKindVeth); err != nil {
			t.Fatal(err)
		}
	}
	ifindexes, ifCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ifCloser.Close() }()
	if err := ifindexes.Register(uint32(links["peer-h"]), block, 0x05); err != nil {
		t.Fatal(err)
	}

	edge := uint32(links["edge-h"])
	maps := testHostLinkPolicy(t, pinDir, table, edge, addr)
	e, ok, err := ifindexes.Get(uint32(links["edge-h"]))
	if err != nil || !ok {
		t.Fatalf("edge-h row = %v, %v", ok, err)
	}
	if e.Block != block || e.Argument != 0x11 {
		t.Errorf("edge-h registered under block %#x argument %#x, want the VRF's lowest argument 0x11", e.Block, e.Argument)
	}

	if err := UnregisterHostLink(pinDir, uint32(links["edge-h"])); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ifindexes.Get(uint32(links["edge-h"])); err != nil || ok {
		t.Errorf("edge-h row after unregister = %v, %v", ok, err)
	}
	var row prog.UsidTpIfaceValue
	if err := maps.Interfaces.Lookup(edge, &row); err == nil {
		t.Errorf("edge-h policy row after unregister = %+v", row)
	}
	if _, ok, err := ifindexes.Get(uint32(links["peer-h"])); err != nil || !ok {
		t.Errorf("another link's row after unregister = %v, %v", ok, err)
	}
	if err := UnregisterHostLink(pinDir, uint32(links["edge-h"])); err != nil {
		t.Errorf("repeated unregister: %v", err)
	}
	if err := UnregisterHostLink(pinDir+"-absent", uint32(links["edge-h"])); err != nil {
		t.Errorf("unregister with no pinned maps: %v", err)
	}
}

// testHostLinkPolicy registers edge-h, ifindex edge, twice and checks its
// policy row keeps one token and records addr, then that a node enforcing
// policy refuses it unless the kernel passed the preflight. It returns the
// policy maps.
func testHostLinkPolicy(t *testing.T, pinDir string, table, edge uint32, addr netip.Addr) *tpmap.Maps {
	t.Helper()
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maps.Close)
	policyRow := func() (prog.UsidTpIfaceValue, bool) {
		t.Helper()
		var row prog.UsidTpIfaceValue
		if err := maps.Interfaces.Lookup(edge, &row); err != nil {
			return row, false
		}
		return row, true
	}
	var token uint64
	for i := range 2 {
		if err := RegisterHostLink(pinDir, table, edge, "edge-h", addr); err != nil {
			t.Fatal(err)
		}
		row, ok := policyRow()
		if !ok || row.Kind != tpmap.KindTenant || row.PolicyToken == 0 {
			t.Fatalf("registration %d: policy row = %+v, %v; want a tenant row with a token", i, row, ok)
		}
		if i == 1 && row.PolicyToken != token {
			t.Errorf("a repeated registration changed the policy token %#x to %#x", token, row.PolicyToken)
		}
		token = row.PolicyToken
	}
	var key prog.UsidTpIfaceAddrKey
	var marked uint8
	key.Ifindex, key.Family, key.Addr = edge, 6, addr.As16()
	if err := maps.InterfaceAddrs.Lookup(key, &marked); err != nil {
		t.Errorf("the link's address is not recorded for its link operations: %v", err)
	}

	if err := maps.SetState(tpmap.State{Mode: tpmap.ModeEnforce, Capable: false}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterHostLink(pinDir, table, edge, "edge-h", addr); !errors.Is(err, ErrNoEnforcement) {
		t.Errorf("registration on a node that enforces but failed the preflight = %v, want ErrNoEnforcement", err)
	}
	if err := maps.SetState(tpmap.State{Mode: tpmap.ModeEnforce, Capable: true}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterHostLink(pinDir, table, edge, "edge-h", addr); err != nil {
		t.Errorf("registration on an enforcing node: %v", err)
	}
	return maps
}
