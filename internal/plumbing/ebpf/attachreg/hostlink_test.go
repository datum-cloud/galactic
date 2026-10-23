// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// TestRegisterHostLink registers a link under its VRF's existing uSID entry,
// refuses a VRF with none, and removes only the link's own rows.
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

	if err := RegisterHostLink(pinDir, table, uint32(links["edge-h"]), "edge-h"); !errors.Is(err, ErrVRFNotRegistered) {
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

	for range 2 {
		if err := RegisterHostLink(pinDir, table, uint32(links["edge-h"]), "edge-h"); err != nil {
			t.Fatal(err)
		}
	}
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
