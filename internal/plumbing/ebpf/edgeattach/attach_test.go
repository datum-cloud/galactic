// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/bond"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN) to load/attach BPF programs " +
			"and create a test network namespace; re-run via sudo")
	}
}

// TestLoad_PreflightBlocksLoad mirrors internal/plumbing/ebpf/attach's
// identical test.
func TestLoad_PreflightBlocksLoad(t *testing.T) {
	origPreflight := preflightCheckFn
	t.Cleanup(func() { preflightCheckFn = origPreflight })

	wantErr := errors.New("simulated missing kernel capability")
	preflightCheckFn = func() error { return wantErr }

	pinDir := filepath.Join(t.TempDir(), "does-not-exist", "galactic-edge")

	objs, err := Load(pinDir)
	if err == nil {
		t.Fatal("Load() error = nil, want a preflight failure")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Load() error = %v, want it to wrap the preflight error %v", err, wantErr)
	}
	if objs != nil {
		t.Errorf("Load() objs = %v, want nil on preflight failure", objs)
	}
	if _, statErr := os.Stat(pinDir); statErr == nil {
		t.Error("Load() created the pin directory despite failing preflight")
	}
}

// TestAttach_NilProgramIsError covers Attach's defensive nil-program
// guard directly, without needing root.
func TestAttach_NilProgramIsError(t *testing.T) {
	if _, err := Attach(nil, []string{"eth0"}); err == nil {
		t.Error("Attach(nil program, ...) error = nil, want an error")
	}
}

// TestAttach_NoInterfacesIsError covers Attach's defensive empty-slice
// guard directly, without needing root or a real program.
func TestAttach_NoInterfacesIsError(t *testing.T) {
	if _, err := Attach(&ebpf.Program{}, nil); err == nil {
		t.Error("Attach(program, nil) error = nil, want an error")
	}
}

// fakeLink is a minimal netlink.Link implementation for tests -- mirrors
// internal/plumbing/ebpf/attach's identical test fixture.
type fakeLink struct {
	attrs    netlink.LinkAttrs
	linkType string
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string {
	if f.linkType == "" {
		return "fake"
	}
	return f.linkType
}

// TestResolveTargets exercises ResolveTargets against a faked netlink view
// (linkByNameFn/linkListFn), covering the reason it exists: unlike
// internal/plumbing/ebpf/attach's expandBondSlaves, which includes a bond
// master alongside its slaves, ResolveTargets must exclude the master
// entirely -- native-mode XDP cannot attach to it at all.
func TestResolveTargets(t *testing.T) {
	origLinkByNameFn, origLinkListFn := linkByNameFn, linkListFn
	t.Cleanup(func() { linkByNameFn, linkListFn = origLinkByNameFn, origLinkListFn })

	const (
		nonBondName = "eth0"
		bondName    = "bond0"
		bondIndex   = 10
		slave1      = "enp3s0f1"
		slave2      = "eno2"
	)

	links := map[string]netlink.Link{
		nonBondName: &fakeLink{attrs: netlink.LinkAttrs{Name: nonBondName, Index: 2}},
		bondName:    &fakeLink{attrs: netlink.LinkAttrs{Name: bondName, Index: bondIndex}, linkType: bond.LinkType},
	}
	allLinks := []netlink.Link{
		links[nonBondName],
		links[bondName],
		&fakeLink{attrs: netlink.LinkAttrs{Name: slave1, Index: 11, MasterIndex: bondIndex}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: slave2, Index: 12, MasterIndex: bondIndex}},
		// A link enslaved to some other, unrelated master must never leak in.
		&fakeLink{attrs: netlink.LinkAttrs{Name: "unrelated-slave", Index: 13, MasterIndex: 999}},
	}

	linkByNameFn = func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		return nil, errFixtureNotFound
	}
	linkListFn = func() ([]netlink.Link, error) { return allLinks, nil }

	t.Run("NonBondPassthrough", func(t *testing.T) {
		got, err := ResolveTargets(nonBondName)
		if err != nil {
			t.Fatalf("ResolveTargets() error = %v", err)
		}
		if len(got) != 1 || got[0] != nonBondName {
			t.Errorf("ResolveTargets() = %v, want [%s]", got, nonBondName)
		}
	})

	t.Run("BondExpandsToSlavesOnly", func(t *testing.T) {
		got, err := ResolveTargets(bondName)
		if err != nil {
			t.Fatalf("ResolveTargets() error = %v", err)
		}
		want := []string{slave1, slave2}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("ResolveTargets() = %v, want %v (slaves only, master excluded)", got, want)
		}
		for _, name := range got {
			if name == bondName {
				t.Errorf("ResolveTargets() = %v, must never include the bond master itself", got)
			}
		}
	})

	t.Run("UnresolvableInterfaceIsError", func(t *testing.T) {
		// Unlike internal/plumbing/ebpf/attach's expandBondSlaves (whose
		// override path never requires its named interfaces to exist yet
		// at config-generation time), the gateway's publicInterface is
		// expected to be a real interface at process startup -- so an
		// unresolvable name is fatal here, matching Attach's own
		// pre-existing behavior for a nonexistent interface.
		if _, err := ResolveTargets("does-not-exist"); err == nil {
			t.Fatal("ResolveTargets() error = nil, want the underlying link-lookup error surfaced")
		}
	})

	t.Run("BondWithNoSlavesIsError", func(t *testing.T) {
		emptyBondName := "bond1"
		links[emptyBondName] = &fakeLink{
			attrs: netlink.LinkAttrs{Name: emptyBondName, Index: 20}, linkType: bond.LinkType,
		}
		if _, err := ResolveTargets(emptyBondName); err == nil {
			t.Fatal("ResolveTargets() error = nil, want an error for a bond master with no slaves")
		}
	})

	t.Run("LinkListErrorPropagated", func(t *testing.T) {
		origLinkListFn := linkListFn
		linkListFn = func() ([]netlink.Link, error) { return nil, errFixtureNotFound }
		defer func() { linkListFn = origLinkListFn }()

		if _, err := ResolveTargets(bondName); err == nil {
			t.Fatal("ResolveTargets() error = nil, want the underlying link-list error surfaced")
		}
	})
}

var errFixtureNotFound = errors.New("edgeattach: fixture link not found")

// TestLoadAttach_SurvivesRestartWithMapsIntact is the real, root-gated
// exit criterion: program load/attach survives a simulated process
// restart with pinned maps intact. Unlike a TC-BPF filter (which persists
// in the kernel independent of any process), an unpinned XDP bpf_link
// detaches when its owning process's file descriptor closes -- so
// simulating "restart" here means explicitly Close()ing the first
// attach's link before re-attaching, not just calling Attach twice in a
// row (see doc.go).
//
// Uses a veth pair, not a dummy interface: dummy's driver, like geneve's
// (this design's own earlier rejected finding), does not implement
// ndo_bpf, so it cannot accept a native-mode XDP attach at all --
// confirmed during this design's Phase 0 spike that veth genuinely does.
func TestLoadAttach_SurvivesRestartWithMapsIntact(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-edge-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const ifaceName = "edgetest0"
	const peerName = "edgetest1"

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}, PeerName: peerName}
		if err := handle.LinkAdd(veth); err != nil {
			return fmt.Errorf("add veth pair: %w", err)
		}
		link, err := handle.LinkByName(ifaceName)
		if err != nil {
			return err
		}
		return handle.LinkSetUp(link)
	})
	if err != nil {
		t.Fatalf("setup veth interface: %v", err)
	}

	vipKey := edgeprog.EdgedsrVipKey{Proto: 6, Port: 80}
	vipValue := edgeprog.EdgedsrVipValue{BackendCount: 1, Generation: 42}

	// --- pre-restart: first load, attach, and populate a map entry. ---
	var firstLink interface{ Close() error }
	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		links, err := Attach(objs.EdgeLb, []string{ifaceName})
		if err != nil {
			return fmt.Errorf("attach: %w", err)
		}
		if len(links) != 1 {
			return fmt.Errorf("attach: got %d links, want 1", len(links))
		}
		firstLink = links[0]

		if err := objs.VipTable.Put(vipKey, vipValue); err != nil {
			return fmt.Errorf("populate vip_table: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("pre-restart load/attach/populate: %v", err)
	}

	// Simulate the old process exiting: close its XDP link so the
	// interface has no attached program, exactly like a real process
	// restart would leave it.
	if err := firstLink.Close(); err != nil {
		t.Fatalf("close pre-restart link: %v", err)
	}

	// --- simulate a container restart: fresh Load+Attach against the
	// same pinDir/interface, as a brand new process would do. ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("reload after restart: %w", err)
		}
		defer func() { _ = objs.Close() }()

		links, err := Attach(objs.EdgeLb, []string{ifaceName})
		if err != nil {
			return fmt.Errorf("re-attach after restart: %w", err)
		}
		defer func() { _ = links[0].Close() }()

		var got edgeprog.EdgedsrVipValue
		if err := objs.VipTable.Lookup(vipKey, &got); err != nil {
			return fmt.Errorf("lookup vip_table entry after restart: %w", err)
		}
		if got.BackendCount != 1 || got.Generation != 42 {
			return fmt.Errorf("vip_table entry after restart = %+v, want BackendCount=1 Generation=42", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-restart verification: %v", err)
	}
}

// TestAttach_MultipleInterfacesRollsBackOnPartialFailure exercises Attach's
// multi-interface path end-to-end against real veth interfaces: attaching
// to two interfaces returns two links, and if a later interface in the
// list fails to attach, every link already attached earlier in that same
// call is rolled back (Closed) rather than left dangling -- verified here
// by re-attaching to the first interface afterward, which only succeeds if
// its earlier attach was genuinely undone (a still-attached native XDP
// program on that interface would make a second attach fail).
func TestAttach_MultipleInterfacesRollsBackOnPartialFailure(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-edge-test-multi-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const (
		iface0Name = "edgetestb0"
		peer0Name  = "edgetestb1"
		iface1Name = "edgetestb2"
		peer1Name  = "edgetestb3"
	)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		for _, v := range []*netlink.Veth{
			{LinkAttrs: netlink.LinkAttrs{Name: iface0Name}, PeerName: peer0Name},
			{LinkAttrs: netlink.LinkAttrs{Name: iface1Name}, PeerName: peer1Name},
		} {
			if err := handle.LinkAdd(v); err != nil {
				return fmt.Errorf("add veth pair %q/%q: %w", v.Name, v.PeerName, err)
			}
			link, err := handle.LinkByName(v.Name)
			if err != nil {
				return err
			}
			if err := handle.LinkSetUp(link); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup veth interfaces: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		// --- attach to both real interfaces: two links back. ---
		links, err := Attach(objs.EdgeLb, []string{iface0Name, iface1Name})
		if err != nil {
			return fmt.Errorf("attach to both interfaces: %w", err)
		}
		if len(links) != 2 {
			return fmt.Errorf("attach: got %d links, want 2", len(links))
		}
		for _, l := range links {
			_ = l.Close()
		}

		// --- attach again, this time with a second name that can never
		// attach (it doesn't exist): the first interface's attach must be
		// rolled back, not left dangling. ---
		if _, err := Attach(objs.EdgeLb, []string{iface0Name, "does-not-exist"}); err == nil {
			return errors.New("Attach() with an unresolvable second interface error = nil, want an error")
		}

		// If the rollback above genuinely closed iface0Name's link, a
		// fresh solo attach to it succeeds; if it leaked, this fails with
		// the kernel refusing a second native XDP program on the same
		// interface.
		links, err = Attach(objs.EdgeLb, []string{iface0Name})
		if err != nil {
			return fmt.Errorf(
				"re-attach to %q after a rolled-back partial failure: %w "+
					"(the earlier partial attach was likely not rolled back)", iface0Name, err)
		}
		defer func() { _ = links[0].Close() }()
		return nil
	})
	if err != nil {
		t.Fatalf("multi-interface attach/rollback: %v", err)
	}
}

// TestResolveTargetsAndAttach_RealBondDevice exercises ResolveTargets and
// Attach against a genuine Linux bonding master (real netlink IFLA_MASTER
// enslavement, not TestResolveTargets' faked netlink view), end to end:
// resolving the bond to its slaves and attaching the real XDP program to
// each one.
//
// Deliberately does not also assert that attaching directly to the bond
// master fails: on this test's kernel, with veth slaves (which do support
// native XDP themselves), it does not -- some kernels' bonding driver does
// implement ndo_bpf by forwarding the attach to every slave, which only
// fails if a slave's own driver lacks native XDP support (this is believed
// to be the actual failure mode on proxima-evices: 802.3ad over an
// igb/tg3 pair, and tg3 in particular is commonly cited as lacking native
// XDP support; not independently confirmed against that node's kernel).
// Whether master-attach fails outright or succeeds-but-silently-relies-on
// slave support is kernel/driver dependent either way, so asserting one
// direction here would make this test flaky across kernels rather than
// meaningful -- resolving to (and attaching only to) the slaves directly
// is correct regardless of which case a given kernel falls into.
func TestResolveTargetsAndAttach_RealBondDevice(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-edge-test-bond-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const (
		bondName = "bond0"
		slave0   = "edgebond0"
		slave1   = "edgebond1"
	)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		bondLink := netlink.NewLinkBond(netlink.LinkAttrs{Name: bondName})
		if err := netlink.LinkAdd(bondLink); err != nil {
			return fmt.Errorf("add bond master: %w", err)
		}

		for i, name := range []string{slave0, slave1} {
			veth := &netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: name},
				PeerName:  fmt.Sprintf("%s-peer%d", bondName, i),
			}
			if err := netlink.LinkAdd(veth); err != nil {
				return fmt.Errorf("add veth %q: %w", name, err)
			}
			slave, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetMaster(slave, bondLink); err != nil {
				return fmt.Errorf("enslave %q to %q: %w", name, bondName, err)
			}
			if err := netlink.LinkSetUp(slave); err != nil {
				return err
			}
		}
		return netlink.LinkSetUp(bondLink)
	})
	if err != nil {
		t.Fatalf("setup bond0 with two real slaves: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		got, err := ResolveTargets(bondName)
		if err != nil {
			return fmt.Errorf("ResolveTargets(%q): %w", bondName, err)
		}
		sort.Strings(got)
		want := []string{slave0, slave1}
		if !slices.Equal(got, want) {
			return fmt.Errorf("ResolveTargets(%q) = %v, want %v", bondName, got, want)
		}

		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		// Attaching to the resolved slaves is exactly what this design
		// exists to make work.
		links, err := Attach(objs.EdgeLb, got)
		if err != nil {
			return fmt.Errorf("attach to bond slaves %v: %w", got, err)
		}
		for _, l := range links {
			_ = l.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("resolve/attach against a real bond device: %v", err)
	}
}
