// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN) to load/attach BPF programs " +
			"and create a test network namespace; re-run via sudo")
	}
}

// TestAttach_NilProgramIsError covers Attach's defensive nil-program
// guard directly, without needing root.
func TestAttach_NilProgramIsError(t *testing.T) {
	if _, err := Attach(nil, []string{"eth0"}); err == nil {
		t.Error("Attach(nil program, ...) error = nil, want an error")
	}
}

// TestAttach_EmptyInterfaceListIsError covers the other guard. An empty list
// must not read as "attach nothing and carry on": a shard with no attachment
// claims no packet on any uplink, and every packet crossing the node leaves
// untranslated and uncounted -- the silent failure #545 is about, node-wide.
func TestAttach_EmptyInterfaceListIsError(t *testing.T) {
	for _, names := range [][]string{nil, {}} {
		if _, err := Attach(nil, names); err == nil {
			t.Errorf("Attach(_, %v) error = nil, want an error", names)
		}
	}
}

// TestLoadAttach_SurvivesRestartWithMapsIntact is the real, root-gated
// exit criterion: program load/attach survives a simulated process
// restart with pinned maps intact. Unlike a TC-BPF filter (which persists
// in the kernel independent of any process), an unpinned XDP bpf_link
// detaches when its owning process's file descriptor closes -- so
// simulating "restart" here means explicitly Close()ing the first
// attach's link before re-attaching, not just calling Attach twice in a
// row (see doc.go).
//
// Uses a veth pair, not a dummy interface: dummy's driver, like geneve's,
// does not implement ndo_bpf, so it cannot accept a native-mode XDP attach
// at all -- same finding internal/plumbing/ebpf/edgeattach's identical
// test documents.
func TestLoadAttach_SurvivesRestartWithMapsIntact(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-nat-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const ifaceName = "nat66test0"
	const peerName = "nat66test1"

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

	cfg := natprog.NatShardConfig{
		ShardSid:      netip.MustParseAddr("fc00:1:2::1").As16(),
		ShardPubAddr6: netip.MustParseAddr("2001:db8:9999::1").As16(),
	}

	// --- pre-restart: first load, attach, and populate a map entry. ---
	var firstLink interface{ Close() error }
	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		attached, err := Attach(objs.NatIngress, []string{ifaceName})
		if err != nil {
			return fmt.Errorf("attach: %w", err)
		}
		firstLink = attached[0]

		if err := objs.ShardConfigTable.Put(uint32(0), cfg); err != nil {
			return fmt.Errorf("populate shard_config_table: %w", err)
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

		attached, err := Attach(objs.NatIngress, []string{ifaceName})
		if err != nil {
			return fmt.Errorf("re-attach after restart: %w", err)
		}
		defer func() { _ = attached[0].Close() }()

		var got natprog.NatShardConfig
		if err := objs.ShardConfigTable.Lookup(uint32(0), &got); err != nil {
			return fmt.Errorf("lookup shard_config_table entry after restart: %w", err)
		}
		if got != cfg {
			return fmt.Errorf("shard_config_table entry after restart = %+v, want %+v", got, cfg)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-restart verification: %v", err)
	}
}

// TestAttach_MultipleUplinksRollsBackOnPartialFailure is the root-gated
// exit criterion for #545: a dual-homed shard node attaches its translation
// program to every fabric uplink, not just the primary.
//
// It also pins the all-or-nothing contract. A shard that attached to one
// uplink and then failed on the second would be the very condition this
// change exists to remove -- one uplink translating, the other forwarding
// tenant traffic untranslated and uncounted -- so a partial failure must
// leave nothing attached and fail the caller outright.
//
// Uses veth pairs, not dummy interfaces, for the reason the restart test
// above documents: dummy's driver does not implement ndo_bpf.
func TestAttach_MultipleUplinksRollsBackOnPartialFailure(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-nat-test-multi-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const (
		uplink0Name = "nat66testb0"
		peer0Name   = "nat66testb1"
		uplink1Name = "nat66testb2"
		peer1Name   = "nat66testb3"
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
			{LinkAttrs: netlink.LinkAttrs{Name: uplink0Name}, PeerName: peer0Name},
			{LinkAttrs: netlink.LinkAttrs{Name: uplink1Name}, PeerName: peer1Name},
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
		t.Fatalf("setup veth uplinks: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		// --- both uplinks of a dual-homed shard node: two links back. ---
		links, err := Attach(objs.NatIngress, []string{uplink0Name, uplink1Name})
		if err != nil {
			return fmt.Errorf("attach to both uplinks: %w", err)
		}
		if len(links) != 2 {
			return fmt.Errorf("attach: got %d links, want 2 (one per uplink)", len(links))
		}
		for _, l := range links {
			_ = l.Close()
		}

		// --- a second uplink that can never attach: the first uplink's
		// attach must be rolled back, not left dangling. ---
		if _, err := Attach(objs.NatIngress, []string{uplink0Name, "does-not-exist"}); err == nil {
			return errors.New("Attach() with an unresolvable second uplink error = nil, want an error")
		}

		// If the rollback genuinely closed the first uplink's link, a fresh
		// solo attach to it succeeds; if it leaked, this fails with the
		// kernel refusing a second native XDP program on the same interface.
		links, err = Attach(objs.NatIngress, []string{uplink0Name})
		if err != nil {
			return fmt.Errorf(
				"re-attach to %q after a rolled-back partial failure: %w "+
					"(the earlier partial attach was likely not rolled back)", uplink0Name, err)
		}
		defer func() { _ = links[0].Close() }()
		return nil
	})
	if err != nil {
		t.Fatalf("multi-uplink attach/rollback: %v", err)
	}
}
