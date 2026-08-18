// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

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
	if _, err := Attach(nil, "eth0"); err == nil {
		t.Error("Attach(nil program, ...) error = nil, want an error")
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

		l, err := Attach(objs.EdgeLb, ifaceName)
		if err != nil {
			return fmt.Errorf("attach: %w", err)
		}
		firstLink = l

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

		l, err := Attach(objs.EdgeLb, ifaceName)
		if err != nil {
			return fmt.Errorf("re-attach after restart: %w", err)
		}
		defer func() { _ = l.Close() }()

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
