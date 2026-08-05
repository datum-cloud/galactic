// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN) to load/attach BPF programs " +
			"and create a test network namespace; re-run via sudo")
	}
}

// TestLoad_PreflightBlocksLoad exercises the milestone's hard requirement
// that the kernel preflight check runs and blocks load on failure --
// exercised here via a stubbed preflightCheckFn so it needs no root and no
// real kernel capability gap to prove Load never reaches the BPF loader
// once the preflight check fails.
func TestLoad_PreflightBlocksLoad(t *testing.T) {
	origPreflight := preflightCheckFn
	t.Cleanup(func() { preflightCheckFn = origPreflight })

	wantErr := errors.New("simulated missing kernel capability")
	preflightCheckFn = func() error { return wantErr }

	// A pin directory that does not exist and is not on a bpffs -- if Load
	// ever got past the preflight check, os.MkdirAll or the BPF loader
	// itself would fail for an entirely different, less specific reason.
	// Getting back an error that wraps wantErr proves the preflight check
	// is what stopped it, not something else downstream.
	pinDir := filepath.Join(t.TempDir(), "does-not-exist", "galactic")

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
		t.Error("Load() created the pin directory despite failing preflight -- it must not touch " +
			"the filesystem or the kernel before the preflight check passes")
	}
}

// TestLoadAttach_SurvivesRestartWithMapsIntact is this milestone's exit
// criterion: program load/attach survives a container restart with maps
// intact (pinned-map continuity, design plan §4.4/§9). It requires real
// root privileges to load/attach a BPF program and create an isolated test
// network namespace, so it is skipped (not silently passed) when not run
// as root.
//
// "Restart" is simulated by closing the first Load/Attach's objects (which
// releases this process's own FDs, exactly like a container exiting) and
// then calling Load/Attach again against the *same* pin directory and
// interface -- the second call stands in for the replacement container's
// process. Map contents populated before the "restart" must still be
// readable after it, and re-attaching must replace the existing filter
// rather than stack a second one.
func TestLoadAttach_SurvivesRestartWithMapsIntact(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const ifaceName = "usidtest0"

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

		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}
		if err := handle.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		return handle.LinkSetUp(dummy)
	})
	if err != nil {
		t.Fatalf("setup dummy interface: %v", err)
	}

	const locatorKey uint64 = 0x0102030405060708

	// --- pre-restart: first load, attach, and populate a map entry. ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		if err := Attach(objs.UsidIngress, []string{ifaceName}); err != nil {
			return fmt.Errorf("attach: %w", err)
		}

		if err := objs.LocatorTable.Put(locatorKey, prog.UsidLocatorValue{Generation: 1}); err != nil {
			return fmt.Errorf("populate locator_table: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("pre-restart load/attach/populate: %v", err)
	}

	// --- simulate a container restart: fresh Load+Attach against the
	// same pinDir/interface, as a brand new process would do. ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("reload after restart: %w", err)
		}
		defer func() { _ = objs.Close() }()

		if err := Attach(objs.UsidIngress, []string{ifaceName}); err != nil {
			return fmt.Errorf("re-attach after restart: %w", err)
		}

		var val prog.UsidLocatorValue
		if err := objs.LocatorTable.Lookup(locatorKey, &val); err != nil {
			return fmt.Errorf("lookup locator_table entry after restart: %w", err)
		}
		if val.Generation != 1 {
			return fmt.Errorf("locator_table entry after restart: generation = %d, want 1", val.Generation)
		}

		// Re-attach must replace the existing filter, not stack a second
		// one alongside it.
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("find link: %w", err)
		}
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("list filters: %w", err)
		}
		if len(filters) != 1 {
			return fmt.Errorf("filter count after re-attach = %d, want 1 (idempotent replace, not a duplicate)",
				len(filters))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-restart verification: %v", err)
	}
}

// TestAttach_NoInterfacesIsError covers the defensive nil/empty-input
// guards in Attach directly, without needing root.
func TestAttach_NoInterfacesIsError(t *testing.T) {
	if err := Attach(nil, []string{testIfaceEth0}); err == nil {
		t.Error("Attach(nil program, ...) error = nil, want an error")
	}
	if err := Attach(nil, nil); err == nil {
		t.Error("Attach(nil, nil) error = nil, want an error")
	}
}
