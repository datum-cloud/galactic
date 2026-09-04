// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// TestHealth_NilObjectsIsUnhealthy covers the guard clause directly, no
// root or kernel required.
func TestHealth_NilObjectsIsUnhealthy(t *testing.T) {
	if err := Health(nil, []string{testIfaceEth0}); err == nil {
		t.Fatal("Health(nil, ...) error = nil, want an error")
	}
}

// TestCheckAttached_FakeNetlink exercises checkAttached/checkAttachedOne's
// logic against a faked netlink view (linkByNameFn/filterListFn), without
// needing root or a real interface -- covering the three outcomes the real
// integration test below can only exercise one of per run: interface
// missing entirely, interface present but without our filter, and
// interface present with our filter attached.
func TestCheckAttached_FakeNetlink(t *testing.T) {
	origLinkByName := linkByNameFn
	origFilterList := filterListFn
	t.Cleanup(func() {
		linkByNameFn = origLinkByName
		filterListFn = origFilterList
	})

	dummyLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: testIfaceEth0, Index: 7}}

	t.Run("interface not found is unhealthy", func(t *testing.T) {
		linkByNameFn = func(name string) (netlink.Link, error) {
			return nil, fmt.Errorf("simulated: no such interface %q", name)
		}
		if err := checkAttached([]string{testIfaceEth0}); err == nil {
			t.Fatal("checkAttached() error = nil, want an error for a missing interface")
		}
	})

	t.Run("interface present but filter missing is unhealthy", func(t *testing.T) {
		linkByNameFn = func(string) (netlink.Link, error) { return dummyLink, nil }
		filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.BpfFilter{Name: "some-other-filter"},
			}, nil
		}
		err := checkAttached([]string{testIfaceEth0})
		if err == nil {
			t.Fatal("checkAttached() error = nil, want an error when the galactic filter is absent")
		}
		if !strings.Contains(err.Error(), "not attached") {
			t.Errorf("checkAttached() error = %v, want it to mention the filter is not attached", err)
		}
	})

	t.Run("interface present with our filter attached is healthy", func(t *testing.T) {
		linkByNameFn = func(string) (netlink.Link, error) { return dummyLink, nil }
		filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.BpfFilter{Name: "some-other-filter"},
				&netlink.BpfFilter{Name: filterName},
			}, nil
		}
		if err := checkAttached([]string{testIfaceEth0}); err != nil {
			t.Fatalf("checkAttached() unexpected error: %v", err)
		}
	})

	t.Run("no interfaces at all is unhealthy", func(t *testing.T) {
		if err := checkAttached(nil); err == nil {
			t.Fatal("checkAttached(nil) error = nil, want an error")
		}
	})

	t.Run("FilterList error is unhealthy", func(t *testing.T) {
		linkByNameFn = func(string) (netlink.Link, error) { return dummyLink, nil }
		filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) {
			return nil, errors.New("simulated netlink error")
		}
		if err := checkAttached([]string{testIfaceEth0}); err == nil {
			t.Fatal("checkAttached() error = nil, want an error when FilterList itself fails")
		}
	})
}

// TestHandleHealthy_WatcherAware is a real, root-gated integration test
// (Health's own program/map Info() checks have no fake seam, unlike
// checkAttached, so a fully faked unit test can't exercise a passing
// Health result) covering two of ecv's review questions together against
// a genuinely healthy datapath:
//   - "should a dead watcher fail health?" -- a Watcher whose Watch loop
//     never started (Alive() == false) must make Healthy report unhealthy
//     even though Health's own checks all pass;
//   - "should a failed health check drive a reconcile before it fails the
//     probe?" -- once the filter is externally cleared (Health now fails
//     too), Healthy must nudge a *live* Watcher for an out-of-band
//     reconcile.
func TestHandleHealthy_WatcherAware(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-health-watcher-test-%d", 0))
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	const ifaceName = "usidhwtest0"
	// Handle.Healthy() always calls the real ResolveInterfaces() (it takes
	// no ifaces parameter, unlike Health itself) -- override it to the
	// dummy interface below, since a test netns has no default IPv6 route
	// for auto-detection to find.
	t.Setenv(config.EnvCNIEBPFInterfaces, ifaceName)

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

	var objs *prog.UsidObjects
	err = nsObj.Do(func(_ ns.NetNS) error {
		var loadErr error
		objs, loadErr = Load(pinDir)
		if loadErr != nil {
			return fmt.Errorf("load: %w", loadErr)
		}
		return Attach(objs.UsidIngress, []string{ifaceName})
	})
	if err != nil {
		t.Fatalf("load/attach: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	err = nsObj.Do(func(_ ns.NetNS) error {
		h := &Handle{Objs: objs} // no Watcher wired up at all -- must not change existing behavior
		if err := h.Healthy(); err != nil {
			return fmt.Errorf("Healthy() with no Watcher = %w, want nil (unaffected by the watcher check)", err)
		}

		w := newWatcher() // never started (Watch never ran against it) -- Alive() == false
		h.Watcher = w
		err := h.Healthy()
		if err == nil {
			return errors.New("Healthy() with a never-started Watcher = nil, want an error (dead watcher)")
		}
		if !strings.Contains(err.Error(), "watch loop is not running") {
			return fmt.Errorf("Healthy() error = %w, want it to mention the watch loop is not running", err)
		}

		// Now simulate a live Watch loop (Alive() == true) and externally
		// clear the filter, so Health's own checkAttached fails too.
		w.alive.Store(true)
		if err := Detach([]string{ifaceName}); err != nil {
			return fmt.Errorf("simulate external filter clear: %w", err)
		}
		if err := h.Healthy(); err == nil {
			return errors.New("Healthy() after Detach = nil, want an error from Health's own checkAttached")
		}
		select {
		case <-w.nudge:
			// A reconcile request is now pending, exactly as Watch's own
			// select loop would consume it on its next iteration.
		default:
			return errors.New("Healthy() on a Health failure did not nudge its live Watcher for an out-of-band reconcile")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHealth_RealDatapath_FlipsAfterAttachIsKilled is this milestone's exit
// criterion: "health check fails correctly when the program is unloaded
// (simulate by killing the attach and confirming the health endpoint
// flips)." It requires real root privileges to load/attach a BPF program
// and create an isolated test network namespace, so it is skipped (not
// silently passed) when not run as root -- matching attach_test.go's own
// TestLoadAttach_SurvivesRestartWithMapsIntact.
//
// Two independent ways of "killing the attach" are exercised, since they
// exercise genuinely different Health checks:
//   - Detach removes the kernel-level tc filter while this process's own
//     program/map handles stay open -- proves checkAttached actually
//     queries live kernel state instead of trusting a cached "we called
//     Attach once" assumption.
//   - objs.Close() releases this process's own file descriptors while the
//     kernel-level filter (which holds its own independent reference, see
//     the package doc comment) is left untouched -- proves
//     checkProgramReachable/checkMapsReachable catch a staleness the
//     attachment check alone would miss.
func TestHealth_RealDatapath_FlipsAfterAttachIsKilled(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-health-test-%d", 0))
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	const ifaceName = "usidhealth0"

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

	var objs *prog.UsidObjects
	err = nsObj.Do(func(_ ns.NetNS) error {
		var loadErr error
		objs, loadErr = Load(pinDir)
		if loadErr != nil {
			return fmt.Errorf("load: %w", loadErr)
		}
		if attachErr := Attach(objs.UsidIngress, []string{ifaceName}); attachErr != nil {
			return fmt.Errorf("attach: %w", attachErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("load/attach: %v", err)
	}
	t.Cleanup(func() {
		_ = objs.Close()
		_ = nsObj.Do(func(_ ns.NetNS) error { return nil })
	})

	// --- healthy immediately after attach ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		return Health(objs, []string{ifaceName})
	})
	if err != nil {
		t.Fatalf("Health() immediately after attach: unexpected error: %v", err)
	}

	// --- "kill the attach" #1: Detach removes the kernel-side filter ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		return Detach([]string{ifaceName})
	})
	if err != nil {
		t.Fatalf("Detach: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return Health(objs, []string{ifaceName})
	})
	if err == nil {
		t.Fatal("Health() after Detach: error = nil, want the attachment check to fail")
	}
	if !strings.Contains(err.Error(), "not attached") {
		t.Errorf("Health() after Detach: error = %v, want it to mention the filter is not attached", err)
	}
	t.Logf("Health() correctly flipped to unhealthy after Detach: %v", err)

	// --- re-attach, confirm healthy again, then "kill the attach" #2:
	// closing this process's own handle. ---
	err = nsObj.Do(func(_ ns.NetNS) error {
		return Attach(objs.UsidIngress, []string{ifaceName})
	})
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	err = nsObj.Do(func(_ ns.NetNS) error {
		return Health(objs, []string{ifaceName})
	})
	if err != nil {
		t.Fatalf("Health() after re-attach: unexpected error: %v", err)
	}

	if err := objs.Close(); err != nil {
		t.Fatalf("objs.Close(): %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return Health(objs, []string{ifaceName})
	})
	if err == nil {
		t.Fatal("Health() after objs.Close(): error = nil, want the program/map reachability checks to fail")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("Health() after objs.Close(): error = %v, want it to mention the program/maps are not reachable", err)
	}
	t.Logf("Health() correctly flipped to unhealthy after objs.Close(): %v", err)
}

// TestCheckNotPreempted covers the condition that makes this datapath
// silently invisible: another CNI attaching tcx to an interface this one
// owns. tcx runs ahead of clsact, so such a program decides the packet's
// fate before usid_ingress is invoked, and this side sees a clean zero
// rather than a drop.
//
// Every case here is about which of those readings is worth calling
// unhealthy. Reporting one wrongly points an operator at the datapath when
// the fault is elsewhere, or worse, marks a healthy node down.
func TestCheckNotPreempted(t *testing.T) {
	origLinkByName := linkByNameFn
	origTCXQuery := tcxQueryFn
	origProgramName := programNameFn
	t.Cleanup(func() {
		linkByNameFn = origLinkByName
		tcxQueryFn = origTCXQuery
		programNameFn = origProgramName
	})

	dummyLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: testIfaceEth0, Index: 7}}
	linkByNameFn = func(string) (netlink.Link, error) { return dummyLink, nil }

	t.Run("no tcx program means clsact is first", func(t *testing.T) {
		tcxQueryFn = func(int) ([]ebpf.ProgramID, error) { return nil, nil }
		if err := checkNotPreempted([]string{testIfaceEth0}); err != nil {
			t.Errorf("checkNotPreempted() error = %v, want nil with no tcx program attached", err)
		}
	})

	t.Run("a foreign tcx program in front is unhealthy", func(t *testing.T) {
		tcxQueryFn = func(int) ([]ebpf.ProgramID, error) { return []ebpf.ProgramID{101}, nil }
		programNameFn = func(ebpf.ProgramID) (string, error) { return "cil_from_netdev", nil }
		err := checkNotPreempted([]string{testIfaceEth0})
		if err == nil {
			t.Fatal("checkNotPreempted() error = nil, want an error for a foreign tcx program")
		}
		// The offender's name is the whole diagnostic value: without it an
		// operator learns only that something is wrong.
		if !strings.Contains(err.Error(), "cil_from_netdev") {
			t.Errorf("checkNotPreempted() error = %q, want it to name the preempting program", err)
		}
		if !strings.Contains(err.Error(), testIfaceEth0) {
			t.Errorf("checkNotPreempted() error = %q, want it to name the interface", err)
		}
	})

	// Keeps this correct if this package moves to tcx itself: its own
	// program running first is the desired end state, not a fault.
	t.Run("this datapath first in the tcx chain is healthy", func(t *testing.T) {
		tcxQueryFn = func(int) ([]ebpf.ProgramID, error) { return []ebpf.ProgramID{202, 203}, nil }
		programNameFn = func(id ebpf.ProgramID) (string, error) {
			if id == 202 {
				return prog.UsidProgUsidIngress, nil
			}
			return "cil_from_netdev", nil
		}
		if err := checkNotPreempted([]string{testIfaceEth0}); err != nil {
			t.Errorf("checkNotPreempted() error = %v, want nil when this datapath is first", err)
		}
	})

	// A kernel with no tcx query support cannot have a tcx program to be
	// preempted by. Reporting that as a datapath fault would hold such a
	// node permanently unhealthy over a condition it cannot have.
	t.Run("query unsupported is not a datapath fault", func(t *testing.T) {
		tcxQueryFn = func(int) ([]ebpf.ProgramID, error) {
			return nil, errors.New("simulated: BPF_PROG_QUERY unsupported")
		}
		if err := checkNotPreempted([]string{testIfaceEth0}); err != nil {
			t.Errorf("checkNotPreempted() error = %v, want nil when the query is unsupported", err)
		}
	})

	// An attached program whose name cannot be read is not evidence of
	// preemption by anything in particular, and a guess here would send an
	// operator after the wrong component.
	t.Run("unreadable program name does not claim preemption", func(t *testing.T) {
		tcxQueryFn = func(int) ([]ebpf.ProgramID, error) { return []ebpf.ProgramID{404}, nil }
		programNameFn = func(ebpf.ProgramID) (string, error) {
			return "", errors.New("simulated: program vanished")
		}
		if err := checkNotPreempted([]string{testIfaceEth0}); err != nil {
			t.Errorf("checkNotPreempted() error = %v, want nil when the name is unreadable", err)
		}
	})
}
