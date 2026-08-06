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

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
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

// TestLoad_RecreatesIncompatiblyPinnedMap covers the gap ecv's review
// flagged: a map pinned by a previous version of this program with a
// different shape (e.g. a changed value struct size, as vrf_value grew
// this cycle) must be recreated from scratch on the next Load, not treated
// as a fatal error that crashloops the node until an operator manually
// deletes the stale pin. Every map here is control-plane-owned and
// reconstructable (usidmap.Register/the GC controller repopulate it), so
// losing its contents across a schema change is the correct trade-off.
func TestLoad_RecreatesIncompatiblyPinnedMap(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-test-schema-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatalf("create pin dir: %v", err)
	}

	// Pre-pin a vrf_table with a deliberately incompatible shape (wrong
	// ValueSize) -- standing in for a previous process version's now-stale
	// pin after a value struct change.
	stale, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       prog.UsidMapVrfTable,
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create stale map: %v", err)
	}
	if err := stale.Pin(filepath.Join(pinDir, prog.UsidMapVrfTable)); err != nil {
		t.Fatalf("pin stale map: %v", err)
	}
	_ = stale.Close()

	objs, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load() with an incompatible pinned map = %v, want it to recreate the map and succeed", err)
	}
	defer func() { _ = objs.Close() }()

	info, err := objs.VrfTable.Info()
	if err != nil {
		t.Fatalf("VrfTable.Info(): %v", err)
	}
	if info.ValueSize == 4 {
		t.Errorf("vrf_table ValueSize after recreation = %d, want the real program's value size, not the stale 4-byte one",
			info.ValueSize)
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

// TestEnsureClsact_TreatsConcurrentEEXISTAsSuccess covers ensureClsact's
// race window against another agent (notably Cilium, which manages its own
// clsact qdisc on the same native devices) adding the same qdisc between
// ensureClsact's List and its own Add call: QdiscAdd returning EEXIST in
// that window must be treated as success, not propagated as an error,
// since the qdisc ensureClsact wanted to exist now does.
func TestEnsureClsact_TreatsConcurrentEEXISTAsSuccess(t *testing.T) {
	origList, origAdd := qdiscListFn, qdiscAddFn
	t.Cleanup(func() { qdiscListFn, qdiscAddFn = origList, origAdd })

	// List sees no clsact yet -- the race window ensureClsact is exposed
	// to is exactly a List that runs before the other agent's Add.
	qdiscListFn = func(netlink.Link) ([]netlink.Qdisc, error) { return nil, nil }
	qdiscAddFn = func(netlink.Qdisc) error { return unix.EEXIST }

	link := &fakeLink{attrs: netlink.LinkAttrs{Index: 1, Name: testIfaceEth0}}
	if err := ensureClsact(link); err != nil {
		t.Errorf("ensureClsact() = %v, want nil when QdiscAdd races EEXIST", err)
	}
}

// TestEnsureClsact_PropagatesOtherAddErrors confirms ensureClsact only
// swallows EEXIST specifically -- any other QdiscAdd failure must still be
// reported.
func TestEnsureClsact_PropagatesOtherAddErrors(t *testing.T) {
	origList, origAdd := qdiscListFn, qdiscAddFn
	t.Cleanup(func() { qdiscListFn, qdiscAddFn = origList, origAdd })

	wantErr := errors.New("simulated netlink failure")
	qdiscListFn = func(netlink.Link) ([]netlink.Qdisc, error) { return nil, nil }
	qdiscAddFn = func(netlink.Qdisc) error { return wantErr }

	link := &fakeLink{attrs: netlink.LinkAttrs{Index: 1, Name: testIfaceEth0}}
	if err := ensureClsact(link); !errors.Is(err, wantErr) {
		t.Errorf("ensureClsact() = %v, want it to wrap %v", err, wantErr)
	}
}

// TestResolveFilterPriority_EnvOverride covers
// config.EnvCNIEBPFFilterPriority overriding the default tc priority, and
// falling back to the default on an unset or invalid value -- the same
// override-then-fallback pattern interfaces_test.go's
// TestResolveInterfaces_EnvOverride exercises for interface selection.
func TestResolveFilterPriority_EnvOverride(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     uint16
	}{
		{name: "unset uses default", envValue: "", want: defaultFilterPriority},
		{name: "valid override", envValue: "5", want: 5},
		{name: "invalid value falls back to default", envValue: "not-a-number", want: defaultFilterPriority},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvCNIEBPFFilterPriority, tt.envValue)
			if got := resolveFilterPriority(); got != tt.want {
				t.Errorf("resolveFilterPriority() = %d, want %d", got, tt.want)
			}
		})
	}
}
