// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_SYS_ADMIN) to load BPF programs; re-run via sudo")
	}
}

// TestLoadAgainstPinnedDatapath loads every prototype program through the
// verifier, with the uSID maps a datapath load pinned, and checks that Load
// uses those pins rather than creating any.
func TestLoadAgainstPinnedDatapath(t *testing.T) {
	requireRoot(t)

	galactic := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-handoff-test-%d", os.Getpid()))
	mine := galactic + "-probe"
	t.Cleanup(func() {
		_ = os.RemoveAll(galactic)
		_ = os.RemoveAll(mine)
	})
	usid, err := attach.Load(galactic)
	if err != nil {
		t.Fatalf("load the uSID datapath: %v", err)
	}
	defer usid.Close() //nolint:errcheck // test cleanup

	before, err := os.ReadDir(galactic)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := Load(galactic, mine)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer objs.Close() //nolint:errcheck // test cleanup
	for name, p := range map[string]any{
		"hp_xdp_public": objs.Programs.XDPPublic, "hp_tc_tenant_rx": objs.Programs.TCTenantRx,
		"hp_tc_tap_rx": objs.Programs.TCTapRx, "hp_xdp_pair_peer": objs.Programs.XDPPairPeer,
		"hp_tc_pair_rx": objs.Programs.TCPairRx, "hp_tc_link_guard": objs.Programs.TCLinkGuard,
	} {
		if p == nil {
			t.Errorf("%s did not load", name)
		}
	}
	after, err := os.ReadDir(galactic)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("Load changed the datapath's pins: %d entries before, %d after", len(before), len(after))
	}
	if _, err := os.Stat(filepath.Join(mine, "hp_stats")); err != nil {
		t.Errorf("the probe's own maps are not pinned under its directory: %v", err)
	}
}

// TestLoadRefusesWithoutDatapath checks that Load fails, and creates no map,
// when the uSID maps its programs use are not pinned.
func TestLoadRefusesWithoutDatapath(t *testing.T) {
	requireRoot(t)

	empty := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-handoff-empty-%d", os.Getpid()))
	mine := empty + "-probe"
	t.Cleanup(func() {
		_ = os.RemoveAll(empty)
		_ = os.RemoveAll(mine)
	})
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if objs, err := Load(empty, mine); err == nil {
		_ = objs.Close()
		t.Fatal("Load succeeded with no uSID maps pinned")
	}
	entries, err := os.ReadDir(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("Load created %d entries in the datapath's pin directory", len(entries))
	}
}
