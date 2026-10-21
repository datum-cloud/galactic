// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// Interfaces the tests below give the datapath, and the sysctl device that
// stands for every interface.
const (
	testIfaceA  = "uplink1"
	testIfaceB  = "uplink2"
	testIfaceC  = "uplink3"
	testMissing = "uplink9"
	allDevices  = "all"
)

// fakeIPv4Sysctls points the sysctl package at a temporary procfs holding the
// IPv4 forwarding sysctls of each of ifaces, all 0, and returns its root.
func fakeIPv4Sysctls(t *testing.T, ifaces ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, dev := range append([]string{allDevices}, ifaces...) {
		writeOffSysctl(t, root, "net", "ipv4", "conf", dev, "forwarding")
	}
	writeOffSysctl(t, root, "net", "ipv4", "ip_forward")
	if err := sysctl.SetProcSysPath(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sysctl.SetProcSysPath(config.DefaultProcSysPath); err != nil {
			t.Error(err)
		}
	})
	return root
}

// writeOffSysctl writes a sysctl that reads 0, as a fresh interface has.
func writeOffSysctl(t *testing.T, root string, segments ...string) {
	t.Helper()
	path := filepath.Join(append([]string{root}, segments...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readSysctl(t *testing.T, root string, segments ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{root}, segments...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// TestIPv4Forwarding_FollowsNeed covers the IPv4 forwarding sysctls: tracking
// the datapath's interfaces writes nothing, enabling turns forwarding on for
// each of them and host-wide, and an interface resolved after that gets it
// too.
func TestIPv4Forwarding_FollowsNeed(t *testing.T) {
	root := fakeIPv4Sysctls(t, testIfaceA, testIfaceB, testIfaceC)
	f := newIPv4Forwarding()

	f.track([]string{testIfaceA, testIfaceB})
	for _, dev := range []string{testIfaceA, testIfaceB, allDevices} {
		if got := readSysctl(t, root, "net", "ipv4", "conf", dev, "forwarding"); got != "0" {
			t.Errorf("%s forwarding = %s before any IPv4 VIP loads, want 0", dev, got)
		}
	}
	if got := readSysctl(t, root, "net", "ipv4", "ip_forward"); got != "0" {
		t.Errorf("ip_forward = %s before any IPv4 VIP loads, want 0", got)
	}

	if err := f.enable(); err != nil {
		t.Fatalf("enable: %v", err)
	}
	for _, dev := range []string{testIfaceA, testIfaceB, allDevices} {
		if got := readSysctl(t, root, "net", "ipv4", "conf", dev, "forwarding"); got != "1" {
			t.Errorf("%s forwarding = %s once enabled, want 1", dev, got)
		}
	}
	if got := readSysctl(t, root, "net", "ipv4", "ip_forward"); got != "1" {
		t.Errorf("ip_forward = %s once enabled, want 1", got)
	}
	if got := readSysctl(t, root, "net", "ipv4", "conf", testIfaceC, "forwarding"); got != "0" {
		t.Errorf("%s forwarding = %s while not a datapath interface, want 0", testIfaceC, got)
	}

	// A bond member enslaved later is resolved by watchTargets.
	f.track([]string{testIfaceA, testIfaceB, testIfaceC})
	if got := readSysctl(t, root, "net", "ipv4", "conf", testIfaceC, "forwarding"); got != "1" {
		t.Errorf("%s forwarding = %s once tracked with forwarding on, want 1", testIfaceC, got)
	}

	// Enabling again, as every pass does, is harmless.
	if err := f.enable(); err != nil {
		t.Errorf("enable again: %v", err)
	}
}

// TestIPv4Forwarding_RetriesAfterFailure covers an interface whose sysctl
// cannot be set: enable reports it, and a later call succeeds once it can.
func TestIPv4Forwarding_RetriesAfterFailure(t *testing.T) {
	root := fakeIPv4Sysctls(t, testIfaceA)
	f := newIPv4Forwarding()
	f.track([]string{testIfaceA, testMissing})

	if err := f.enable(); err == nil || !strings.Contains(err.Error(), testMissing) {
		t.Fatalf("enable error = %v, want one naming %s, whose sysctl is missing", err, testMissing)
	}
	writeOffSysctl(t, root, "net", "ipv4", "conf", testMissing, "forwarding")
	if err := f.enable(); err != nil {
		t.Fatalf("enable after %s appeared: %v", testMissing, err)
	}
	if got := readSysctl(t, root, "net", "ipv4", "conf", testMissing, "forwarding"); got != "1" {
		t.Errorf("%s forwarding = %s, want 1", testMissing, got)
	}
}

// TestIPv4Forwarding_RewritesARecreatedInterface covers an interface that
// stops resolving and comes back with forwarding off, as a bond member
// deleted and created again does: it is written again when it returns.
func TestIPv4Forwarding_RewritesARecreatedInterface(t *testing.T) {
	root := fakeIPv4Sysctls(t, testIfaceA, testIfaceB)
	f := newIPv4Forwarding()
	f.track([]string{testIfaceA, testIfaceB})
	if err := f.enable(); err != nil {
		t.Fatalf("enable: %v", err)
	}

	f.track([]string{testIfaceA})
	writeOffSysctl(t, root, "net", "ipv4", "conf", testIfaceB, "forwarding")
	f.track([]string{testIfaceA, testIfaceB})
	if got := readSysctl(t, root, "net", "ipv4", "conf", testIfaceB, "forwarding"); got != "1" {
		t.Errorf("%s forwarding = %s once recreated and tracked again, want 1", testIfaceB, got)
	}
}

// TestIPv4Forwarding_NilIsOff covers a node with IPv4 VIPs off, which has no
// ipv4Forwarding: every call is a no-op.
func TestIPv4Forwarding_NilIsOff(t *testing.T) {
	var f *ipv4Forwarding
	f.track([]string{testIfaceA})
	if err := f.enable(); err != nil {
		t.Errorf("nil enable = %v, want nil", err)
	}
}
