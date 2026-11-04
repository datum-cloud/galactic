//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
)

// TestInitializeWithoutPeerPin covers a router that rolls before the datapath
// loader has pinned the next-hop map: it must open the remaining maps and
// enable policy instead of failing every service route on the node.
func TestInitializeWithoutPeerPin(t *testing.T) {
	requireRoot(t)
	pinDir := filepath.Join("/sys/fs/bpf", "galactic-peer-pin-test-"+strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objects, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("load datapath: %v", err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	if err := os.Remove(filepath.Join(pinDir, serviceroutemap.ServicePeerMapName)); err != nil {
		t.Fatalf("remove next-hop pin: %v", err)
	}

	programmer := &EBPFRouteProgrammer{PinDir: pinDir}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize without a next-hop pin: %v", err)
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatalf("Finalize without a next-hop pin: %v", err)
	}
}
