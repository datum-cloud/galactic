// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
)

// TestLocal_LoadsWithWorkerContainerCapabilities loads the Local handoff
// programs with only the capabilities the galactic-worker container holds,
// as Worker does at start. The uSID maps it opens are pinned first as full
// root, as galactic-cni does on a node. Every other test here loads as full
// root, which hides verifier rules that depend on capabilities.
func TestLocal_LoadsWithWorkerContainerCapabilities(t *testing.T) {
	requireRoot(t)
	manifest := filepath.Join("..", "..", "..", "config", "galactic-worker", "base", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "galactic-worker")
	if err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("/sys/fs/bpf/galactic-local-caps-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pin) })
	usid, err := attach.Load(pin + "/usid")
	if err != nil {
		t.Fatalf("pin the uSID datapath: %v", err)
	}
	t.Cleanup(func() { _ = usid.Close() })

	err = loadcaps.Run(caps, func() error {
		objs, err := localprog.Load(pin+"/usid", pin+"/local")
		if err != nil {
			return err
		}
		return objs.Close()
	})
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("verifier rejected the Local programs with capabilities %v:\n%+v", caps, ve)
	}
	if err != nil {
		t.Fatalf("load the Local programs with capabilities %v: %v", caps, err)
	}
}
