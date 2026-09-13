// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// TestEdgedsr_LoadsWithEdgedsrContainerCapabilities loads the datapath with only
// the capabilities its galactic-gateway container holds. Every other test here
// loads as full root, which hides verifier rules that depend on
// capabilities.
func TestEdgedsr_LoadsWithEdgedsrContainerCapabilities(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-gateway", "base", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "galactic-gateway")
	if err != nil {
		t.Fatal(err)
	}
	err = loadcaps.Run(caps, func() error {
		var objs EdgedsrObjects
		if err := LoadEdgedsrObjects(&objs, nil); err != nil {
			return err
		}
		return objs.Close()
	})
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("verifier rejected the datapath with capabilities %v:\n%+v", caps, ve)
	}
	if err != nil {
		t.Fatalf("load datapath with capabilities %v: %v", caps, err)
	}
}
