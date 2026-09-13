// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// TestNat_LoadsWithNatContainerCapabilities loads the datapath with only the
// capabilities its galactic-nat container holds. Every other test here loads
// as full root, which hides verifier rules that depend on capabilities.
func TestNat_LoadsWithNatContainerCapabilities(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-nat", "base", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "galactic-nat")
	if err != nil {
		t.Fatal(err)
	}
	err = loadcaps.Run(caps, func() error {
		var objs NatObjects
		if err := LoadNatObjects(&objs, nil); err != nil {
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
