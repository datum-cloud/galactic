// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66prog

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// TestNat66_LoadsWithNat66ContainerCapabilities loads the datapath with only
// the capabilities its galactic-nat66 container holds. Every other test here
// loads as full root, which hides verifier rules that depend on
// capabilities.
func TestNat66_LoadsWithNat66ContainerCapabilities(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-nat66", "base", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "galactic-nat66")
	if err != nil {
		t.Fatal(err)
	}
	err = loadcaps.Run(caps, func() error {
		var objs Nat66Objects
		if err := LoadNat66Objects(&objs, nil); err != nil {
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
