// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// TestUsid_LoadsWithGalacticCNICapabilities loads the datapath with only the
// capabilities galactic-cni's loader container holds. Every other test here
// loads as full root, which hides verifier rules that apply without
// CAP_PERFMON.
func TestUsid_LoadsWithGalacticCNICapabilities(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-cni", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "credential-refresh")
	if err != nil {
		t.Fatal(err)
	}
	err = loadcaps.Run(caps, func() error {
		var objs UsidObjects
		if err := LoadUsidObjects(&objs, nil); err != nil {
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
