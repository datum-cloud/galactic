// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// TestUsid_LoadsWithGalacticCNICapabilities loads the datapath with only the
// capabilities galactic-cni's loader container holds. Every other test here
// loads as full root, which hides verifier rules that apply without
// CAP_PERFMON.
//
// It also loads without PERFMON even when the manifest grants it. The datapath
// must not depend on PERFMON-only verifier allowances such as variable packet
// pointer offsets, so that the grant stays optional and a regression fails CI
// instead of hiding behind it.
func TestUsid_LoadsWithGalacticCNICapabilities(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-cni", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "credential-refresh")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		caps []string
	}{
		{"ManifestCapabilities", caps},
		{"ManifestCapabilitiesWithoutPerfmon", slices.DeleteFunc(slices.Clone(caps), func(c string) bool {
			return c == "PERFMON"
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadcaps.Run(tt.caps, func() error {
				var objs UsidObjects
				if err := LoadUsidObjects(&objs, nil); err != nil {
					return err
				}
				return objs.Close()
			})
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				t.Fatalf("verifier rejected the datapath with capabilities %v:\n%+v", tt.caps, ve)
			}
			if err != nil {
				t.Fatalf("load datapath with capabilities %v: %v", tt.caps, err)
			}
		})
	}
}
