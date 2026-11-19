// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestInspectWithoutDispatcher checks that inspecting a host no datapath has
// opened a dispatcher on reports ErrNoDispatcher and creates nothing.
func TestInspectWithoutDispatcher(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "galactic-xdp")
	if _, err := Inspect(dir); !errors.Is(err, ErrNoDispatcher) {
		t.Fatalf("Inspect(empty) = %v, want ErrNoDispatcher", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Inspect created %s: %v", dir, err)
	}
}
