// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"testing"
)

// TestDriftDetail checks that a dry run's difference reaches the change's
// drift report, wrapped or not, and that a retry is not drift.
func TestDriftDetail(t *testing.T) {
	err := fmt.Errorf("local: plan 80: %w", dirty("filter %s is not current on %s", filterRx, "bond0"))
	if !errors.Is(err, errDirty) {
		t.Fatal("a dirty error is not errDirty")
	}
	if got, want := dirtyDetail(err), "filter galactic_local_rx is not current on bond0"; got != want {
		t.Fatalf("detail %q, want %q", got, want)
	}
	if got := dirtyDetail(errDirty); got != "" {
		t.Fatalf("a bare errDirty has detail %q", got)
	}
	if d, ok := (&change{dirty: true, detail: "x"}).Drift(); !ok || d != "x" {
		t.Fatalf("drift %q %t", d, ok)
	}
	if _, ok := (&change{dirty: true, retry: true}).Drift(); ok {
		t.Fatal("a retry of links the last Apply could not create is reported as drift")
	}
}
