// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"path/filepath"
	"testing"
)

// resetHooks restores the package-level hook vars to their default no-ops
// after a test installs custom ones, mirroring how every other override-var
// test in this package (preflightCheckFn, routeListFn, ...) cleans up.
func resetHooks(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetHooks(Hooks{})
	})
}

// TestSetHooks_NilFieldsDefaultToNoOps covers SetHooks' own defaulting
// logic directly: passing a zero-value Hooks (or a Hooks with some fields
// nil) must never leave a nil func var that a later Load/attachOne/
// detachOne call would panic on.
func TestSetHooks_NilFieldsDefaultToNoOps(t *testing.T) {
	resetHooks(t)

	SetHooks(Hooks{})
	loadHook(errors.New("must not panic"))
	attachHook("eth0", errors.New("must not panic"))
	detachHook("eth0", errors.New("must not panic"))

	SetHooks(Hooks{OnLoad: func(error) {}})
	loadHook(nil)
	attachHook("eth0", nil) // OnAttach left nil, must still not panic
	detachHook("eth0", nil) // OnDetach left nil, must still not panic
}

// TestLoad_FiresLoadHookOnFailure covers the milestone's "BPF program
// load/reload events and failures" metric hook at its most exercisable
// failure path without root: a stubbed preflightCheckFn failure (the same
// technique TestLoad_PreflightBlocksLoad already uses), asserting loadHook
// observes the exact error Load returns.
func TestLoad_FiresLoadHookOnFailure(t *testing.T) {
	origPreflight := preflightCheckFn
	t.Cleanup(func() { preflightCheckFn = origPreflight })
	resetHooks(t)

	wantErr := errors.New("simulated missing kernel capability")
	preflightCheckFn = func() error { return wantErr }

	var gotErr error
	var calls int
	SetHooks(Hooks{OnLoad: func(err error) {
		calls++
		gotErr = err
	}})

	pinDir := filepath.Join(t.TempDir(), "does-not-exist", "galactic")
	if _, err := Load(pinDir); err == nil {
		t.Fatal("Load() error = nil, want the preflight failure")
	}

	if calls != 1 {
		t.Fatalf("loadHook called %d times, want exactly 1", calls)
	}
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("loadHook observed error = %v, want it to wrap %v", gotErr, wantErr)
	}
}
