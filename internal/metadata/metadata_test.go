// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"strings"
	"testing"
)

func TestBuildInfo(t *testing.T) {
	vs := BuildInfo("galactic-router")
	if vs == "" {
		t.Error("BuildInfo should not be empty")
	}
	expected := []string{
		"galactic-router",
		Version,
		GitCommit,
		GitTreeState,
		BuildDate,
		SPDXLicense,
		GitURL,
		GoVersion,
		Platform,
		Executable,
	}
	for _, want := range expected {
		if !strings.Contains(vs, want) {
			t.Errorf("BuildInfo missing %q", want)
		}
	}
}
