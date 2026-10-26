// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package preflight

import "testing"

func TestAtLeast(t *testing.T) {
	for release, want := range map[string]bool{
		"6.8.0": true, "6.18.2-custom": true, "7.1.3-200.fc44.x86_64": true, "6.7.12": false, "5.15.0-91-generic": false,
		"6": false, "garbage": false, "6.8rc1": true,
	} {
		if got := atLeast(release, [2]int{6, 8}); got != want {
			t.Errorf("atLeast(%q) = %v, want %v", release, got, want)
		}
	}
}
