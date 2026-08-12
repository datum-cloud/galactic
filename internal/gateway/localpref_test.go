// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "testing"

func TestLocalPreference_Primary(t *testing.T) {
	got := LocalPreference(testNodeA, testNodeA)
	if got != PrimaryLocalPref {
		t.Fatalf("LocalPreference(primary match) = %d, want %d", got, PrimaryLocalPref)
	}
}

func TestLocalPreference_Secondary(t *testing.T) {
	got := LocalPreference(testNodeB, testNodeA)
	if got != SecondaryLocalPref {
		t.Fatalf("LocalPreference(no match) = %d, want %d", got, SecondaryLocalPref)
	}
}

func TestLocalPreference_EmptyPrimaryNode(t *testing.T) {
	// A rule that hasn't been assigned a primaryNode yet must never be
	// treated as "primary" by an empty-string coincidence.
	got := LocalPreference("", "")
	if got != SecondaryLocalPref {
		t.Fatalf("LocalPreference(\"\", \"\") = %d, want %d (secondary, not accidentally primary)",
			got, SecondaryLocalPref)
	}
}

func TestLocalPreference_ValuesOrdered(t *testing.T) {
	if PrimaryLocalPref <= SecondaryLocalPref {
		t.Fatalf("PrimaryLocalPref (%d) must be greater than SecondaryLocalPref (%d)",
			PrimaryLocalPref, SecondaryLocalPref)
	}
}
