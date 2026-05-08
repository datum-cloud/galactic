// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package program

import (
	"errors"
	"net"
	"testing"
)

// TestLookupVRFFeedsBase62 is the regression guard described in
// PLAN-bgp-cutover.md: it asserts that the strings actually reaching
// vrf.GetVRFIdForVPC are the *base62* encoding, not raw hex. A
// future refactor that accidentally passes hex through the boundary
// fails this test rather than silently producing a kernel route in
// the wrong VRF (or no kernel route at all, since the lookup misses).
func TestLookupVRFFeedsBase62(t *testing.T) {
	var gotVPC, gotAttach string
	vrfLookupFn = func(vpcB62, attachB62 string) (uint32, error) {
		gotVPC = vpcB62
		gotAttach = attachB62
		return 42, nil
	}
	t.Cleanup(func() {
		// Restore the package-level default so other tests in the
		// suite don't see the fake lookup.
		vrfLookupFn = nil
	})

	if _, err := lookupVRF("000004d2", "002a"); err != nil {
		t.Fatalf("lookupVRF: %v", err)
	}
	// Hex 000004d2 -> base62 jU ; hex 002a -> base62 G.
	if gotVPC != "jU" {
		t.Errorf("vpc reached lookup as %q, want %q", gotVPC, "jU")
	}
	if gotAttach != "G" {
		t.Errorf("attach reached lookup as %q, want %q", gotAttach, "G")
	}
}

func TestLookupVRFRejectsBadHex(t *testing.T) {
	vrfLookupFn = func(string, string) (uint32, error) {
		t.Fatal("lookup should not have been called for bad hex")
		return 0, errors.New("unreachable")
	}
	t.Cleanup(func() { vrfLookupFn = nil })

	if _, err := lookupVRF("zz", "002a"); err == nil {
		t.Fatal("expected error for non-hex vpc")
	}
}

// TestAddDeleteSignatures is a build-time guard: if the public
// signatures of Add/Delete drift, this fails to compile. Add/Delete
// require a real netlink socket so we don't actually call them, just
// verify they accept the documented argument shape.
func TestAddDeleteSignatures(_ *testing.T) {
	var _ = func() {
		_ = Add("01", "02", &net.IPNet{}, []net.IP{net.IPv6loopback})
		_ = Delete("01", "02", &net.IPNet{})
	}
}
