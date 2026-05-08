// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgp

import (
	"net"
	"testing"
)

// TestVerifyPrefixSIDRoundTrip is the build-time guard for the
// prefix-sid encoding. If a future GoBGP version regresses the
// L3 Service Sub-TLV serialization, this test catches it before the
// agent's startup-time check would.
func TestVerifyPrefixSIDRoundTrip(t *testing.T) {
	if err := VerifyPrefixSIDRoundTrip(); err != nil {
		t.Fatalf("PrefixSID round-trip failed against the pinned GoBGP: %v", err)
	}
}

// TestEncodeDecodePrefixSIDApiLayer verifies the api-layer (anypb)
// encoder and decoder are inverses. The wire-format guard above
// protects against GoBGP regressions; this guards the api glue.
func TestEncodeDecodePrefixSIDApiLayer(t *testing.T) {
	want := net.ParseIP("fc00::1234:5678:9abc:0").To16()
	if want == nil {
		t.Fatal("setup: parse SID")
	}
	any, err := encodePrefixSIDForSID(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := sidFromPrefixSID(any)
	if got == nil {
		t.Fatal("decode returned nil")
	}
	if !got.Equal(want) {
		t.Errorf("round-trip mismatch: got %s, want %s", got, want)
	}
}

// TestNewServerRejectsPrefixSIDIfRoundTripFails covers the agent's
// startup-time fail-fast behavior. The verification call is exercised
// by simply constructing a Server with EncodingPrefixSID — if the
// pinned GoBGP works, this succeeds; if it ever regresses, this fails
// at the same point the agent would refuse to start.
func TestNewServerAcceptsPrefixSIDOnPinnedGoBGP(t *testing.T) {
	_, err := NewServer(Config{
		LocalASN:    65000,
		RouterID:    "10.0.0.1",
		NodeLocator: net.ParseIP("2001:db8::1"),
		Encoding:    EncodingPrefixSID,
	})
	if err != nil {
		t.Fatalf("NewServer with EncodingPrefixSID against pinned GoBGP: %v", err)
	}
}
