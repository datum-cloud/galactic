// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6

import (
	"bytes"
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// rfcExampleMapping is RFC 6296 §3.6's own worked example — internal
// FD01:0203:0405::/48, external 2001:0DB8:0001::/48, precomputed adjustment
// 0xD54F. Used as a test vector directly against the RFC's published
// numbers, not just internal self-consistency.
func rfcExampleMapping(t *testing.T) Mapping {
	t.Helper()
	return Mapping{
		ULAPrefix:    mustCIDR(t, "fd01:203:405::/48"),
		PublicPrefix: mustCIDR(t, "2001:db8:1::/48"),
	}
}

// TestMapping_Adjustment_RFCExample pins Adjustment's result against RFC
// 6296 §3.6's own published checksums and adjustment value.
func TestMapping_Adjustment_RFCExample(t *testing.T) {
	got, err := rfcExampleMapping(t).Adjustment()
	if err != nil {
		t.Fatalf("Adjustment: %v", err)
	}
	if got != 0xD54F {
		t.Errorf("Adjustment() = %#04x, want %#04x (RFC 6296 §3.6)", got, 0xD54F)
	}
}

// TestTranslate_RFCExample pins Translate's result against RFC 6296 §3.6's
// own published example address translation.
func TestTranslate_RFCExample(t *testing.T) {
	m := rfcExampleMapping(t)

	internal := net.ParseIP("fd01:203:405:1::1234")
	wantExternal := net.ParseIP("2001:db8:1:d550::1234")

	got, err := Translate(m, internal, true)
	if err != nil {
		t.Fatalf("Translate(outbound): %v", err)
	}
	if !got.Equal(wantExternal) {
		t.Errorf("Translate(outbound) = %v, want %v", got, wantExternal)
	}

	// And the reverse direction must recover the original address exactly.
	back, err := Translate(m, got, false)
	if err != nil {
		t.Fatalf("Translate(inbound): %v", err)
	}
	if !back.Equal(internal) {
		t.Errorf("Translate(inbound) round-trip = %v, want %v", back, internal)
	}
}

// TestTranslate_HostBitsUnchanged verifies bits below the fixed adjustment
// word (the Interface Identifier) are never modified — RFC 6296's whole
// premise is that the IID is untouched.
func TestTranslate_HostBitsUnchanged(t *testing.T) {
	m := rfcExampleMapping(t)
	internal := net.ParseIP("fd01:203:405:1::abcd:ef01")

	got, err := Translate(m, internal, true)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !got[8:].Equal(internal.To16()[8:]) {
		t.Errorf("IID bytes changed: got %x, want %x", got[8:], internal.To16()[8:])
	}
}

// TestTranslate_TwoTenantsCollidingULA is the overlapping-address-space
// property this package exists for: two independent Mappings sharing the
// identical ULAPrefix must translate to different, correct PublicPrefix
// addresses, with no shared state or cross-contamination — the caller
// (nptv6map, keyed by VRFID) is what keeps them from ever being applied to
// the wrong tenant's packet, but Translate itself must not silently produce
// the same output for both when given each mapping independently.
func TestTranslate_TwoTenantsCollidingULA(t *testing.T) {
	const sharedULA = "fd20:60::/48"
	tenantA := Mapping{ULAPrefix: mustCIDR(t, sharedULA), PublicPrefix: mustCIDR(t, "2001:db8:a::/48")}
	tenantB := Mapping{ULAPrefix: mustCIDR(t, sharedULA), PublicPrefix: mustCIDR(t, "2001:db8:b::/48")}

	addr := net.ParseIP("fd20:60::100:0")

	gotA, err := Translate(tenantA, addr, true)
	if err != nil {
		t.Fatalf("Translate(tenantA): %v", err)
	}
	gotB, err := Translate(tenantB, addr, true)
	if err != nil {
		t.Fatalf("Translate(tenantB): %v", err)
	}
	if gotA.Equal(gotB) {
		t.Fatalf("tenantA and tenantB translated the identical colliding ULA to the same public address: %v", gotA)
	}
	if !mustCIDR(t, "2001:db8:a::/48").Contains(gotA) {
		t.Errorf("tenantA result %v not within its own PublicPrefix", gotA)
	}
	if !mustCIDR(t, "2001:db8:b::/48").Contains(gotB) {
		t.Errorf("tenantB result %v not within its own PublicPrefix", gotB)
	}
}

func TestMapping_Errors(t *testing.T) {
	tests := []struct {
		name      string
		mapping   Mapping
		wantError bool
	}{
		{"Nil", Mapping{}, true},
		{"MismatchedLength", Mapping{
			ULAPrefix:    mustCIDR(t, "fd20:60::/48"),
			PublicPrefix: mustCIDR(t, "2001:db8::/56"),
		}, true},
		{"TooLong", Mapping{
			ULAPrefix:    mustCIDR(t, "fd20:60::/56"),
			PublicPrefix: mustCIDR(t, "2001:db8::/56"),
		}, true},
		{"Valid", rfcExampleMapping(t), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.mapping.Adjustment()
			if (err != nil) != tt.wantError {
				t.Errorf("Adjustment() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

// TestTranslate_RejectsOutOfRangeAddress verifies Translate refuses an
// address that isn't actually within the expected source prefix, rather
// than silently translating garbage.
func TestTranslate_RejectsOutOfRangeAddress(t *testing.T) {
	m := rfcExampleMapping(t)
	_, err := Translate(m, net.ParseIP("fd99::1"), true)
	if err == nil {
		t.Error("Translate: expected error for address outside ULAPrefix, got nil")
	}
}

// TestCopyPrefixBits_NonByteAligned exercises the partial-byte boundary
// case directly (a /48 in the tests above never touches it — all this
// package's real callers use byte-aligned /48 prefixes today, but the
// helper itself must not silently corrupt bits for a non-byte-aligned
// length).
func TestCopyPrefixBits_NonByteAligned(t *testing.T) {
	dst := net.IP{0xFF, 0xFF, 0xFF, 0xFF}
	src := net.IP{0x00, 0x00, 0x00, 0x00}

	copyPrefixBits(dst, src, 20) // 2 full bytes + top 4 bits of byte 2

	want := []byte{0x00, 0x00, 0x0F, 0xFF} // byte2's low nibble (unmasked) survives from dst
	if !bytes.Equal(dst, want) {
		t.Errorf("copyPrefixBits result = %x, want %x", dst, want)
	}
}
