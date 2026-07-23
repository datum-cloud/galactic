// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package uformat

import (
	"net/netip"
	"testing"
)

// testBlock is an arbitrary 48-bit Block value used across tests that
// don't specifically target Block's own boundaries.
const testBlock uint64 = 0x2001_0DB8_FF01

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		fields Fields
	}{
		{
			"MinNodeIDMinArgumentEndDT46",
			Fields{Block: testBlock, NodeID: NodeIDMin, Function: FunctionEndDT46, Argument: ArgumentMin},
		},
		{
			"MaxNodeIDMaxArgumentEndDT2",
			Fields{Block: testBlock, NodeID: NodeIDMax, Function: FunctionEndDT2, Argument: ArgumentMax},
		},
		{"EncodeZeroBlock", Fields{Block: 0, NodeID: 0x0001, Function: FunctionEndDT46, Argument: 0x001}},
		{"EncodeMaxBlock", Fields{Block: BlockMax, NodeID: 0x0001, Function: FunctionEndDT46, Argument: 0x001}},
		{
			"ReservedArgumentZeroStillEncodes",
			Fields{Block: testBlock, NodeID: 0x0001, Function: FunctionEndDT46, Argument: 0x000},
		},
		{"UndefinedFunctionStillEncodes", Fields{Block: testBlock, NodeID: 0x0001, Function: 0x3, Argument: 0x001}},
		{"NodeIDZeroStillEncodes", Fields{Block: testBlock, NodeID: 0x0000, Function: FunctionEndDT46, Argument: 0x001}},
		{
			"NodeIDAboveReservedRangeStillEncodes",
			Fields{Block: testBlock, NodeID: 0xFFFF, Function: FunctionEndDT46, Argument: 0x001},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := Encode(tt.fields)
			if err != nil {
				t.Fatalf("Encode(%+v) unexpected error: %v", tt.fields, err)
			}
			got, err := Decode(addr)
			if err != nil {
				t.Fatalf("Decode(%s) unexpected error: %v", addr, err)
			}
			if got != tt.fields {
				t.Errorf("round trip = %+v, want %+v (addr %s)", got, tt.fields, addr)
			}
		})
	}
}

func TestEncodeFieldOverflow(t *testing.T) {
	tests := []struct {
		name   string
		fields Fields
	}{
		{"BlockOverflows48Bits", Fields{Block: BlockMax + 1, NodeID: 1, Function: FunctionEndDT46, Argument: 1}},
		{"FunctionOverflows4Bits", Fields{Block: testBlock, NodeID: 1, Function: 0x10, Argument: 1}},
		{"ArgumentOverflows12Bits", Fields{Block: testBlock, NodeID: 1, Function: FunctionEndDT46, Argument: 0x1000}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Encode(tt.fields); err == nil {
				t.Errorf("Encode(%+v) = nil error, want overflow error", tt.fields)
			}
		})
	}
}

func TestDecodeRejectsNonZeroPadding(t *testing.T) {
	addr, err := Encode(Fields{Block: testBlock, NodeID: 1, Function: FunctionEndDT46, Argument: 1})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	b := addr.As16()
	b[15] = 0x01 // corrupt the last padding byte (bit 128)
	corrupted := netip.AddrFrom16(b)

	if _, err := Decode(corrupted); err == nil {
		t.Errorf("Decode(%s) = nil error, want non-zero-padding error", corrupted)
	}
}

func TestDecodeRejectsNonV6Address(t *testing.T) {
	if _, err := Decode(netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Errorf("Decode(IPv4) = nil error, want error")
	}
	if _, err := Block(netip.Addr{}); err == nil {
		t.Errorf("Block(zero Addr) = nil error, want error")
	}
}

// TestAccessorsRejectNonV6Address exercises the shared as16 guard from
// every exported accessor and key constructor that takes a netip.Addr, so
// each of their error branches has direct coverage, not just Decode's/
// Block's.
func TestAccessorsRejectNonV6Address(t *testing.T) {
	invalid := netip.MustParseAddr("192.0.2.1")

	if _, err := NodeID(invalid); err == nil {
		t.Errorf("NodeID(IPv4) = nil error, want error")
	}
	if _, err := Function(invalid); err == nil {
		t.Errorf("Function(IPv4) = nil error, want error")
	}
	if _, err := Argument(invalid); err == nil {
		t.Errorf("Argument(IPv4) = nil error, want error")
	}
	if _, err := LocatorKeyFromAddr(invalid); err == nil {
		t.Errorf("LocatorKeyFromAddr(IPv4) = nil error, want error")
	}
	if _, err := FunctionKeyFromAddr(invalid); err == nil {
		t.Errorf("FunctionKeyFromAddr(IPv4) = nil error, want error")
	}
}

// TestFieldAccessorsMatchDecode verifies the standalone Block/NodeID/
// Function/Argument accessors agree with Decode's extraction of the same
// address, field by field, at every field's fixed offset.
func TestFieldAccessorsMatchDecode(t *testing.T) {
	fields := Fields{Block: testBlock, NodeID: 0xABCD, Function: FunctionEndDT2, Argument: 0x0AB}
	addr, err := Encode(fields)
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	if got, err := Block(addr); err != nil || got != fields.Block {
		t.Errorf("Block(%s) = %#x, %v; want %#x, nil", addr, got, err, fields.Block)
	}
	if got, err := NodeID(addr); err != nil || got != fields.NodeID {
		t.Errorf("NodeID(%s) = %#x, %v; want %#x, nil", addr, got, err, fields.NodeID)
	}
	if got, err := Function(addr); err != nil || got != fields.Function {
		t.Errorf("Function(%s) = %#x, %v; want %#x, nil", addr, got, err, fields.Function)
	}
	if got, err := Argument(addr); err != nil || got != fields.Argument {
		t.Errorf("Argument(%s) = %#x, %v; want %#x, nil", addr, got, err, fields.Argument)
	}
}

// TestArgumentIndependentOfFunction confirms Argument is read from its own
// fixed offset (bits 69-80) regardless of Function's value (bits 65-68) —
// the nibble split within byte 8 must not leak bits between the two
// fields.
func TestArgumentIndependentOfFunction(t *testing.T) {
	for _, function := range []uint8{FunctionEndDT46, FunctionEndDT2, 0x0, 0xF} {
		addr, err := Encode(Fields{Block: testBlock, NodeID: 1, Function: function, Argument: ArgumentMax})
		if err != nil {
			t.Fatalf("Encode(function=%#x): unexpected error: %v", function, err)
		}
		arg, err := Argument(addr)
		if err != nil {
			t.Fatalf("Argument(%s): unexpected error: %v", addr, err)
		}
		if arg != ArgumentMax {
			t.Errorf("Argument(%s) with function=%#x = %#x, want %#x", addr, function, arg, ArgumentMax)
		}
		fn, err := Function(addr)
		if err != nil || fn != function {
			t.Errorf("Function(%s) = %#x, %v; want %#x, nil", addr, fn, err, function)
		}
	}
}

func TestValidateNodeID(t *testing.T) {
	tests := []struct {
		name      string
		nodeID    uint16
		wantError bool
	}{
		{"MinValid", 0x0001, false},
		{"NodeIDMaxValid", 0xDFFF, false},
		{"MidValid", 0x1234, false},
		{"ZeroRejected", 0x0000, true},
		{"JustAboveMaxRejected", 0xE000, true},
		{"MaxUint16Rejected", 0xFFFF, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNodeID(tt.nodeID)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateNodeID(%#x) error = %v, wantError = %v", tt.nodeID, err, tt.wantError)
			}
		})
	}
}

func TestValidateFunction(t *testing.T) {
	tests := []struct {
		name      string
		function  uint8
		wantError bool
	}{
		{"EndDT46Valid", FunctionEndDT46, false},
		{"EndDT2Valid", FunctionEndDT2, false},
		{"ZeroRejected", 0x0, true},
		{"MidRangeRejected", 0xA, true},
		{"MaxNibbleRejected", 0xF + 1, true}, // 0x10, also out of nibble range but still exercises rejection
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFunction(tt.function)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateFunction(%#x) error = %v, wantError = %v", tt.function, err, tt.wantError)
			}
		})
	}
}

func TestValidateArgument(t *testing.T) {
	tests := []struct {
		name      string
		argument  uint16
		wantError bool
	}{
		{"MinValid", 0x001, false},
		{"ArgumentMaxValid", 0xFFF, false},
		{"MidValid", 0x800, false},
		{"ZeroRejectedExplicitly", 0x000, true},
		{"OverflowRejected", 0x1000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArgument(tt.argument)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateArgument(%#x) error = %v, wantError = %v", tt.argument, err, tt.wantError)
			}
		})
	}
}

func TestValidateBlock(t *testing.T) {
	tests := []struct {
		name      string
		block     uint64
		wantError bool
	}{
		{"ZeroValid", 0, false},
		{"BlockMaxValid", BlockMax, false},
		{"OverflowRejected", BlockMax + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBlock(tt.block)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateBlock(%#x) error = %v, wantError = %v", tt.block, err, tt.wantError)
			}
		})
	}
}

func TestFieldsValidate(t *testing.T) {
	tests := []struct {
		name      string
		fields    Fields
		wantError bool
	}{
		{"AllValid", Fields{Block: testBlock, NodeID: 0x1234, Function: FunctionEndDT46, Argument: 0x001}, false},
		{
			"ArgumentZeroInvalid",
			Fields{Block: testBlock, NodeID: 0x1234, Function: FunctionEndDT46, Argument: 0x000},
			true,
		},
		{
			"NodeIDOutOfRangeInvalid",
			Fields{Block: testBlock, NodeID: 0xFFFF, Function: FunctionEndDT46, Argument: 0x001},
			true,
		},
		{"UndefinedFunctionInvalid", Fields{Block: testBlock, NodeID: 0x1234, Function: 0x3, Argument: 0x001}, true},
		{
			"BlockOverflowInvalid",
			Fields{Block: BlockMax + 1, NodeID: 0x1234, Function: FunctionEndDT46, Argument: 0x001},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fields.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Fields(%+v).Validate() error = %v, wantError = %v", tt.fields, err, tt.wantError)
			}
		})
	}
}

func TestLocatorKey(t *testing.T) {
	tests := []struct {
		name   string
		block  uint64
		nodeID uint16
	}{
		{"MinNodeID", testBlock, NodeIDMin},
		{"MaxNodeID", testBlock, NodeIDMax},
		{"LocatorZeroBlock", 0, 0x1234},
		{"LocatorMaxBlock", BlockMax, 0x1234},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := NewLocatorKey(tt.block, tt.nodeID)
			if err != nil {
				t.Fatalf("NewLocatorKey(%#x, %#x): unexpected error: %v", tt.block, tt.nodeID, err)
			}

			addr, err := Encode(Fields{Block: tt.block, NodeID: tt.nodeID, Function: FunctionEndDT46, Argument: 0x001})
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}
			got, err := LocatorKeyFromAddr(addr)
			if err != nil {
				t.Fatalf("LocatorKeyFromAddr(%s): unexpected error: %v", addr, err)
			}
			if got != want {
				t.Errorf("LocatorKeyFromAddr(%s) = %#x, want %#x", addr, got, want)
			}
		})
	}
}

// TestLocatorKeyIgnoresFunctionAndArgument confirms the locator_table key
// depends only on Block+Node-ID (bits 1-64) — two addresses differing only
// in Function/Argument must produce the same LocatorKey, matching R1's
// "/64 match, not /128" requirement.
func TestLocatorKeyIgnoresFunctionAndArgument(t *testing.T) {
	addrA, err := Encode(Fields{Block: testBlock, NodeID: 0x1234, Function: FunctionEndDT46, Argument: 0x001})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	addrB, err := Encode(Fields{Block: testBlock, NodeID: 0x1234, Function: FunctionEndDT2, Argument: 0xFFF})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	keyA, err := LocatorKeyFromAddr(addrA)
	if err != nil {
		t.Fatalf("LocatorKeyFromAddr(%s): unexpected error: %v", addrA, err)
	}
	keyB, err := LocatorKeyFromAddr(addrB)
	if err != nil {
		t.Fatalf("LocatorKeyFromAddr(%s): unexpected error: %v", addrB, err)
	}
	if keyA != keyB {
		t.Errorf("LocatorKey differs across Function/Argument: %#x (A) != %#x (B)", keyA, keyB)
	}
}

func TestFunctionKey(t *testing.T) {
	tests := []struct {
		name     string
		block    uint64
		function uint8
	}{
		{"EndDT46", testBlock, FunctionEndDT46},
		{"EndDT2", testBlock, FunctionEndDT2},
		{"FunctionZeroBlock", 0, FunctionEndDT46},
		{"FunctionMaxBlock", BlockMax, FunctionEndDT2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := NewFunctionKey(tt.block, tt.function)
			if err != nil {
				t.Fatalf("NewFunctionKey(%#x, %#x): unexpected error: %v", tt.block, tt.function, err)
			}

			addr, err := Encode(Fields{Block: tt.block, NodeID: 0xABCD, Function: tt.function, Argument: 0x001})
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}
			got, err := FunctionKeyFromAddr(addr)
			if err != nil {
				t.Fatalf("FunctionKeyFromAddr(%s): unexpected error: %v", addr, err)
			}
			if got != want {
				t.Errorf("FunctionKeyFromAddr(%s) = %#x, want %#x", addr, got, want)
			}
		})
	}
}

// TestFunctionKeyIgnoresNodeIDAndArgument confirms the function_table key
// depends only on Block+Function, composed across the non-adjacent bit
// ranges — two addresses differing only in Node-ID/Argument must produce
// the same FunctionKey.
func TestFunctionKeyIgnoresNodeIDAndArgument(t *testing.T) {
	addrA, err := Encode(Fields{Block: testBlock, NodeID: 0x0001, Function: FunctionEndDT46, Argument: 0x001})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	addrB, err := Encode(Fields{Block: testBlock, NodeID: 0xDFFF, Function: FunctionEndDT46, Argument: 0xFFF})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	keyA, err := FunctionKeyFromAddr(addrA)
	if err != nil {
		t.Fatalf("FunctionKeyFromAddr(%s): unexpected error: %v", addrA, err)
	}
	keyB, err := FunctionKeyFromAddr(addrB)
	if err != nil {
		t.Fatalf("FunctionKeyFromAddr(%s): unexpected error: %v", addrB, err)
	}
	if keyA != keyB {
		t.Errorf("FunctionKey differs across Node-ID/Argument: %#x (A) != %#x (B)", keyA, keyB)
	}
}

func TestNewLocatorKeyRejectsBlockOverflow(t *testing.T) {
	if _, err := NewLocatorKey(BlockMax+1, 1); err == nil {
		t.Errorf("NewLocatorKey(BlockMax+1, 1) = nil error, want overflow error")
	}
}

func TestNewFunctionKeyRejectsOverflow(t *testing.T) {
	if _, err := NewFunctionKey(BlockMax+1, FunctionEndDT46); err == nil {
		t.Errorf("NewFunctionKey(BlockMax+1, ...) = nil error, want block-overflow error")
	}
	if _, err := NewFunctionKey(testBlock, 0x10); err == nil {
		t.Errorf("NewFunctionKey(..., 0x10) = nil error, want function-overflow error")
	}
}

func TestVRFKey(t *testing.T) {
	tests := []struct {
		name     string
		block    uint64
		argument uint16
	}{
		{"MinArgument", testBlock, ArgumentMin},
		{"MaxArgument", testBlock, ArgumentMax},
		{"VRFZeroBlock", 0, ArgumentMin},
		{"VRFMaxBlock", BlockMax, ArgumentMax},
		// NewVRFKey deliberately does not reject the reserved Argument
		// 0x000 (that rejection belongs to usidmap.VRFTable.Register per
		// design plan R4/§5.1) -- confirm it still composes a key rather
		// than erroring.
		{"ReservedArgumentZeroStillComposes", testBlock, 0x000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := NewVRFKey(tt.block, tt.argument)
			if err != nil {
				t.Fatalf("NewVRFKey(%#x, %#x): unexpected error: %v", tt.block, tt.argument, err)
			}

			addr, err := Encode(Fields{Block: tt.block, NodeID: 0xABCD, Function: FunctionEndDT46, Argument: tt.argument})
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}
			got, err := VRFKeyFromAddr(addr)
			if err != nil {
				t.Fatalf("VRFKeyFromAddr(%s): unexpected error: %v", addr, err)
			}
			if got != want {
				t.Errorf("VRFKeyFromAddr(%s) = %#x, want %#x", addr, got, want)
			}
		})
	}
}

// TestVRFKeyIgnoresNodeIDAndFunction confirms the vrf_table key depends
// only on Block+Argument, composed across the non-adjacent bit ranges —
// two addresses differing only in Node-ID/Function must produce the same
// VRFKey.
func TestVRFKeyIgnoresNodeIDAndFunction(t *testing.T) {
	addrA, err := Encode(Fields{Block: testBlock, NodeID: 0x0001, Function: FunctionEndDT46, Argument: 0x123})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	addrB, err := Encode(Fields{Block: testBlock, NodeID: 0xDFFF, Function: FunctionEndDT2, Argument: 0x123})
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	keyA, err := VRFKeyFromAddr(addrA)
	if err != nil {
		t.Fatalf("VRFKeyFromAddr(%s): unexpected error: %v", addrA, err)
	}
	keyB, err := VRFKeyFromAddr(addrB)
	if err != nil {
		t.Fatalf("VRFKeyFromAddr(%s): unexpected error: %v", addrB, err)
	}
	if keyA != keyB {
		t.Errorf("VRFKey differs across Node-ID/Function: %#x (A) != %#x (B)", keyA, keyB)
	}
}

// TestVRFKeyIncludesBlock confirms two different Blocks sharing the same
// Argument produce different VRFKeys — the design plan R8 property that
// lets a make-before-break migration hold two independently keyed entries
// for the same Argument, one per Block.
func TestVRFKeyIncludesBlock(t *testing.T) {
	keyA, err := NewVRFKey(0x0102030405AA, 0x123)
	if err != nil {
		t.Fatalf("NewVRFKey: unexpected error: %v", err)
	}
	keyB, err := NewVRFKey(0x0A0B0C0D0E0F, 0x123)
	if err != nil {
		t.Fatalf("NewVRFKey: unexpected error: %v", err)
	}
	if keyA == keyB {
		t.Errorf("VRFKey ignored Block: both blocks produced %#x for the same Argument", keyA)
	}
}

func TestNewVRFKeyRejectsOverflow(t *testing.T) {
	if _, err := NewVRFKey(BlockMax+1, ArgumentMin); err == nil {
		t.Errorf("NewVRFKey(BlockMax+1, ...) = nil error, want block-overflow error")
	}
	if _, err := NewVRFKey(testBlock, ArgumentMax+1); err == nil {
		t.Errorf("NewVRFKey(..., ArgumentMax+1) = nil error, want argument-overflow error")
	}
}
