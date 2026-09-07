// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package uformat implements the pure-Go bit-layout primitives for the uFMT
// 48+16 SRv6 uSID carrier format. It has no kernel, cgo, or BPF dependency: it
// encodes and decodes the fixed-offset fields inside a 128-bit uSID address and
// derives the map keys the datapath's locator_table and function_table use.
//
// Bit layout, in the RFC 9800 REPLACE-CSID flavor:
//
//	bit  1                  48 49              64 65   68 69          80 81                  128
//	     |------ uSID Block (48) ------|-- Node-ID (16) --|-Fn(4)-|-- Argument (12) --|------ Padding (48, zero) ------|
//
// Byte layout of the 16-byte address, bit 1 being the most significant bit of
// byte 0:
//
//	bytes 0-5   (48 bits) Block
//	bytes 6-7   (16 bits) Node-ID
//	byte  8 hi  ( 4 bits) Function
//	byte 8 lo + byte 9 (12 bits) Argument
//	bytes 10-15 (48 bits) Padding (must be zero)
//
// Every accessor reads or writes its field at that field's fixed offset only.
// Nothing here shifts one field's bits into another field's frame: all four
// fields stay independently readable from an unmutated address, and map keys
// are composed by copying those fixed-offset reads. A field's own
// right-justifying shift out of its offset is not what that rules out.
package uformat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Field widths, in bits, of the uFMT 48+16 layout.
const (
	BlockBits    = 48
	NodeIDBits   = 16
	FunctionBits = 4
	ArgumentBits = 12
	PaddingBits  = 48
)

const (
	// BlockMax is the largest value that fits in the 48-bit Block field.
	BlockMax = 1<<BlockBits - 1 // 0xFFFFFFFFFFFF

	// NodeIDMin and NodeIDMax bound the reserved Node-ID range. 0xE000-0xFFFF
	// belongs to the Function and Argument universe, not to Node-ID.
	NodeIDMin = 0x0001
	NodeIDMax = 0xDFFF

	// FunctionEndDT46 and FunctionEndDT2 are the only Function values defined:
	// 0xE selects the L3 uEnd.DT46 behavior this datapath implements, and 0xF
	// is reserved for a future L2 uEnd.DT2 behavior this code must not
	// block.
	FunctionEndDT46 = 0xE
	FunctionEndDT2  = 0xF

	// ArgumentMin and ArgumentMax bound the valid Argument range. 0x000 is
	// reserved and must never be registered into vrf_table; ValidateArgument
	// rejects it.
	ArgumentMin = 0x001
	ArgumentMax = 0xFFF // 12-bit max
)

// Fields is the decoded set of uFMT 48+16 fields carried by one uSID address.
// Block and NodeID occupy their full width; Function and Argument are stored
// right-justified in wider types with only their low 4 and 12 bits
// significant.
type Fields struct {
	Block    uint64
	NodeID   uint16
	Function uint8
	Argument uint16
}

// Validate returns an error if any field is out of range: Block above BlockMax,
// Node-ID outside its bounds, Function not a defined value, or Argument outside
// its bounds, which alone excludes the reserved zero.
//
// Decode does not call this. Callers validate at the point a value is about to
// be registered into a map, never on the packet-read path.
func (f Fields) Validate() error {
	return errors.Join(
		ValidateBlock(f.Block),
		ValidateNodeID(f.NodeID),
		ValidateFunction(f.Function),
		ValidateArgument(f.Argument),
	)
}

// ValidateBlock returns an error if block does not fit in the 48-bit Block
// field.
func ValidateBlock(block uint64) error {
	if block > BlockMax {
		return fmt.Errorf("uformat: block %#x overflows the 48-bit Block field (max %#x)", block, uint64(BlockMax))
	}
	return nil
}

// ValidateNodeID returns an error if nodeID falls outside the reserved Node-ID
// range 0x0001-0xDFFF.
func ValidateNodeID(nodeID uint16) error {
	if nodeID < NodeIDMin || nodeID > NodeIDMax {
		return fmt.Errorf("uformat: node-id %#x out of range [%#x,%#x]", nodeID, uint16(NodeIDMin), uint16(NodeIDMax))
	}
	return nil
}

// ValidateFunction returns an error unless function is one of the two defined
// Function values. A registration-time check only: the datapath never validates
// Function against this enum, and an unrecognised value shows up as a
// function_table miss at forward time.
func ValidateFunction(function uint8) error {
	if function != FunctionEndDT46 && function != FunctionEndDT2 {
		return fmt.Errorf("uformat: function %#x is not a defined Function value (want %#x or %#x)",
			function, uint8(FunctionEndDT46), uint8(FunctionEndDT2))
	}
	return nil
}

// ValidateArgument returns an error if argument is outside its valid range,
// which includes rejecting the reserved 0x000 that must never be registered
// into vrf_table. A registration-time check only: the datapath's fixed-offset
// read never rejects any 12-bit value.
func ValidateArgument(argument uint16) error {
	if argument < ArgumentMin || argument > ArgumentMax {
		return fmt.Errorf("uformat: argument %#x out of range [%#x,%#x]", argument, uint16(ArgumentMin), uint16(ArgumentMax))
	}
	return nil
}

// as16 returns addr's raw 16 bytes, or an error if addr is not a 16-byte
// IPv6 address.
func as16(addr netip.Addr) ([16]byte, error) {
	if !addr.Is6() {
		return [16]byte{}, fmt.Errorf("uformat: %s is not a 16-byte IPv6 address", addr)
	}
	return addr.As16(), nil
}

// Block returns the 48-bit uSID Block at bits 1-48 of addr, read directly
// at its fixed offset with no shift of the address itself.
func Block(addr netip.Addr) (uint64, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:8]) >> NodeIDBits, nil
}

// NodeID returns the 16-bit Node-ID at bits 49-64 of addr.
func NodeID(addr netip.Addr) (uint16, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[6:8]), nil
}

// Function returns the 4-bit Function at bits 65-68 of addr, the upper nibble
// of byte 8, read from the unmutated address. It is not checked against
// ValidateFunction: a caller on the packet-read path should let the subsequent
// function_table lookup fail rather than reject the value here.
func Function(addr netip.Addr) (uint8, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return b[8] >> 4, nil
}

// Argument returns the 12-bit Argument at bits 69-80 of addr, the lower nibble
// of byte 8 plus byte 9, read from the unmutated address. It is never itself
// part of a match key, and no 12-bit value is rejected here; a caller that must
// reject the reserved 0x000 calls ValidateArgument.
func Argument(addr netip.Addr) (uint16, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return uint16(b[8]&0x0F)<<8 | uint16(b[9]), nil
}

// Decode extracts every uFMT 48+16 field from addr at its fixed offset. It
// returns an error if addr is not a 16-byte IPv6 address, or if the 48-bit
// padding tail is non-zero. That is a structural check, distinct from the
// semantic range checks Validate performs and Decode does not.
func Decode(addr netip.Addr) (Fields, error) {
	b, err := as16(addr)
	if err != nil {
		return Fields{}, err
	}
	for i := 10; i < 16; i++ {
		if b[i] != 0 {
			return Fields{}, fmt.Errorf("uformat: %s has non-zero padding at byte %d (bits 81-128 must be zero)", addr, i)
		}
	}
	return Fields{
		Block:    binary.BigEndian.Uint64(b[:8]) >> NodeIDBits,
		NodeID:   binary.BigEndian.Uint16(b[6:8]),
		Function: b[8] >> 4,
		Argument: uint16(b[8]&0x0F)<<8 | uint16(b[9]),
	}, nil
}

// Encode constructs a uFMT 48+16 address from f, placing each field at its
// fixed offset with zero padding in the tail. It errors when Block, Function, or
// Argument overflow their field width, but does not enforce the narrower
// semantic ranges, so a caller can build a synthetic or deliberately reserved
// address here and validate separately when the value is meant to be
// registered.
func Encode(f Fields) (netip.Addr, error) {
	if err := ValidateBlock(f.Block); err != nil {
		return netip.Addr{}, err
	}
	if f.Function > 0x0F {
		return netip.Addr{}, fmt.Errorf("uformat: function %#x overflows the 4-bit Function field", f.Function)
	}
	if f.Argument > ArgumentMax {
		return netip.Addr{}, fmt.Errorf("uformat: argument %#x overflows the 12-bit Argument field", f.Argument)
	}

	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], f.Block<<NodeIDBits|uint64(f.NodeID))
	b[8] = (f.Function << 4) | (byte(f.Argument>>8) & 0x0F)
	b[9] = byte(f.Argument)
	// bytes 10-15 remain zero (padding).
	return netip.AddrFrom16(b), nil
}

// LocatorKey is the 64-bit exact-match key for locator_table: bits 1-64 of a
// uSID address, Block and Node-ID, read with no shift. Every address sharing a
// Block and Node-ID yields the same key whatever its Function and Argument,
// which is what a /64 match needs.
type LocatorKey uint64

// LocatorKeyFromAddr composes the locator_table key directly from a uSID
// address — the raw top 8 bytes, read once with no shift.
func LocatorKeyFromAddr(addr netip.Addr) (LocatorKey, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return LocatorKey(binary.BigEndian.Uint64(b[:8])), nil
}

// NewLocatorKey composes a locator_table key from a Block and Node-ID directly,
// without a full address, for registering a locator from CRD state rather than
// from a packet.
func NewLocatorKey(block uint64, nodeID uint16) (LocatorKey, error) {
	if err := ValidateBlock(block); err != nil {
		return 0, err
	}
	return LocatorKey(block<<NodeIDBits | uint64(nodeID)), nil
}

// FunctionKey is the 52-bit exact-match key for function_table: Block in the
// high bits and Function in the low bits, in the low 52 bits of a uint64.
//
// Block and Function are not adjacent in the wire address, with Node-ID between
// them, so this key is always composed from two independently read values
// rather than one contiguous span. The Block must be carried forward from the
// locator_table match, or re-read from the still-unmutated packet, and combined
// with a freshly read Function.
type FunctionKey uint64

// FunctionKeyFromAddr composes the function_table key from a uSID address, by
// reading Block and Function independently at their fixed offsets and combining
// them.
func FunctionKeyFromAddr(addr netip.Addr) (FunctionKey, error) {
	block, err := Block(addr)
	if err != nil {
		return 0, err
	}
	function, err := Function(addr)
	if err != nil {
		return 0, err
	}
	return NewFunctionKey(block, function)
}

// NewFunctionKey composes a function_table key from a Block and Function
// value directly.
func NewFunctionKey(block uint64, function uint8) (FunctionKey, error) {
	if err := ValidateBlock(block); err != nil {
		return 0, err
	}
	if function > 0x0F {
		return 0, fmt.Errorf("uformat: function %#x overflows the 4-bit Function field", function)
	}
	return FunctionKey(block<<FunctionBits | uint64(function)), nil
}

// VRFKey is the composite exact-match key for vrf_table: Block in the high bits
// and Argument in the low bits, in the low 60 bits of a uint64.
//
// Block is part of the key rather than Argument alone, so two Blocks can each
// hold an independently matched entry for the same Argument during a
// make-before-break migration.
//
// Block and Argument are not adjacent in the wire address either, with Node-ID
// and Function between them, so like FunctionKey this is always composed from
// two independently read values.
type VRFKey uint64

// VRFKeyFromAddr composes the vrf_table key from a uSID address, by reading
// Block and Argument independently at their fixed offsets and combining them.
func VRFKeyFromAddr(addr netip.Addr) (VRFKey, error) {
	block, err := Block(addr)
	if err != nil {
		return 0, err
	}
	argument, err := Argument(addr)
	if err != nil {
		return 0, err
	}
	return NewVRFKey(block, argument)
}

// NewVRFKey composes a vrf_table key from a Block and Argument directly,
// without a full address, for registering from CNI-supplied values rather than
// from a packet. It bounds-checks only that argument fits the 12-bit field and
// does not reject the reserved 0x000; a caller that must enforce that calls
// ValidateArgument first.
func NewVRFKey(block uint64, argument uint16) (VRFKey, error) {
	if err := ValidateBlock(block); err != nil {
		return 0, err
	}
	if argument > ArgumentMax {
		return 0, fmt.Errorf("uformat: argument %#x overflows the 12-bit Argument field", argument)
	}
	return VRFKey(block<<ArgumentBits | uint64(argument)), nil
}
