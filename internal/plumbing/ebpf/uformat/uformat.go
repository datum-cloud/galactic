// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package uformat implements the pure-Go bit-layout primitives for the
// `uFMT 48+16` SRv6 uSID carrier format specified in
// datum-cloud/enhancements#740 ("Option 2 — Shared 16-bit Slot") and
// consumed by the eBPF/TC-BPF datapath described in
// .local/plan-ebpf-xdp-usid-datapath.md. It has no kernel, cgo, or BPF
// dependency: it only encodes/decodes the fixed-bit-offset fields inside a
// 128-bit uSID address and derives the map keys the datapath's
// locator_table and function_table use.
//
// Bit layout (RFC 9800 REPLACE-CSID flavor; see the design plan's R2 and
// its "why R2 departs from PR #740's original shift wording" call-out for
// why nothing here ever shifts the address):
//
//	bit  1                  48 49              64 65   68 69          80 81                  128
//	     |------ uSID Block (48) ------|-- Node-ID (16) --|-Fn(4)-|-- Argument (12) --|------ Padding (48, zero) ------|
//
// Byte layout of the 16-byte address (bit 1 is the MSB of byte 0, matching
// [net/netip.Addr.As16]'s network-byte-order convention):
//
//	bytes 0-5   (48 bits) Block
//	bytes 6-7   (16 bits) Node-ID
//	byte  8 hi  ( 4 bits) Function
//	byte 8 lo + byte 9 (12 bits) Argument
//	bytes 10-15 (48 bits) Padding (must be zero)
//
// Every accessor in this package reads (or writes) its field at that
// field's fixed offset only. There is deliberately no bit-shift of the
// address anywhere in this package (design plan R2): Block, Node-ID,
// Function, and Argument are always independently readable at their fixed
// offsets from an unmutated address, and locator_table/function_table keys
// are built by directly copying or composing those fixed-offset reads, not
// by shifting the address to bring a field into a canonical position.
//
// Placement note: this package lives under internal/plumbing/ebpf/ rather
// than as a sibling of internal/plumbing/{srv6,vrf,intf,sysctl} directly,
// because the eBPF datapath work is a multi-milestone effort (design plan
// §4, §6) that needs more than one package — this one (pure-Go bit layout,
// Milestone 2.1), the BPF program sources and generated bindings
// (Milestone 2.2), and the load/attach/reconcile control daemon logic
// (Milestone 3.x) all belong under one ebpf/ umbrella rather than
// individually crowding internal/plumbing's top level. uformat has no
// dependency on the other two and can be imported on its own.
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

	// NodeIDMin and NodeIDMax bound PR #740's reserved Node-ID range.
	// 0xE000-0xFFFF belongs to the Function/Argument universe, not to
	// Node-ID (design plan §10, "Node-ID range not validated anywhere").
	NodeIDMin = 0x0001
	NodeIDMax = 0xDFFF

	// FunctionEndDT46 and FunctionEndDT2 are the only two Function values
	// PR #740 defines today (design plan R3): 0xE selects the L3
	// uEnd.DT46 behavior this plan builds; 0xF is reserved for a future
	// uEnd.DT2 (L2) behavior and must not be blocked by this code.
	FunctionEndDT46 = 0xE
	FunctionEndDT2  = 0xF

	// ArgumentMin and ArgumentMax bound the valid Argument range.
	// Argument 0x000 is reserved by PR #740 and must never be registered
	// into vrf_table (design plan R4, §5.1) — ValidateArgument rejects it.
	ArgumentMin = 0x001
	ArgumentMax = 0xFFF // 12-bit max
)

// Fields is the fully decoded set of uFMT 48+16 fields carried by a single
// uSID address. Block and NodeID occupy their full width (uint64/uint16);
// Function and Argument are stored right-justified in wider integer types
// with only their low 4 / 12 bits significant.
type Fields struct {
	Block    uint64
	NodeID   uint16
	Function uint8
	Argument uint16
}

// Validate returns a non-nil error if any field violates its documented
// range: Block > BlockMax, Node-ID outside [NodeIDMin,NodeIDMax], Function
// not one of the defined enum values, or Argument outside
// [ArgumentMin,ArgumentMax] (which alone excludes the reserved zero value —
// R4, §5.1). Decode does not call this automatically — callers validate
// explicitly at the point a value is about to be registered into a map
// (design plan §5.1), never on the datapath's packet-read path itself.
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

// ValidateNodeID returns an error if nodeID falls outside PR #740's
// reserved Node-ID range 0x0001-0xDFFF.
func ValidateNodeID(nodeID uint16) error {
	if nodeID < NodeIDMin || nodeID > NodeIDMax {
		return fmt.Errorf("uformat: node-id %#x out of range [%#x,%#x]", nodeID, uint16(NodeIDMin), uint16(NodeIDMax))
	}
	return nil
}

// ValidateFunction returns an error unless function is one of the two
// Function values PR #740 defines today: FunctionEndDT46 (0xE) or
// FunctionEndDT2 (0xF, reserved for future L2 use — design plan R3). This
// is a registration-time check only — the datapath itself never validates
// Function against this enum; an unrecognized Function is instead detected
// as a function_table miss at forward time (design plan §4.2 step 4).
func ValidateFunction(function uint8) error {
	if function != FunctionEndDT46 && function != FunctionEndDT2 {
		return fmt.Errorf("uformat: function %#x is not a defined Function value (want %#x or %#x)",
			function, uint8(FunctionEndDT46), uint8(FunctionEndDT2))
	}
	return nil
}

// ValidateArgument returns an error if argument is outside
// [ArgumentMin,ArgumentMax]. This includes rejecting the reserved value
// 0x000, which PR #740 forbids ever registering into vrf_table (design
// plan R4, §5.1). Per R4, the datapath's fixed-offset packet read
// (Argument, below) never itself rejects any 12-bit value at forward
// time — this validation applies only at registration time.
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

// Function returns the 4-bit Function at bits 65-68 of addr — the upper
// nibble of byte 8 — read directly from the unmutated address (design plan
// R2). The returned value is not checked against ValidateFunction; callers
// on the packet-read path should not reject it, only fail the subsequent
// function_table lookup.
func Function(addr netip.Addr) (uint8, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return b[8] >> 4, nil
}

// Argument returns the 12-bit Argument at bits 69-80 of addr — the lower
// nibble of byte 8 plus all of byte 9 — read directly from the unmutated
// address (design plan R2, R4). This value is never itself part of a match
// key and this function never rejects any 12-bit value; callers that need
// to reject the reserved 0x000 (e.g. before a vrf_table registration) call
// ValidateArgument separately.
func Argument(addr netip.Addr) (uint16, error) {
	b, err := as16(addr)
	if err != nil {
		return 0, err
	}
	return uint16(b[8]&0x0F)<<8 | uint16(b[9]), nil
}

// Decode extracts every uFMT 48+16 field from addr at its fixed bit
// offset. It returns an error if addr is not a 16-byte IPv6 address, or if
// the 48-bit zero-padding tail (bits 81-128) is non-zero — a structural
// format check, distinct from the semantic range checks in Validate*
// (which Decode does not call).
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

// Encode constructs a uFMT 48+16 IPv6 address from f, placing each field at
// its fixed bit offset with zero padding in bits 81-128. It returns an
// error if Block, Function, or Argument overflow their field width; it
// does not enforce the narrower semantic ranges in Validate* (e.g.
// Argument 0x000 or an out-of-range Node-ID), so callers can construct
// synthetic/placeholder or intentionally-reserved test addresses through
// this function and validate separately when a value is meant to be
// registered for real.
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
	b[8] = f.Function<<4 | byte(f.Argument>>8)&0x0F
	b[9] = byte(f.Argument)
	// bytes 10-15 remain zero (padding).
	return netip.AddrFrom16(b), nil
}

// LocatorKey is the 64-bit exact-match key for the locator_table map: bits
// 1-64 of a uSID address (Block(48) + Node-ID(16)), read directly with no
// shift. Every address sharing the same Block and Node-ID produces the
// same LocatorKey regardless of Function/Argument, which is exactly the
// property R1's "/64 match, not /128" needs.
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

// NewLocatorKey composes a locator_table key from a Block and Node-ID
// value directly, without needing a full address — used by the control
// daemon (Milestone 3.x) when registering a locator from BGPRouter CRD
// state rather than from a packet.
func NewLocatorKey(block uint64, nodeID uint16) (LocatorKey, error) {
	if err := ValidateBlock(block); err != nil {
		return 0, err
	}
	return LocatorKey(block<<NodeIDBits | uint64(nodeID)), nil
}

// FunctionKey is the 52-bit exact-match key for the function_table map:
// Block(48) in the high bits, Function(4) in the low bits, stored in the
// low 52 bits of a uint64 (the top 12 bits are always zero). Block and
// Function are never adjacent bit ranges in the wire address — Node-ID
// sits between them at bits 49-64 — so this key is always composed from
// two independently-obtained values, never read as a single contiguous
// span (design plan §4.2 step 3/4; the Block value must be carried forward
// as program state from the locator_table match, or re-read directly from
// the still-unmutated packet, and combined with a freshly read Function).
type FunctionKey uint64

// FunctionKeyFromAddr composes the function_table key directly from a
// uSID address, by independently reading Block (bits 1-48) and Function
// (bits 65-68) at their fixed offsets and then combining them — never as a
// single contiguous span.
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

// VRFKey is the composite exact-match key for the vrf_table map: uSID
// Block(48) in the high bits, Argument(12) in the low bits, stored in the
// low 60 bits of a uint64 (design plan §4.4; R8 -- Block is part of the
// key, not Argument alone, so two Blocks can each hold an independently
// counted, independently matched entry for the same Argument value during
// a make-before-break migration). Block and Argument are never adjacent
// bit ranges in the wire address either -- Node-ID and Function sit
// between them at bits 49-68 -- so, like FunctionKey, this key is always
// composed from two independently obtained values, never read as a single
// contiguous span.
//
// Milestone 2.1 deliberately left this constructor unbuilt (see
// prog/usid_test.go's own local vrfKey helper and its comment) for
// whichever milestone needed a real, exported map-key constructor first --
// Milestone 3.3's control-daemon read/write API (internal/plumbing/ebpf/
// usidmap) is that first use.
type VRFKey uint64

// VRFKeyFromAddr composes the vrf_table key directly from a uSID address,
// by independently reading Block (bits 1-48) and Argument (bits 69-80) at
// their fixed offsets and combining them -- never as a single contiguous
// span.
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

// NewVRFKey composes a vrf_table key from a Block and Argument value
// directly, without needing a full address -- used by
// internal/plumbing/ebpf/usidmap when registering/unregistering an entry
// from CNI-supplied values rather than from a packet. Like NewFunctionKey,
// this only bounds-checks that argument fits the 12-bit field; it does not
// reject the reserved value 0x000 the way ValidateArgument does --
// callers that must enforce that (usidmap.VRFTable.Register, design plan
// R4/§5.1) validate separately before calling this.
func NewVRFKey(block uint64, argument uint16) (VRFKey, error) {
	if err := ValidateBlock(block); err != nil {
		return 0, err
	}
	if argument > ArgumentMax {
		return 0, fmt.Errorf("uformat: argument %#x overflows the 12-bit Argument field", argument)
	}
	return VRFKey(block<<ArgumentBits | uint64(argument)), nil
}
