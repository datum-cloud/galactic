// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net/netip"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// functionNibble maps an SRv6Function to its uFMT 48+16 Function value
// (uformat.FunctionEndDT46 or FunctionEndDT2). End.DT46 is the only
// officially supported value (go.datum.net/network's SRv6Function enum
// dropped End.DT4/End.DT6 entirely -- neither was ever requested by any
// caller in this codebase, and the uFMT shared Function/Argument slot has
// no distinct wire code for a per-family variant anyway, design plan R3):
// it is the only endpoint behavior the eBPF datapath's vrf_table ever
// installs, regardless of pod-subnet address family (see
// internal/cnibgp/bgp.go's registerEBPFDatapath/buildAdvertisementSpec).
func functionNibble(fn bgpv1alpha1.SRv6Function) (uint8, error) {
	if fn == bgpv1alpha1.SRv6FunctionEndDT46 {
		return uformat.FunctionEndDT46, nil
	}
	return 0, fmt.Errorf("unsupported SRv6 function %q for uFMT 48+16 encoding", fn)
}

// ComputeSID derives the compressed SRv6 uSID for a (locator, nodeID,
// argument, function) tuple in the `uFMT 48+16` REPLACE-CSID layout (RFC
// 9800 §4.2.7; datum-cloud/enhancements#740 "Option 2 — Shared 16-bit
// Slot"):
//
//	bits 1-48   uSID Block    (locator's network prefix; must be an IPv6 /48)
//	bits 49-64  Node-ID       (nodeID; BGPRouterSpec.NodeID, this router's PoP-local slot)
//	bits 65-68  Function      (functionNibble(function); the endpoint behavior)
//	bits 69-80  Argument      (argument; the 12-bit value identifying which
//	                           local Linux VRF this SID's decapped traffic
//	                           resolves to -- allocated per node, not derived
//	                           from the VPCAttachment identifier)
//	bits 81-128 Padding       (always zero)
//
// See internal/plumbing/ebpf/uformat for the field layout and the
// encode/decode primitives this delegates to.
func ComputeSID(locator string, nodeID, argument int32, function bgpv1alpha1.SRv6Function) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(locator)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse SRv6 locator %q: %w", locator, err)
	}
	if !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("SRv6 locator %q is not an IPv6 prefix", locator)
	}
	if prefix.Bits() != uformat.BlockBits {
		return netip.Addr{}, fmt.Errorf(
			"SRv6 locator %q must be a /%d uSID Block, got /%d", locator, uformat.BlockBits, prefix.Bits())
	}
	if nodeID < uformat.NodeIDMin || nodeID > uformat.NodeIDMax {
		return netip.Addr{}, fmt.Errorf(
			"nodeID %d out of range [%#x,%#x]", nodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}
	if argument < uformat.ArgumentMin || argument > uformat.ArgumentMax {
		return netip.Addr{}, fmt.Errorf(
			"argument %d out of range [%#x,%#x]", argument, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	fn, err := functionNibble(function)
	if err != nil {
		return netip.Addr{}, err
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("derive uSID Block from locator %q: %w", locator, err)
	}

	return uformat.Encode(uformat.Fields{
		Block:    block,
		NodeID:   uint16(nodeID),
		Function: fn,
		Argument: uint16(argument),
	})
}
