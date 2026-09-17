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

// functionNibble maps an SRv6Function to its 4-bit uFMT 48+16 Function value.
// End.DT46 is the only accepted value: it is the only endpoint behavior the
// eBPF datapath installs, whatever the pod subnet's address family, and the
// shared Function/Argument slot has no distinct code for a per-family
// variant. Any other function is an error.
func functionNibble(fn bgpv1alpha1.SRv6Function) (uint8, error) {
	if fn == bgpv1alpha1.SRv6FunctionEndDT46 {
		return uformat.FunctionEndDT46, nil
	}
	return 0, fmt.Errorf("unsupported SRv6 function %q for uFMT 48+16 encoding", fn)
}

// ComputeSID derives the compressed SRv6 uSID for a (locator, nodeID,
// argument, function) tuple in the uFMT 48+16 REPLACE-CSID layout of RFC 9800
// §4.2.7:
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
// locator must be an IPv6 /48; nodeID and argument must fit their fields.
// Returns the full 128-bit SID, or an error naming the field that is out of
// range. See internal/plumbing/ebpf/uformat for the encode primitives.
func ComputeSID(locator string, nodeID, argument int32, function bgpv1alpha1.SRv6Function) (netip.Addr, error) {
	block, err := nodeIdentity(locator, nodeID)
	if err != nil {
		return netip.Addr{}, err
	}
	if argument < uformat.ArgumentMin || argument > uformat.ArgumentMax {
		return netip.Addr{}, fmt.Errorf(
			"argument %d out of range [%#x,%#x]", argument, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	fn, err := functionNibble(function)
	if err != nil {
		return netip.Addr{}, err
	}

	return uformat.Encode(uformat.Fields{
		Block:    block,
		NodeID:   uint16(nodeID),
		Function: fn,
		Argument: uint16(argument),
	})
}

// nodeIdentity validates locator and nodeID as the node-identifying half of a
// uSID -- bits 1-48 and 49-64 -- and returns the Block they encode. Shared by
// every SID this package builds, so a SID and the base it is completed from
// cannot disagree about which node they name.
func nodeIdentity(locator string, nodeID int32) (uint64, error) {
	prefix, err := netip.ParsePrefix(locator)
	if err != nil {
		return 0, fmt.Errorf("parse SRv6 locator %q: %w", locator, err)
	}
	if !prefix.Addr().Is6() {
		return 0, fmt.Errorf("SRv6 locator %q is not an IPv6 prefix", locator)
	}
	if prefix.Bits() != uformat.BlockBits {
		return 0, fmt.Errorf(
			"SRv6 locator %q must be a /%d uSID Block, got /%d", locator, uformat.BlockBits, prefix.Bits())
	}
	if nodeID < uformat.NodeIDMin || nodeID > uformat.NodeIDMax {
		return 0, fmt.Errorf(
			"nodeID %d out of range [%#x,%#x]", nodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return 0, fmt.Errorf("derive uSID Block from locator %q: %w", locator, err)
	}
	return block, nil
}

// NodeSIDBase derives the value usid_egress stores in node_src_addr_table and
// completes per packet: this node's own End.DT46 SID with the Argument field
// left zero. It shares nodeIdentity and uformat.Encode with ComputeSID, so a
// completed base and the SID that attachment advertises cannot drift apart.
//
// The Argument is deliberately absent. It identifies the tenant VRF a SID's
// decapsulated traffic resolves to, and the datapath already holds the right
// one for the packet in front of it, from the attachment that packet arrived
// on. Completing the base there costs two byte writes and keeps this a
// per-node constant, where a fully formed SID would have to be stored and
// garbage-collected per VRF.
//
// The result is never a usable SID on its own: Argument 0x000 is reserved and
// vrf_table must always miss it, so a base that reached the wire unchanged is
// dropped by the receiving node rather than delivered to an arbitrary tenant.
//
// locator must be an IPv6 /48 and nodeID must fit its field; both are checked
// the same way ComputeSID checks them.
func NodeSIDBase(locator string, nodeID int32) (netip.Addr, error) {
	block, err := nodeIdentity(locator, nodeID)
	if err != nil {
		return netip.Addr{}, err
	}

	return uformat.Encode(uformat.Fields{
		Block:    block,
		NodeID:   uint16(nodeID),
		Function: uformat.FunctionEndDT46,
		Argument: 0,
	})
}
