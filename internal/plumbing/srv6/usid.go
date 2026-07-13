// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net/netip"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// usidSuffixBits is the number of host bits ComputeSID consumes after the
// locator prefix: 8 bits NodeID + 16 bits VRFID + 8 bits Function.
const usidSuffixBits = 32

// functionByte maps an SRv6Function to the stable byte value ComputeSID
// encodes into the SID's Function octet. End.DT46 maps to 0 since it is the
// behavior CNI has always installed; the values only need to be distinct and
// are not meaningful outside this package.
func functionByte(fn bgpv1alpha1.SRv6Function) (byte, error) {
	switch fn {
	case bgpv1alpha1.SRv6FunctionEndDT46:
		return 0, nil
	case bgpv1alpha1.SRv6FunctionEndDT4:
		return 4, nil
	case bgpv1alpha1.SRv6FunctionEndDT6:
		return 6, nil
	default:
		return 0, fmt.Errorf("unknown SRv6 function %q", fn)
	}
}

// ComputeSID derives the compressed SRv6 uSID for a (locator, nodeID, vrfID,
// function) tuple, per RFC 9800 NEXT-CSID Argument addressing.
//
// The locator's network prefix is preserved unchanged and immediately
// followed by a 32-bit, byte-aligned suffix:
//
//	byte 0    NodeID   (1-254; BGPRouterSpec.NodeID, this router's PoP-local slot)
//	byte 1-2  VRFID    (1-65535, big-endian; the uSID Argument identifying the VRF)
//	byte 3    Function (functionByte(function); the endpoint behavior)
//
// remaining host bits are zeroed. locator must be an IPv6 CIDR with a
// byte-aligned prefix length that leaves room for the 32-bit suffix (e.g. a
// /48 through /96 locator).
func ComputeSID(locator string, nodeID, vrfID int32, function bgpv1alpha1.SRv6Function) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(locator)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse SRv6 locator %q: %w", locator, err)
	}
	if !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("SRv6 locator %q is not an IPv6 prefix", locator)
	}
	bits := prefix.Bits()
	if bits%8 != 0 {
		return netip.Addr{}, fmt.Errorf("SRv6 locator %q must have a byte-aligned prefix length", locator)
	}
	if bits+usidSuffixBits > 128 {
		return netip.Addr{}, fmt.Errorf(
			"SRv6 locator %q leaves no room for a %d-bit NodeID/VRFID/Function suffix", locator, usidSuffixBits)
	}
	if nodeID < 1 || nodeID > 254 {
		return netip.Addr{}, fmt.Errorf("nodeID %d out of range [1,254]", nodeID)
	}
	if vrfID < 1 || vrfID > 65535 {
		return netip.Addr{}, fmt.Errorf("vrfID %d out of range [1,65535]", vrfID)
	}
	fnByte, err := functionByte(function)
	if err != nil {
		return netip.Addr{}, err
	}

	addr := prefix.Addr().As16()
	offset := bits / 8
	addr[offset] = byte(nodeID)
	addr[offset+1] = byte(vrfID >> 8)
	addr[offset+2] = byte(vrfID)
	addr[offset+3] = fnByte
	for i := offset + 4; i < 16; i++ {
		addr[i] = 0
	}
	return netip.AddrFrom16(addr), nil
}
