// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// maxSupportedPrefixLen is the boundary RFC 6296 sets: prefixes this length or
// shorter place the adjustment at a fixed word. Longer ones need the
// per-address scheme this package does not implement.
const maxSupportedPrefixLen = 48

// adjustmentWordOffset is the byte offset of the 16-bit word the checksum
// adjustment is folded into, for prefixes within the supported length.
const adjustmentWordOffset = 6

// Mapping is one VRF's stateless prefix translation: an address in ULAPrefix
// translates, checksum-neutrally and in both directions, to the corresponding
// address in PublicPrefix.
type Mapping struct {
	// ULAPrefix is the tenant-facing IPv6 ULA prefix, as presented by
	// backends inside the VRF.
	ULAPrefix *net.IPNet

	// PublicPrefix is the externally routable prefix ULAPrefix translates to
	// and from. It must share ULAPrefix's length, translation only ever
	// rewriting the shared prefix and never host bits.
	PublicPrefix *net.IPNet
}

// prefixLen validates that both prefixes are set, both IPv6, share a length,
// and that the length is supported, and returns that shared length.
func (m Mapping) prefixLen() (int, error) {
	if m.ULAPrefix == nil || m.PublicPrefix == nil {
		return 0, errors.New("nptv6: ULAPrefix and PublicPrefix are both required")
	}
	ulaOnes, ulaBits := m.ULAPrefix.Mask.Size()
	pubOnes, pubBits := m.PublicPrefix.Mask.Size()
	if ulaBits != 128 || pubBits != 128 {
		return 0, errors.New("nptv6: ULAPrefix and PublicPrefix must both be IPv6 (/128-bit mask) CIDRs")
	}
	if ulaOnes != pubOnes {
		return 0, fmt.Errorf("nptv6: ULAPrefix length /%d and PublicPrefix length /%d must match", ulaOnes, pubOnes)
	}
	if ulaOnes > maxSupportedPrefixLen {
		return 0, fmt.Errorf(
			"nptv6: prefix length /%d exceeds the supported maximum /%d (RFC 6296 §3.5's longer-prefix "+
				"IID-word scheme is not implemented)", ulaOnes, maxSupportedPrefixLen)
	}
	return ulaOnes, nil
}

// Adjustment precomputes the checksum-neutral adjustment for m, once, on the
// control plane. Translate applies it as a cheap add or subtract rather than
// recomputing it per packet.
func (m Mapping) Adjustment() (uint16, error) {
	if _, err := m.prefixLen(); err != nil {
		return 0, err
	}
	intChecksum := prefixChecksum(m.ULAPrefix.IP)
	pubChecksum := prefixChecksum(m.PublicPrefix.IP)
	// RFC 6296 §3.6: adjustment = external checksum - internal checksum,
	// in 1's-complement arithmetic (subtraction = add the complement).
	return onesComplementAdd(pubChecksum, ^intChecksum), nil
}

// Translate applies m to addr. outbound true translates a ULA address to its
// public counterpart, adding the adjustment; false translates the reverse,
// subtracting it. A pure function: the same inputs always produce the same
// output.
func Translate(m Mapping, addr net.IP, outbound bool) (net.IP, error) {
	length, err := m.prefixLen()
	if err != nil {
		return nil, err
	}

	addr16 := addr.To16()
	if addr16 == nil || addr.To4() != nil {
		return nil, fmt.Errorf("nptv6: %v is not an IPv6 address", addr)
	}

	from, to := m.PublicPrefix, m.ULAPrefix
	if outbound {
		from, to = m.ULAPrefix, m.PublicPrefix
	}
	if !from.Contains(addr16) {
		return nil, fmt.Errorf("nptv6: address %v is not within %v", addr, from)
	}

	result := make(net.IP, net.IPv6len)
	copy(result, addr16)
	copyPrefixBits(result, to.IP, length)

	adjustment, err := m.Adjustment()
	if err != nil {
		return nil, err
	}
	word := binary.BigEndian.Uint16(result[adjustmentWordOffset : adjustmentWordOffset+2])
	if outbound {
		word = onesComplementAdd(word, adjustment)
	} else {
		word = onesComplementAdd(word, ^adjustment)
	}
	binary.BigEndian.PutUint16(result[adjustmentWordOffset:adjustmentWordOffset+2], word)

	return result, nil
}

// prefixChecksum computes the one's-complement checksum of prefix's first 48
// bits, summing with end-around carry and complementing.
//
// prefix is assumed already zero-padded beyond its configured length, which any
// parsed CIDR is, so a prefix shorter than 48 bits contributes zero for its
// unused high-order words.
func prefixChecksum(prefix net.IP) uint16 {
	ip := prefix.To16()
	var sum uint32
	for i := 0; i < 6; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// onesComplementAdd adds a and b with end-around carry, the same arithmetic a
// checksum update uses and what the RFC means by one's-complement arithmetic
// for both computing the adjustment and applying it. Subtraction is addition of
// the complement.
func onesComplementAdd(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// copyPrefixBits overwrites dst's first prefixLen bits with src's, leaving every
// later bit in dst untouched. Both must be 16-byte slices.
func copyPrefixBits(dst, src net.IP, prefixLen int) {
	fullBytes := prefixLen / 8
	copy(dst[:fullBytes], src[:fullBytes])

	if remBits := prefixLen % 8; remBits != 0 {
		mask := byte(0xFF << (8 - remBits))
		dst[fullBytes] = (src[fullBytes] & mask) | (dst[fullBytes] &^ mask)
	}
}
