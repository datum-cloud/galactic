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

// maxSupportedPrefixLen is RFC 6296 §3.4's boundary: prefixes of this
// length or shorter place the adjustment at a fixed word (bits 48..63).
// Longer prefixes need §3.5's per-address IID-word scheme — see doc.go.
const maxSupportedPrefixLen = 48

// adjustmentWordOffset is the byte offset of the 16-bit word (bits 48..63)
// RFC 6296 §3.4 fixes the checksum adjustment into, for prefixes of length
// maxSupportedPrefixLen or shorter.
const adjustmentWordOffset = 6

// Mapping is one VRF's stateless RFC 6296 prefix translation: backends
// presenting an address in ULAPrefix are translated, checksum-neutrally and
// bidirectionally, to the corresponding address in PublicPrefix.
type Mapping struct {
	// ULAPrefix is the tenant-facing IPv6 ULA prefix, as presented by
	// backends inside the VRF.
	ULAPrefix *net.IPNet

	// PublicPrefix is the externally-routable prefix ULAPrefix translates
	// to/from. Must share ULAPrefix's own prefix length — RFC 6296
	// translation only ever rewrites the shared prefix, never host bits.
	PublicPrefix *net.IPNet
}

// prefixLen validates that ULAPrefix/PublicPrefix are both set, both IPv6,
// share an identical prefix length, and that length is within this
// package's supported range (see doc.go). Returns the shared length.
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

// Adjustment precomputes the RFC 6296 §3.6 checksum-neutral adjustment
// value for m, control-plane side, once — Translate applies it as a cheap
// 1's-complement add/subtract, never recomputing it per packet.
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

// Translate applies m to addr. outbound=true translates a ULAPrefix address
// to its PublicPrefix counterpart (the internal-to-external direction, RFC
// 6296 §3.4 — adjustment is added); outbound=false translates the reverse
// direction (adjustment is subtracted). Pure function, no state: the
// identical (m, addr, outbound) input always produces the identical output.
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

// prefixChecksum computes the RFC 1071-style 1's-complement checksum (sum
// with end-around carry, then bitwise complement) of prefix's first 48
// bits (3 big-endian 16-bit words) — RFC 6296 §3.6's "one's complement
// checksum of the prefix". prefix is assumed already zero-padded beyond its
// own configured length (true of any net.IPNet.IP produced by
// net.ParseCIDR), so a prefix shorter than 48 bits contributes zero words
// for its own unused high-order bits, matching the RFC's worked example.
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

// onesComplementAdd adds a and b using 1's-complement (end-around-carry)
// arithmetic — the same construction an IP/TCP checksum update uses, and
// what RFC 6296 §3.6 means by "using one's complement arithmetic" for both
// the adjustment computation and its application (subtraction is addition
// of the bitwise complement).
func onesComplementAdd(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// copyPrefixBits overwrites dst's first prefixLen bits with src's first
// prefixLen bits, leaving every bit at position >= prefixLen in dst
// untouched. Both dst and src must be 16-byte (net.IPv6len) slices.
func copyPrefixBits(dst, src net.IP, prefixLen int) {
	fullBytes := prefixLen / 8
	copy(dst[:fullBytes], src[:fullBytes])

	if remBits := prefixLen % 8; remBits != 0 {
		mask := byte(0xFF << (8 - remBits))
		dst[fullBytes] = (src[fullBytes] & mask) | (dst[fullBytes] &^ mask)
	}
}
