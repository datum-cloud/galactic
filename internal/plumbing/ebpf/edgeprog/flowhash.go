// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

// Affinity values mirror the datapath's EDGE_AFFINITY_* defines, hand-kept in
// sync since a C define has no BTF representation to generate a constant
// from. They are vip_value's affinity byte, and select what FlowHash hashes
// besides the client's address.
const (
	// AffinityNone hashes the client's address and source port.
	AffinityNone uint8 = 0
	// AffinityClientIP hashes the client's address only.
	AffinityClientIP uint8 = 1
	// AffinityClientIPAndProtocol hashes the client's address and L4 protocol.
	AffinityClientIPAndProtocol uint8 = 2
)

// FlowHash mirrors the datapath's flow_hash, hand-kept in sync with the C
// source: the hash edge_lb takes modulo the Maglev table size to pick a
// client's slot. addr is the client's address in its 16-byte form, an IPv4
// address IPv4-mapped, affinity is the rule's Affinity value, proto the L4
// protocol number and port the client's source port. Only the inputs affinity
// selects are hashed; an unknown affinity hashes as AffinityNone. It exists so
// a test or tool can predict the backend a gateway picks for a flow.
//
// It is 32-bit FNV-1a over addr, then the port in network byte order
// (AffinityNone), nothing (AffinityClientIP) or proto
// (AffinityClientIPAndProtocol), then murmur3's fmix32 finalizer.
func FlowHash(addr [16]byte, affinity, proto uint8, port uint16) uint32 {
	const (
		fnvOffset = 2166136261
		fnvPrime  = 16777619
	)
	h := uint32(fnvOffset)
	for _, b := range addr {
		h ^= uint32(b)
		h *= fnvPrime
	}
	switch affinity {
	case AffinityClientIP:
	case AffinityClientIPAndProtocol:
		h ^= uint32(proto)
		h *= fnvPrime
	default:
		h ^= uint32(port >> 8)
		h *= fnvPrime
		h ^= uint32(port & 0xff)
		h *= fnvPrime
	}

	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
