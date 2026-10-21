// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

// FlowHash mirrors the datapath's flow_hash, hand-kept in sync with the C
// source: the hash edge_lb takes modulo the Maglev table size to pick a
// client's slot. addr is the client's address in its 16-byte form, an IPv4
// address IPv4-mapped, and port is the client's source port. It exists so a
// test or tool can predict the backend a gateway picks for a flow.
//
// It is 32-bit FNV-1a over addr and port in network byte order, then
// murmur3's fmix32 finalizer.
func FlowHash(addr [16]byte, port uint16) uint32 {
	const (
		fnvOffset = 2166136261
		fnvPrime  = 16777619
	)
	h := uint32(fnvOffset)
	for _, b := range addr {
		h ^= uint32(b)
		h *= fnvPrime
	}
	h ^= uint32(port >> 8)
	h *= fnvPrime
	h ^= uint32(port & 0xff)
	h *= fnvPrime

	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
