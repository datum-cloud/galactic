// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// TestFlowHash_ConsecutivePortsSpreadAcrossBackends checks that a client's
// consecutive source ports spread over a two-backend rule's Maglev table as
// evenly as a fair hash would, across many backend pairs. A run of 16 ports
// all on one backend should happen 1 time in 2^15. Without a finalizer, FNV-1a
// gave consecutive ports slots a fixed distance apart, and on some tables
// those slots kept landing on one backend: about 0.47% of runs over all
// pairs, and 27% of runs on the worst pair (#958).
func TestFlowHash_ConsecutivePortsSpreadAcrossBackends(t *testing.T) {
	const (
		pairs   = 200
		clients = 2000
		ports   = 16
		// Fair odds of 16 ports all on one of two backends: 2 * 2^-16.
		fair = 1.0 / (1 << 15)
		// No single pair may put a run on one backend more than this often.
		worstPerPair = 0.01
	)
	r := rand.New(rand.NewPCG(958, 1))

	pick := func(table *[edgemap.MaglevTableSize]byte, addr [16]byte, port uint16) byte {
		return table[edgeprog.FlowHash(addr, port)%edgemap.MaglevTableSize]
	}
	oneBackend := func(table *[edgemap.MaglevTableSize]byte, addr [16]byte, port func(int) uint16) bool {
		first := pick(table, addr, port(0))
		for i := 1; i < ports; i++ {
			if pick(table, addr, port(i)) != first {
				return false
			}
		}
		return true
	}

	var consecutive, random int
	for p := range pairs {
		backends := []DesiredBackend{
			{Address: randomAddr(r, false), Port: 8443},
			{Address: randomAddr(r, false), Port: 8443},
		}
		_, table, err := buildMaglevTable(DesiredRule{Key: "ns/svc"}, backends)
		if err != nil {
			t.Fatalf("pair %d: buildMaglevTable: %v", p, err)
		}

		var pairConsecutive int
		for c := range clients {
			addr := randomAddr(r, c%2 == 0).As16()
			base := uint16(1024 + r.IntN(65536-1024-ports))
			if oneBackend(&table, addr, func(i int) uint16 { return base + uint16(i) }) {
				pairConsecutive++
			}
			if oneBackend(&table, addr, func(int) uint16 { return uint16(1024 + r.IntN(65536-1024)) }) {
				random++
			}
		}
		if got := float64(pairConsecutive) / clients; got > worstPerPair {
			t.Errorf("backends %v and %v: %d consecutive ports on one backend for %.2f%% of clients, want at most %.0f%%",
				backends[0].Address, backends[1].Address, ports, 100*got, 100*worstPerPair)
		}
		consecutive += pairConsecutive
	}

	runs := float64(pairs * clients)
	if got := float64(consecutive) / runs; got > 3*fair {
		t.Errorf("%d consecutive ports on one backend for %.4f%% of clients, "+
			"want at most %.4f%% (3 times fair; random ports: %.4f%%)",
			ports, 100*got, 300*fair, 100*float64(random)/runs)
	}
}

// randomAddr returns a random IPv6 address, or an IPv4 address in its
// IPv4-mapped form when v4 is set, as the datapath hashes an IPv4 client.
func randomAddr(r *rand.Rand, v4 bool) netip.Addr {
	if v4 {
		var b [4]byte
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return netip.AddrFrom16(netip.AddrFrom4(b).As16())
	}
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return netip.AddrFrom16(b)
}
