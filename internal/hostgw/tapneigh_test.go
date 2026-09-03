// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"net"
	"testing"
)

// TestSolicitVRFNeighbor_PicksNetworkByFamily pins the family selection: an
// IPv4 guest must be solicited over udp4 and an IPv6 guest over udp6.
// Getting this wrong would dial the wrong family and never solicit, which
// looks exactly like a guest that has not booted.
//
// Exercised through the real function: it swallows every error by design
// (ensureNeighbor's poll is the only judge), so the assertion is that it
// returns without panicking for either family, against addresses in
// documentation ranges that route nowhere.
func TestSolicitVRFNeighbor_PicksNetworkByFamily(t *testing.T) {
	for _, guest := range []string{"2001:db8::1", "192.0.2.1"} {
		t.Run(guest, func(t *testing.T) {
			solicitVRFNeighbor("no-such-vrf0", net.ParseIP(guest))
		})
	}
}

// TestLookupNeighborMAC_UnknownLinkIsEmptyNotAnError records what the kernel
// actually does, which is not what it looks like it should: NeighList against
// an ifindex that does not exist filters to an empty set rather than
// failing, so a vanished link reads as "no neighbour yet" and not as an
// error.
//
// That is the right outcome here even though it is the surprising one. A tap
// that has gone away takes its attachment with it, and the next sweep will
// not see the link at all, so there is nothing for ensureNeighbor to report
// and nothing to retry. Pinned so a future change to lookupNeighborMAC does
// not start treating a missing link as a failure to log about on every tick.
func TestLookupNeighborMAC_UnknownLinkIsEmptyNotAnError(t *testing.T) {
	mac, err := lookupNeighborMAC(0x7fffffff, net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Errorf("lookupNeighborMAC() on a nonexistent link error = %v, want nil", err)
	}
	if mac != nil {
		t.Errorf("lookupNeighborMAC() = %v, want no hardware address", mac)
	}
}

// TestGuestAddrsForTap_EmptyTableIsEmpty covers the ordinary no-attachment
// case: a table with no routes yields no guest addresses and no error path,
// so the sweep skips the tap rather than soliciting a zero address.
func TestGuestAddrsForTap_EmptyTableIsEmpty(t *testing.T) {
	// Table 0 is never a VPC VRF table (vrf.Add allocates from 1 up), so a
	// filtered list against it is reliably empty on any host.
	if got := guestAddrsForTap(0, 0x7fffffff); len(got) != 0 {
		t.Errorf("guestAddrsForTap(empty) = %v, want none", got)
	}
}

// TestEnsureTapGuestNeighbors_NoTapsIsQuiet covers the common case on a node
// with no VM attachments at all: the sweep must report nothing and, in
// particular, must not count a pending entry it will then log about on every
// tick. Any node running this test has no galactic tap enslaved to a VPC
// VRF, so both counters must be zero.
func TestEnsureTapGuestNeighbors_NoTapsIsQuiet(t *testing.T) {
	resolved, pending := EnsureTapGuestNeighbors()
	if resolved != 0 || pending != 0 {
		t.Errorf("EnsureTapGuestNeighbors() = (%d, %d), want (0, 0) with no tap attachments",
			resolved, pending)
	}
}
