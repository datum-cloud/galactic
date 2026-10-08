// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/plumbing/srv6"
)

// collidingAddrs returns two addresses in fd00:10::/64 whose srv6.BackendSlot
// on port is equal, found by search: a 16-bit slot space makes one turn up
// within a few hundred candidates.
func collidingAddrs(t *testing.T, port uint16) (netip.Addr, netip.Addr) {
	t.Helper()
	seen := make(map[uint16]netip.Addr)
	for i := 1; i < 1<<20; i++ {
		addr := netip.MustParseAddr(fmt.Sprintf("fd00:10::%x:%x", i>>16, i&0xffff))
		slot := srv6.BackendSlot(addr, port)
		if first, ok := seen[slot]; ok {
			return first, addr
		}
		seen[slot] = addr
	}
	t.Fatal("no two addresses share a slot")
	return netip.Addr{}, netip.Addr{}
}

func TestDropConflictingBackends(t *testing.T) {
	const port = 8443
	att := func(name string) types.NamespacedName { return types.NamespacedName{Namespace: "tenant", Name: name} }
	a, b := collidingAddrs(t, port)
	other := netip.MustParseAddr("fd00:10::ffff:1")

	backends := []ruleBackend{
		{attachment: att("first"), node: testNAT66NodeA, addr: a, port: port},
		{attachment: att("dup"), node: testNAT66NodeB, addr: a, port: port},
		{attachment: att("slot"), node: testNAT66NodeA, addr: b, port: port},
		{attachment: att("slot-elsewhere"), node: testNAT66NodeB, addr: b, port: port},
		{attachment: att("plain"), node: testNAT66NodeA, addr: other, port: port},
	}
	// The slot entry is dropped for its slot on node-a, so it claims no
	// address, and slot-elsewhere, the same address on node-b where the slot
	// is free, is kept.

	kept, rejected := dropConflictingBackends(backends)

	keptNames := make([]string, 0, len(kept))
	for _, k := range kept {
		keptNames = append(keptNames, k.attachment.Name)
	}
	if strings.Join(keptNames, ",") != "first,slot-elsewhere,plain" {
		t.Errorf("kept = %v, want [first slot-elsewhere plain]", keptNames)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v, want 2 entries", rejected)
	}
	if !strings.Contains(rejected[0], "tenant/dup: address") {
		t.Errorf("rejected[0] = %q, want the duplicate address", rejected[0])
	}
	if !strings.Contains(rejected[1], "tenant/slot: backend") || !strings.Contains(rejected[1], "shares slot") {
		t.Errorf("rejected[1] = %q, want the slot collision on the first node", rejected[1])
	}
}

// TestDropConflictingBackends_SlotOnOtherNode covers two backends whose slots
// match on different nodes: each node keys its own rows, so both are kept.
func TestDropConflictingBackends_SlotOnOtherNode(t *testing.T) {
	const port = 8443
	a, b := collidingAddrs(t, port)
	kept, rejected := dropConflictingBackends([]ruleBackend{
		{attachment: types.NamespacedName{Name: "a"}, node: testNAT66NodeA, addr: a, port: port},
		{attachment: types.NamespacedName{Name: "b"}, node: testNAT66NodeB, addr: b, port: port},
	})
	if len(kept) != 2 || len(rejected) != 0 {
		t.Errorf("kept = %d, rejected = %v, want both kept", len(kept), rejected)
	}
}
