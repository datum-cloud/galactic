// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"net"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

const testBlock uint64 = 0x2001_0DB8_FF01

func newTestTable(clock func() uint64) (*VipXlatTable, *fakeTable) {
	ft := newFakeTable()
	return &VipXlatTable{table: ft, clock: clock, generations: make(map[prog.UsidVipXlatKey]uint64)}, ft
}

func TestVipXlatTable_RegisterIngressAndGet(t *testing.T) {
	vt, _ := newTestTable(constClock(7))

	vip := net.ParseIP("2001:db8:5:5::100")
	backend := net.ParseIP("fd20:60::5:5")
	const vipPort, backendPort = 8080, 30080

	if err := vt.RegisterIngress(testBlock, 0x654, ProtoUDP, vip, vipPort, backend, backendPort); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x654, ProtoUDP, vipPort)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after RegisterIngress")
	}
	if entry.Block != testBlock || entry.Argument != 0x654 || entry.Proto != ProtoUDP || entry.Port != vipPort {
		t.Errorf("Get key = %+v, want block=%#x argument=0x654 proto=%d port=%d", entry.Key, testBlock, ProtoUDP, vipPort)
	}
	if !entry.Addr.Equal(backend) {
		t.Errorf("Get addr = %s, want %s (ingress row rewrites to the backend)", entry.Addr, backend)
	}
	if entry.RewritePort != backendPort {
		t.Errorf("Get rewrite port = %d, want %d", entry.RewritePort, backendPort)
	}
	if entry.Generation != 7 {
		t.Errorf("Get generation = %d, want 7", entry.Generation)
	}
}

func TestVipXlatTable_RegisterEgressAndGet(t *testing.T) {
	vt, _ := newTestTable(constClock(3))

	vip := net.ParseIP("2001:db8:5:5::100")
	backend := net.ParseIP("fd20:60::5:5")
	const vipPort, backendPort = 8080, 30080

	if err := vt.RegisterEgress(testBlock, 0x654, ProtoTCP, backend, backendPort, vip, vipPort); err != nil {
		t.Fatalf("RegisterEgress: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x654, ProtoTCP, backendPort)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after RegisterEgress")
	}
	if entry.Port != backendPort {
		t.Errorf("Get key port = %d, want %d (egress keys on the backend's own port)", entry.Port, backendPort)
	}
	if !entry.Addr.Equal(vip) {
		t.Errorf("Get addr = %s, want %s (egress row rewrites back to the VIP)", entry.Addr, vip)
	}
	if entry.RewritePort != vipPort {
		t.Errorf("Get rewrite port = %d, want %d", entry.RewritePort, vipPort)
	}
}

// TestVipXlatTable_IngressAndEgressRowsAreSwapped proves, for one binding,
// that the ingress and egress rows really do have swapped key/value roles,
// exactly as usid.c's struct vip_xlat_key doc comment describes: the
// ingress row is keyed on the VIP's own port and rewrites to the backend;
// the egress row is keyed on the backend's own port and rewrites to the
// VIP. These are two distinct map entries (different keys), not the same
// entry read two ways.
func TestVipXlatTable_IngressAndEgressRowsAreSwapped(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8:5:5::100")
	backend := net.ParseIP("fd20:60::5:5")
	const vipPort, backendPort = 8080, 30080

	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, vipPort, backend, backendPort); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}
	if err := vt.RegisterEgress(testBlock, 0x1, ProtoTCP, backend, backendPort, vip, vipPort); err != nil {
		t.Fatalf("RegisterEgress: unexpected error: %v", err)
	}

	if got, want := ft.len(), 2; got != want {
		t.Fatalf("table has %d entries after both registrations, want %d (two independent rows)", got, want)
	}

	ingress, ok, err := vt.Get(testBlock, 0x1, ProtoTCP, vipPort)
	if err != nil || !ok {
		t.Fatalf("Get(ingress key): ok=%v err=%v", ok, err)
	}
	egress, ok, err := vt.Get(testBlock, 0x1, ProtoTCP, backendPort)
	if err != nil || !ok {
		t.Fatalf("Get(egress key): ok=%v err=%v", ok, err)
	}

	// Keys differ (ports are swapped between the two rows).
	if ingress.Port != vipPort {
		t.Errorf("ingress row key port = %d, want %d (VIP port)", ingress.Port, vipPort)
	}
	if egress.Port != backendPort {
		t.Errorf("egress row key port = %d, want %d (backend port)", egress.Port, backendPort)
	}
	// Values are the opposite side from each row's own key.
	if !ingress.Addr.Equal(backend) || ingress.RewritePort != backendPort {
		t.Errorf("ingress row value = %s:%d, want %s:%d (backend)", ingress.Addr, ingress.RewritePort, backend, backendPort)
	}
	if !egress.Addr.Equal(vip) || egress.RewritePort != vipPort {
		t.Errorf("egress row value = %s:%d, want %s:%d (VIP)", egress.Addr, egress.RewritePort, vip, vipPort)
	}
	// Neither row is a no-op self-mapping.
	if ingress.Port == ingress.RewritePort {
		t.Errorf("ingress row's key port and rewrite port are both %d -- rows must not collapse to a no-op", ingress.Port)
	}
}

func TestVipXlatTable_GetMissingEntry(t *testing.T) {
	vt, _ := newTestTable(constClock(1))

	_, ok, err := vt.Get(testBlock, 0x1, ProtoTCP, 443)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Errorf("Get: ok = true for an entry never registered")
	}
}

func TestVipXlatTable_RegisterRejectsInvalidProto(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x1, 1 /* ICMP */, vip, 8080, backend, 30080); err == nil {
		t.Errorf("RegisterIngress(proto=ICMP) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("RegisterIngress(proto=ICMP) wrote %d entries, want 0 (reject outright)", ft.len())
	}
}

func TestVipXlatTable_RegisterRejectsIPv4Address(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backendV4 := net.ParseIP("10.0.0.5")
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backendV4, 30080); err == nil {
		t.Errorf("RegisterIngress(backend=IPv4) = nil error, want rejection (IPv6-only substitution)")
	}
	if ft.len() != 0 {
		t.Errorf("RegisterIngress(backend=IPv4) wrote %d entries, want 0", ft.len())
	}
}

func TestVipXlatTable_RegisterRejectsReservedArgumentZero(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x000, ProtoTCP, vip, 8080, backend, 30080); err == nil {
		t.Errorf("RegisterIngress(argument=0x000) = nil error, want rejection (reserved value)")
	}
	if ft.len() != 0 {
		t.Errorf("RegisterIngress(argument=0x000) wrote %d entries, want 0", ft.len())
	}
}

func TestVipXlatTable_UnregisterIsIdempotent(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backend, 30080); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}
	if err := vt.UnregisterIngress(testBlock, 0x1, ProtoTCP, 8080); err != nil {
		t.Fatalf("UnregisterIngress: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after unregister, want 0", ft.len())
	}
	// Second call: already absent, still not an error.
	if err := vt.UnregisterIngress(testBlock, 0x1, ProtoTCP, 8080); err != nil {
		t.Errorf("UnregisterIngress on an already-absent entry: unexpected error: %v", err)
	}
}

func TestVipXlatTable_List(t *testing.T) {
	vt, _ := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backend, 30080); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}
	if err := vt.RegisterEgress(testBlock, 0x1, ProtoTCP, backend, 30080, vip, 8080); err != nil {
		t.Fatalf("RegisterEgress: unexpected error: %v", err)
	}

	entries, err := vt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
}

func TestVipXlatTable_ReconcileRemovesStaleEntries(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backend, 30080); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}
	if err := vt.RegisterIngress(testBlock, 0x2, ProtoTCP, vip, 9090, backend, 40040); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}

	// Only argument 0x1's key is still live; argument 0x2's is stale.
	live := map[Key]struct{}{
		{Block: testBlock, Argument: 0x1, Proto: ProtoTCP, Port: 8080}: {},
	}

	// cutoff above both entries' generation (1) means neither is "too new
	// to judge" -- both are eligible, only the absent one is removed.
	removed, err := vt.Reconcile(live, 2)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("Reconcile removed %d entries, want 1", len(removed))
	}
	if removed[0].Argument != 0x2 {
		t.Errorf("Reconcile removed argument %#x, want 0x2", removed[0].Argument)
	}
	if ft.len() != 1 {
		t.Errorf("table has %d entries after Reconcile, want 1", ft.len())
	}
}

func TestVipXlatTable_ReconcileKeepsEntriesAtOrAfterCutoff(t *testing.T) {
	vt, ft := newTestTable(constClock(5))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	// Registered at generation 5, i.e. at-or-after a cutoff of 5 -- must be
	// kept even though its key is absent from live (it is simply too new
	// to judge against a live set snapshotted before it existed).
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backend, 30080); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}

	removed, err := vt.Reconcile(map[Key]struct{}{}, 5)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Reconcile removed %d entries, want 0 (entry's generation >= cutoff)", len(removed))
	}
	if ft.len() != 1 {
		t.Errorf("table has %d entries after Reconcile, want 1 (kept)", ft.len())
	}
}

func TestVipXlatTable_ReconcileKeepsLiveEntries(t *testing.T) {
	vt, ft := newTestTable(constClock(1))

	vip := net.ParseIP("2001:db8::1")
	backend := net.ParseIP("fd20:60::1")
	if err := vt.RegisterIngress(testBlock, 0x1, ProtoTCP, vip, 8080, backend, 30080); err != nil {
		t.Fatalf("RegisterIngress: unexpected error: %v", err)
	}

	live := map[Key]struct{}{
		{Block: testBlock, Argument: 0x1, Proto: ProtoTCP, Port: 8080}: {},
	}
	removed, err := vt.Reconcile(live, 2)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Reconcile removed %d entries, want 0 (key is live)", len(removed))
	}
	if ft.len() != 1 {
		t.Errorf("table has %d entries after Reconcile, want 1", ft.len())
	}
}

func TestVipXlatTable_GenerationAdvancesWithClock(t *testing.T) {
	vt, _ := newTestTable(constClock(1))
	if got := vt.Generation(); got != 1 {
		t.Errorf("Generation() = %d, want 1", got)
	}
	vt.clock = constClock(42)
	if got := vt.Generation(); got != 42 {
		t.Errorf("Generation() after clock change = %d, want 42", got)
	}
}
