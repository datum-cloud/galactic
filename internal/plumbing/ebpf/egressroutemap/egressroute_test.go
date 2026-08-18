// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

func TestEgressRouteTable_RegisterThenLookupRoundTrips(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	prefix := mustCIDR(t, "2001:db8:ffff::/96")
	sid := net.ParseIP("2001:db8:ff01:1:e001::")

	if err := tbl.Register(7, prefix, sid); err != nil {
		t.Fatalf("Register(%v) = %v, want success", prefix, err)
	}

	key, err := buildKey(7, prefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	var got prog.UsidEgressRouteValue
	if err := tbl.table.Lookup(key, &got); err != nil {
		t.Fatalf("lookup installed entry: %v", err)
	}
	want := sid.To16()
	for i := range want {
		if got.Sid[i] != want[i] {
			t.Fatalf("stored sid = % x, want % x", got.Sid, want)
		}
	}
}

func TestEgressRouteTable_RegisterDefaultPrefixUsesZeroPrefixBits(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff01:9:e001::")

	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(default) = %v, want success", err)
	}

	key, err := buildKey(1, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	if key.Prefixlen != egressRouteKeyFixedBits {
		t.Errorf("default route prefixlen = %d, want %d (fixed portion only, no address bits)",
			key.Prefixlen, egressRouteKeyFixedBits)
	}
	if key.Family != egressRouteFamilyINET6 {
		t.Errorf("default route family = %d, want %d (INET6)", key.Family, egressRouteFamilyINET6)
	}
}

func TestEgressRouteTable_IPv4PrefixStoresAddressLeftJustified(t *testing.T) {
	// usid.c's egress-routing extension memsets rkey.addr to zero, then
	// memcpy's only the raw 4-byte IPv4 destination into its first 4
	// bytes -- never the IPv4-mapped-IPv6 (::ffff:a.b.c.d) convention,
	// which would place those bytes at offset 12. buildKey must match
	// that exactly or a real CNI-configured IPv4 VPC's egress route would
	// silently never match any packet (found and fixed once already,
	// as an analogous bug in this program's own test helper -- see
	// usid_test.go's egressRouteKey comment).
	prefix := mustCIDR(t, "172.40.10.0/24")
	key, err := buildKey(9, prefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	if key.Family != egressRouteFamilyINET4 {
		t.Errorf("family = %d, want %d (INET4)", key.Family, egressRouteFamilyINET4)
	}
	want := [4]byte{172, 40, 10, 0}
	for i, b := range want {
		if key.Addr[i] != b {
			t.Errorf("Addr[%d] = %#x, want %#x", i, key.Addr[i], b)
		}
	}
	for i := 4; i < 16; i++ {
		if key.Addr[i] != 0 {
			t.Errorf("Addr[%d] = %#x, want 0 (IPv4 prefix must be zero-padded beyond its own 4 bytes)", i, key.Addr[i])
		}
	}
	if key.Prefixlen != egressRouteKeyFixedBits+24 {
		t.Errorf("prefixlen = %d, want %d (fixed + /24)", key.Prefixlen, egressRouteKeyFixedBits+24)
	}
}

func TestEgressRouteTable_RegisterRejectsUnusableSID(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	prefix := mustCIDR(t, "2001:db8:ffff::/96")

	tests := []struct {
		name string
		sid  net.IP
	}{
		{"nil sid", nil},
		{"unspecified sid", net.IPv6unspecified},
		{"IPv4 sid", net.ParseIP("10.0.0.1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tbl.Register(1, prefix, tt.sid); err == nil {
				t.Errorf("Register(sid=%v) = nil error, want an error rejecting the unusable SID", tt.sid)
			}
		})
	}
}

func TestEgressRouteTable_UnregisterAbsentEntryIsANoop(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	if err := tbl.Unregister(1, mustCIDR(t, "2001:db8:ffff::/96")); err != nil {
		t.Errorf("Unregister(never registered) = %v, want nil (idempotent)", err)
	}
}

func TestEgressRouteTable_RegisterThenUnregisterRemovesEntry(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	prefix := mustCIDR(t, "2001:db8:ffff::/96")
	sid := net.ParseIP("2001:db8:ff01:1:e001::")

	if err := tbl.Register(1, prefix, sid); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := tbl.Unregister(1, prefix); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	key, err := buildKey(1, prefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	var got prog.UsidEgressRouteValue
	if err := tbl.table.Lookup(key, &got); err == nil {
		t.Error("entry still present after Unregister")
	}
}

func TestEgressRouteTable_SameTableIDDifferentFamilyDoNotCollide(t *testing.T) {
	// family sits inside the LPM-matched fixed portion specifically so
	// two entries can never compare equal on address bits alone once
	// table_id+family already differ -- see struct egress_route_key's
	// own doc comment in usid.c.
	tbl := NewEgressRouteTable(newFakeTable())
	v6 := mustCIDR(t, "::/0")
	v4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}

	if err := tbl.Register(5, v6, net.ParseIP("2001:db8:ff01:9:e001::")); err != nil {
		t.Fatalf("register v6 default: %v", err)
	}
	if err := tbl.Register(5, v4, net.ParseIP("2001:db8:ff02:9:e001::")); err != nil {
		t.Fatalf("register v4 default: %v", err)
	}

	v6Key, _ := buildKey(5, v6)
	v4Key, _ := buildKey(5, v4)
	var v6Val, v4Val prog.UsidEgressRouteValue
	if err := tbl.table.Lookup(v6Key, &v6Val); err != nil {
		t.Fatalf("lookup v6 entry: %v", err)
	}
	if err := tbl.table.Lookup(v4Key, &v4Val); err != nil {
		t.Fatalf("lookup v4 entry: %v", err)
	}
	if v6Val == v4Val {
		t.Error("v6 and v4 default-route entries share the same value -- family must not have collided them")
	}
}

func TestNodeSourceAddress_SetThenGetRoundTrips(t *testing.T) {
	n := &NodeSourceAddress{table: newFakeTable()}
	addr := net.ParseIP("2001:db8:1:10::2")

	if err := n.Set(addr); err != nil {
		t.Fatalf("Set(%v) = %v, want success", addr, err)
	}
	got, ok, err := n.Get()
	if err != nil {
		t.Fatalf("Get() = %v, want success", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true after Set")
	}
	gotAddr, _ := netip.AddrFromSlice(got)
	wantAddr, _ := netip.AddrFromSlice(addr.To16())
	if gotAddr != wantAddr {
		t.Errorf("Get() = %s, want %s", gotAddr, wantAddr)
	}
}

func TestNodeSourceAddress_GetBeforeSetReportsNotOK(t *testing.T) {
	n := &NodeSourceAddress{table: newFakeTable()}
	_, ok, err := n.Get()
	if err != nil {
		t.Fatalf("Get() = %v, want success", err)
	}
	if ok {
		t.Error("Get() ok = true before any Set, want false")
	}
}

func TestNodeSourceAddress_SetRejectsUnspecifiedAddress(t *testing.T) {
	n := &NodeSourceAddress{table: newFakeTable()}
	if err := n.Set(net.IPv6unspecified); err == nil {
		t.Error("Set(::) = nil error, want an error -- usid_egress treats an all-zero entry as \"not configured\"")
	}
}
