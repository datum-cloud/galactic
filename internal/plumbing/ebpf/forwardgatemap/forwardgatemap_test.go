// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package forwardgatemap

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestLayout pins the Go map types to the datapath's structs: struct
// edge_link_value is 16 bytes, struct edge_gate_key 24 (prefixlen, ifindex,
// address) and struct edge_gate_value 24.
func TestLayout(t *testing.T) {
	for name, got := range map[string]int{
		"edge_link_value": binary.Size(linkValue{}),
		"edge_gate_key":   binary.Size(gateKey{}),
		"edge_gate_value": binary.Size(gateValue{}),
	} {
		want := 24
		if name == "edge_link_value" {
			want = 16
		}
		if got != want {
			t.Errorf("%s is %d bytes, want %d", name, got, want)
		}
	}
}

// TestKey checks that a gate's LPM key counts the ifindex's 32 bits ahead of
// the prefix, and that only masked IPv6 prefixes have one.
func TestKey(t *testing.T) {
	p := netip.MustParsePrefix("fd00:5::/48")
	k, err := key(7, p)
	if err != nil {
		t.Fatal(err)
	}
	if k.PrefixLen != 32+48 || k.Ifindex != 7 || k.Addr != p.Addr().As16() {
		t.Fatalf("key %+v", k)
	}
	if k, err := key(7, netip.MustParsePrefix("fd00:5::1/128")); err != nil || k.PrefixLen != 160 {
		t.Fatalf("host prefix key %+v, %v", k, err)
	}
	for _, bad := range []string{"192.0.2.0/24", "::ffff:192.0.2.0/120", "fd00:5::1/48"} {
		if _, err := key(7, netip.MustParsePrefix(bad)); err == nil {
			t.Errorf("prefix %s has a key", bad)
		}
	}
	if _, err := key(7, netip.Prefix{}); err == nil {
		t.Error("the zero prefix has a key")
	}
}
