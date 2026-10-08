// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"net/netip"
	"strings"
	"testing"
)

// Probe destinations the tests share.
const (
	pingV4   = "1.1.1.1"
	pingV6   = "2606:4700::1111"
	testHost = "example.com"
)

// noExport is the canonical spelling of the NO_EXPORT well-known community.
const noExport = "no-export"

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name string
		in   Query
		want Query
		code ErrorCode
	}{
		{name: "summary defaults to IPv4", in: Query{Type: TypeBGPSummary},
			want: Query{Type: TypeBGPSummary, AddressFamily: IPv4}},
		{name: "summary IPv6", in: Query{Type: TypeBGPSummary, AddressFamily: IPv6},
			want: Query{Type: TypeBGPSummary, AddressFamily: IPv6}},
		{name: "summary with target", in: Query{Type: TypeBGPSummary, Target: "x"}, code: CodeTargetForbidden},
		{name: "unknown type", in: Query{Type: "Whois"}, code: CodeInvalidType},
		{name: "bad family", in: Query{Type: TypeBGPSummary, AddressFamily: "ipv4"}, code: CodeInvalidFamily},

		{name: "prefix infers family", in: Query{Type: TypeRouteLookup, Target: "2001:DB8::/32"},
			want: Query{Type: TypeRouteLookup, Target: "2001:db8::/32", AddressFamily: IPv6}},
		{name: "address", in: Query{Type: TypeRouteLookup, Target: "198.51.100.7"},
			want: Query{Type: TypeRouteLookup, Target: "198.51.100.7", AddressFamily: IPv4}},
		{name: "host bits", in: Query{Type: TypeRouteLookup, Target: "198.51.100.7/24"}, code: CodeInvalidTarget},
		{name: "family conflict", in: Query{Type: TypeRouteLookup, Target: "198.51.100.0/24", AddressFamily: IPv6},
			code: CodeFamilyConflict},
		{name: "mapped address", in: Query{Type: TypeRouteLookup, Target: "::ffff:1.2.3.4"}, code: CodeInvalidTarget},
		{name: "zone", in: Query{Type: TypeRouteLookup, Target: "fe80::1%eth0"}, code: CodeInvalidTarget},
		{name: "empty route target", in: Query{Type: TypeRouteLookup}, code: CodeTargetRequired},
		{name: "newline injection", in: Query{Type: TypeRouteLookup, Target: "1.1.1.0/24\nclear bgp *"},
			code: CodeInvalidTarget},
		{name: "NUL injection", in: Query{Type: TypeRouteLookup, Target: "1.1.1.0/24\x00"}, code: CodeInvalidTarget},
		{name: "non-ASCII", in: Query{Type: TypeRouteLookup, Target: "１.1.1.1"}, code: CodeInvalidTarget},

		{name: "aspath", in: Query{Type: TypeASPath, Target: "^65001_"},
			want: Query{Type: TypeASPath, Target: "^65001_", AddressFamily: IPv4}},
		{name: "empty aspath expression is ^$", in: Query{Type: TypeASPath, Target: "^$", AddressFamily: IPv6},
			want: Query{Type: TypeASPath, Target: "^$", AddressFamily: IPv6}},
		{name: "aspath space", in: Query{Type: TypeASPath, Target: "65001 65002"}, code: CodeInvalidTarget},
		{name: "aspath json keyword", in: Query{Type: TypeASPath, Target: "json"}, code: CodeInvalidTarget},
		{name: "aspath unbalanced", in: Query{Type: TypeASPath, Target: "(65001"}, code: CodeInvalidTarget},
		{name: "aspath too long", in: Query{Type: TypeASPath, Target: strings.Repeat("1", 129)}, code: CodeInvalidTarget},
		{name: "aspath empty", in: Query{Type: TypeASPath}, code: CodeTargetRequired},

		{name: "community", in: Query{Type: TypeCommunity, Target: "065001:0100"},
			want: Query{Type: TypeCommunity, Target: "65001:100", AddressFamily: IPv4}},
		{name: "well-known community", in: Query{Type: TypeCommunity, Target: "NO-EXPORT"},
			want: Query{Type: TypeCommunity, Target: noExport, AddressFamily: IPv4}},
		{name: "community overflow", in: Query{Type: TypeCommunity, Target: "65536:1"}, code: CodeInvalidTarget},
		{name: "community sign", in: Query{Type: TypeCommunity, Target: "+1:1"}, code: CodeInvalidTarget},
		{name: "large community", in: Query{Type: TypeLargeCommunity, Target: "4294967295:0:01"},
			want: Query{Type: TypeLargeCommunity, Target: "4294967295:0:1", AddressFamily: IPv4}},
		{name: "large community overflow", in: Query{Type: TypeLargeCommunity, Target: "4294967296:0:1"},
			code: CodeInvalidTarget},
		{name: "large community short", in: Query{Type: TypeLargeCommunity, Target: "1:2"}, code: CodeInvalidTarget},

		{name: "ping address", in: Query{Type: TypePing, Target: pingV6},
			want: Query{Type: TypePing, Target: pingV6, AddressFamily: IPv6}},
		{name: "ping hostname keeps requested family",
			in:   Query{Type: TypePing, Target: "One.One.One.One.", AddressFamily: IPv6},
			want: Query{Type: TypePing, Target: "one.one.one.one", AddressFamily: IPv6}},
		{name: "traceroute hostname defaults IPv4", in: Query{Type: TypeTraceroute, Target: testHost},
			want: Query{Type: TypeTraceroute, Target: testHost, AddressFamily: IPv4}},
		{name: "single label", in: Query{Type: TypePing, Target: "localhost"}, code: CodeInvalidTarget},
		{name: "numeric tld", in: Query{Type: TypePing, Target: "1.2.3.999"}, code: CodeInvalidTarget},
		{name: "underscore host", in: Query{Type: TypePing, Target: "a_b.example.com"}, code: CodeInvalidTarget},
		{name: "too long", in: Query{Type: TypePing, Target: strings.Repeat("a", 256)}, code: CodeInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.in)
			if tt.code != "" {
				if CodeOf(err) != tt.code {
					t.Fatalf("Canonicalize(%+v) error = %v, want code %s", tt.in, err, tt.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize(%+v): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Canonicalize(%+v) = %+v, want %+v", tt.in, got, tt.want)
			}
			// Canonicalization is idempotent.
			again, err := Canonicalize(got)
			if err != nil || again != got {
				t.Fatalf("Canonicalize not idempotent: %+v -> %+v, %v", got, again, err)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	if Lookup(Query{Target: "10.0.0.0/8"}) != LookupExact {
		t.Error("prefix should be an exact lookup")
	}
	if Lookup(Query{Target: "10.0.0.1"}) != LookupLongestMatch {
		t.Error("address should be a longest-match lookup")
	}
}

func TestTypeClasses(t *testing.T) {
	for _, ty := range Types {
		if ty.Expensive() && ty.Probe() {
			t.Errorf("%s is both expensive and a probe", ty)
		}
	}
	if !TypeASPath.Expensive() || TypeRouteLookup.Expensive() || !TypeTraceroute.Probe() {
		t.Error("type classification wrong")
	}
}

func TestDestinationPolicy(t *testing.T) {
	public := DestinationPolicy{Deny: mustPrefixes("2606:4700:10::/48")}
	operator := DestinationPolicy{Allow: mustPrefixes("10.255.255.0/24")}
	tests := []struct {
		policy DestinationPolicy
		addr   string
		ok     bool
	}{
		{public, pingV4, true},
		{public, pingV6, true},
		{public, "10.1.2.3", false},
		{public, "100.64.0.1", false},
		{public, "127.0.0.1", false},
		{public, "169.254.1.1", false},
		{public, "192.0.2.1", false},
		{public, "198.18.0.1", false},
		{public, "224.0.0.1", false},
		{public, "255.255.255.255", false},
		{public, "0.0.0.0", false},
		{public, "::1", false},
		{public, "::", false},
		{public, "fd00::1", false},
		{public, "fe80::1", false},
		{public, "ff02::1", false},
		{public, "2001:db8::1", false},
		{public, "3fff::1", false},
		{public, "5f00::1", false},
		{public, "64:ff9b::808:808", false},
		{public, "2002:c000:204::1", false},
		{public, "2001:0::1", false},
		{public, "4000::1", false},
		{public, "2606:4700:10::1", false},
		{public, "10.255.255.1", false},
		{operator, "10.255.255.1", true},
		{operator, "10.255.254.1", false},
		{operator, "::ffff:10.255.255.1", true},
	}
	for _, tt := range tests {
		err := tt.policy.Check(netip.MustParseAddr(tt.addr))
		if (err == nil) != tt.ok {
			t.Errorf("Check(%s) = %v, want ok=%v", tt.addr, err, tt.ok)
		}
		if err != nil && CodeOf(err) != CodeDestinationDeny {
			t.Errorf("Check(%s) code = %s", tt.addr, CodeOf(err))
		}
	}
}

func TestResolvedProbe(t *testing.T) {
	_, err := ResolvedProbe(Query{Type: TypePing, Target: testHost, AddressFamily: IPv4})
	if CodeOf(err) != CodeHostnameRequired {
		t.Errorf("hostname: err = %v", err)
	}
	_, err = ResolvedProbe(Query{Type: TypePing, Target: pingV4, AddressFamily: IPv6})
	if CodeOf(err) != CodeFamilyConflict {
		t.Errorf("family: err = %v", err)
	}
	a, err := ResolvedProbe(Query{Type: TypePing, Target: pingV4, AddressFamily: IPv4})
	if err != nil || a != netip.MustParseAddr(pingV4) {
		t.Errorf("got %v, %v", a, err)
	}
}

func TestBudgetsClamp(t *testing.T) {
	got := Budgets{MaxNodes: 4, MaxPrefixes: 1000}.Clamp()
	if got.MaxNodes != 4 || got.MaxPrefixes != Ceilings.MaxPrefixes || got.MaxObjectBytes != Ceilings.MaxObjectBytes {
		t.Errorf("Clamp = %+v", got)
	}
}
