// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixtures in testdata/frr-10.7/ are captured verbatim from a standalone
// FRR 10.7.1 topology: two eBGP upstreams sending ECMP prefixes,
// communities, large communities and a default route; one iBGP neighbor
// sending local prefixes with link-local IPv6 next hops; a local AS_SET
// aggregate; and one peer that never comes up. Re-capture them on any
// FRR_VERSION bump.

// Values the fixtures share.
const (
	fixtureRelease = "10.7"
	docPrefixV4    = "198.51.100.0/24"
	docPrefixV6    = "2001:db8:100::/48"
	upstreamPeer   = "172.30.0.11"
)

func fixture(t *testing.T, release, name string) Response {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "frr-"+release, name))
	if err != nil {
		t.Fatal(err)
	}
	return Response{Output: b}
}

func TestParseVersionFixtures(t *testing.T) {
	for release, want := range map[string]Version{
		fixtureRelease: {Major: 10, Minor: 7, Patch: 1, Raw: "10.7.1_git"},
	} {
		v, err := ParseVersion(fixture(t, release, "version.txt").Output)
		if err != nil {
			t.Fatalf("%s: %v", release, err)
		}
		if v != want {
			t.Errorf("%s: got %+v want %+v", release, v, want)
		}
		if err := CheckSupported(v); err != nil {
			t.Errorf("%s: %v", release, err)
		}
	}
	for _, s := range []string{"FRRouting 9.1.2 (x)", "FRRouting 10.2_git (x)", "FRRouting 11.0 (x)"} {
		v, err := ParseVersion([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if CodeOf(CheckSupported(v)) != CodeVersionUnsupported {
			t.Errorf("%s should be unsupported", s)
		}
	}
	if _, err := ParseVersion([]byte("Quagga 1.2")); CodeOf(err) != CodeMalformed {
		t.Errorf("err = %v", err)
	}
}

func TestParseLookupMultipath(t *testing.T) {
	r, err := ParseLookup(fixture(t, fixtureRelease, "bgp-prefix-multipath-ipv4.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Prefix != docPrefixV4 || len(r.Paths) != 2 {
		t.Fatalf("route = %+v", r)
	}
	best, other := r.Paths[0], r.Paths[1]
	if !best.Best || !best.Multipath || other.Best || !other.Multipath {
		t.Errorf("best/multipath flags wrong: %+v / %+v", best, other)
	}
	if best.SelectionReason != "Older Path" || best.Origin != "incomplete" {
		t.Errorf("selection/origin: %+v", best)
	}
	wantSeg := []ASSegment{{Type: SegmentSequence, ASNs: []uint32{65001, 65001}}}
	if !reflect.DeepEqual(best.ASPath.Segments, wantSeg) || best.OriginASN != 65001 {
		t.Errorf("aspath = %+v origin %d", best.ASPath, best.OriginASN)
	}
	if !reflect.DeepEqual(best.Communities, []string{"65001:100", "blackhole", "noExport"}) {
		t.Errorf("communities = %v", best.Communities)
	}
	if !reflect.DeepEqual(best.LargeCommunities, []string{"65001:1:1", "65001:2:11"}) {
		t.Errorf("large = %v", best.LargeCommunities)
	}
	if best.PeerAddress != upstreamPeer || best.PeerRouterID != "10.255.0.11" || best.PeerType != "external" {
		t.Errorf("peer = %+v", best)
	}
	if len(best.NextHops) != 1 || best.NextHops[0].Address != upstreamPeer || !best.NextHops[0].Used {
		t.Errorf("nexthops = %+v", best.NextHops)
	}
	if best.LastUpdate.IsZero() || best.MED == nil || *best.MED != 0 || best.LocalPref != nil {
		t.Errorf("attrs = %+v", best)
	}
}

func TestParseLookupASSet(t *testing.T) {
	r, err := ParseLookup(fixture(t, fixtureRelease, "bgp-prefix-asset-ipv4.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := r.Paths[0]
	if !p.Local || !p.Aggregated || p.PeerAddress != "" {
		t.Errorf("local aggregate flags: %+v", p)
	}
	want := []ASSegment{{Type: SegmentSet, ASNs: []uint32{65001, 65002}}}
	if !reflect.DeepEqual(p.ASPath.Segments, want) || p.ASPath.String != "{65001,65002}" {
		t.Errorf("aspath = %+v", p.ASPath)
	}
	if p.OriginASN != 0 {
		t.Errorf("an AS_SET has no single origin ASN, got %d", p.OriginASN)
	}
}

func TestParseLookupLocalAndLinkLocal(t *testing.T) {
	r, err := ParseLookup(fixture(t, fixtureRelease, "bgp-prefix-ibgp-ipv6.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := r.Paths[0]
	if p.ASPath.String != "" || len(p.ASPath.Segments) != 0 || p.OriginASN != 0 {
		t.Errorf("iBGP-learned path with empty AS path: %+v", p.ASPath)
	}
	if p.LocalPref == nil || *p.LocalPref != 100 || p.PeerType != "internal" {
		t.Errorf("attrs: %+v", p)
	}
	if len(p.NextHops) != 2 || p.NextHops[1].Scope != "link-local" || !p.NextHops[1].Used {
		t.Errorf("nexthops: %+v", p.NextHops)
	}
}

func TestParseLookupLongestMatch(t *testing.T) {
	tests := []struct{ release, file, prefix string }{
		{fixtureRelease, "bgp-addr-lpm-ipv4.json", docPrefixV4},
		{fixtureRelease, "bgp-addr-lpm-ipv6.json", docPrefixV6},
		{fixtureRelease, "bgp-addr-default-ipv4.json", "0.0.0.0/0"},
		{fixtureRelease, "bgp-addr-default-ipv6.json", "::/0"},
		{fixtureRelease, "bgp-prefix-ibgp-ipv4.json", "10.255.255.3/32"},
		{fixtureRelease, "bgp-prefix-ibgp-ipv6.json", "2001:db8:ff01::/48"},
		{fixtureRelease, "bgp-prefix-ipv6.json", docPrefixV6},
	}
	for _, tt := range tests {
		r, err := ParseLookup(fixture(t, tt.release, tt.file))
		if err != nil {
			t.Fatalf("%s/%s: %v", tt.release, tt.file, err)
		}
		if r == nil || r.Prefix != tt.prefix || len(r.Paths) == 0 {
			t.Errorf("%s/%s: got %+v, want prefix %s", tt.release, tt.file, r, tt.prefix)
		}
	}
}

func TestParseLookupAbsent(t *testing.T) {
	r, err := ParseLookup(fixture(t, fixtureRelease, "bgp-prefix-absent-ipv4.json"))
	if err != nil || r != nil {
		t.Errorf("absent prefix = %+v, %v", r, err)
	}
}

func TestParseLookupMalformed(t *testing.T) {
	tests := map[string]string{
		"not json":       "% Unknown command",
		"truncated":      `{"prefix":"10.0.0.0/8","paths":[`,
		"no paths":       `{"prefix":"10.0.0.0/8"}`,
		"bad prefix":     `{"prefix":"bogus","paths":[]}`,
		"path no aspath": `{"prefix":"10.0.0.0/8","paths":[{"nexthops":[]}]}`,
		"path no nh":     `{"prefix":"10.0.0.0/8","paths":[{"aspath":{"string":"","segments":[]}}]}`,
		"bad segment": `{"prefix":"10.0.0.0/8","paths":[{"aspath":{"string":"1",` +
			`"segments":[{"type":"as-weird","list":[1]}]},"nexthops":[]}]}`,
		"wrong type": `{"prefix":"10.0.0.0/8","paths":{"a":1}}`,
	}
	for name, out := range tests {
		if _, err := ParseLookup(Response{Output: []byte(out)}); CodeOf(err) != CodeMalformed {
			t.Errorf("%s: err = %v, want malformed", name, err)
		}
	}
	warning := Response{Output: []byte("Can't compile regexp (\n"), Warning: true}
	if _, err := ParseLookup(warning); CodeOf(err) != CodeCommandFailed {
		t.Errorf("warning text: err = %v", err)
	}
}

func TestParseSummary(t *testing.T) {
	s, err := ParseSummary(fixture(t, fixtureRelease, "bgp-summary-ipv4.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.RouterID != "10.255.0.1" || s.ASN != 65000 || len(s.Peers) != 4 {
		t.Fatalf("summary = %+v", s)
	}
	if s.Peers[0].Address != upstreamPeer || !s.Peers[0].Established || s.Peers[0].PrefixesReceived == 0 {
		t.Errorf("first peer = %+v", s.Peers[0])
	}
	if ibgp := s.Peers[2]; ibgp.Address != "172.30.0.13" || ibgp.RemoteAS != 65000 || !ibgp.Established {
		t.Errorf("iBGP peer = %+v", ibgp)
	}
	down := s.Peers[3]
	if down.Address != "172.30.0.99" || down.Established ||
		(down.State != "Connect" && down.State != "Active") || down.RemoteAS != 65099 {
		t.Errorf("down peer = %+v", down)
	}

	v6, err := ParseSummary(fixture(t, fixtureRelease, "bgp-summary-ipv6.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v6.ASN != 65000 || len(v6.Peers) != 3 || v6.Peers[0].Address != "fd30::11" || v6.Peers[2].RemoteAS != 65000 {
		t.Errorf("IPv6 summary = %+v", v6)
	}

	empty, err := ParseSummary(Response{Output: []byte("{}\n")})
	if err != nil || len(empty.Peers) != 0 {
		t.Errorf("empty summary = %+v, %v", empty, err)
	}
	if _, err := ParseSummary(Response{Output: []byte(`{"peers":{}}`)}); CodeOf(err) != CodeMalformed {
		t.Errorf("summary without router id: %v", err)
	}
}

func TestParseSearch(t *testing.T) {
	res, err := ParseSearch(fixture(t, fixtureRelease, "bgp-regexp-ipv4.json"))
	if err != nil {
		t.Fatal(err)
	}
	prefixes := make([]string, 0, len(res.Routes))
	for _, r := range res.Routes {
		prefixes = append(prefixes, r.Prefix)
		for _, p := range r.Paths {
			if p.OriginASN != 65001 {
				t.Errorf("%s: origin ASN %d", r.Prefix, p.OriginASN)
			}
		}
	}
	if len(prefixes) == 0 || prefixes[0] != "0.0.0.0/0" {
		t.Errorf("prefixes = %v (want sorted, default first)", prefixes)
	}

	empty, err := ParseSearch(fixture(t, fixtureRelease, "bgp-regexp-empty-ipv4.json"))
	if err != nil || len(empty.Routes) != 1 ||
		empty.Routes[0].Prefix != "10.200.0.0/16" || !empty.Routes[0].Paths[0].Local {
		t.Errorf("^$ search = %+v, %v", empty, err)
	}

	none, err := ParseSearch(fixture(t, fixtureRelease, "bgp-regexp-nomatch-ipv4.json"))
	if err != nil || len(none.Routes) != 0 {
		t.Errorf("no-match search = %+v, %v", none, err)
	}

	for _, f := range []struct{ rel, file string }{
		{fixtureRelease, "bgp-community-ipv4.json"}, {fixtureRelease, "bgp-community-ipv6.json"},
		{fixtureRelease, "bgp-large-community-ipv4.json"},
	} {
		if _, err := ParseSearch(fixture(t, f.rel, f.file)); err != nil {
			t.Errorf("%s/%s: %v", f.rel, f.file, err)
		}
	}

	if _, err := ParseSearch(Response{Output: []byte(`{"vrfId":0}`)}); CodeOf(err) != CodeMalformed {
		t.Errorf("no routes key: %v", err)
	}
	noPath := Response{Output: []byte(`{"routes":{"10.0.0.0/8":[{"nexthops":[]}]}}`)}
	if _, err := ParseSearch(noPath); CodeOf(err) != CodeMalformed {
		t.Errorf("path without path string: %v", err)
	}
}

func TestParseASPathString(t *testing.T) {
	tests := []struct {
		in   string
		want []ASSegment
		bad  bool
	}{
		{in: "", want: nil},
		{in: "Local", want: nil},
		{in: "65001 65002", want: []ASSegment{{SegmentSequence, []uint32{65001, 65002}}}},
		{in: "65001 {65002,65003}", want: []ASSegment{
			{SegmentSequence, []uint32{65001}},
			{SegmentSet, []uint32{65002, 65003}},
		}},
		{in: "(65010 65011) 65001", want: []ASSegment{
			{SegmentConfedSequence, []uint32{65010, 65011}},
			{SegmentSequence, []uint32{65001}},
		}},
		{in: "[65010,65011]", want: []ASSegment{{SegmentConfedSet, []uint32{65010, 65011}}}},
		{in: "4294967295", want: []ASSegment{{SegmentSequence, []uint32{4294967295}}}},
		{in: "{65001", bad: true},
		{in: "4294967296", bad: true},
		{in: "65001 x", bad: true},
	}
	for _, tt := range tests {
		got, err := ParseASPathString(tt.in)
		if tt.bad {
			if err == nil {
				t.Errorf("%q: want error", tt.in)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
	if OriginASN([]ASSegment{{SegmentSequence, []uint32{1, 2}}, {SegmentConfedSequence, []uint32{9}}}) != 2 {
		t.Error("trailing confed segment should be skipped for origin ASN")
	}
}

func TestParseInstallation(t *testing.T) {
	inst, err := ParseInstallation(fixture(t, fixtureRelease, "zebra-route-ipv4.json"), docPrefixV4)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Present || len(inst.Routes) != 1 {
		t.Fatalf("installation = %+v", inst)
	}
	r := inst.Routes[0]
	if r.Protocol != "bgp" || !r.Selected || !r.Installed || r.Distance != 20 ||
		len(r.NextHops) != 2 || !r.NextHops[1].FIB {
		t.Errorf("route = %+v", r)
	}

	static, err := ParseInstallation(fixture(t, fixtureRelease, "zebra-route-static-ipv4.json"), "10.200.0.0/16")
	if err != nil || static.Routes[0].Protocol != "static" || !static.Routes[0].NextHops[0].Blackhole {
		t.Errorf("static = %+v, %v", static, err)
	}

	for _, f := range []struct{ rel, file, prefix string }{
		{fixtureRelease, "zebra-route-ipv6.json", docPrefixV6},
		{fixtureRelease, "zebra-route-ibgp-ipv6.json", "2001:db8:ff01::/48"},
	} {
		inst, err := ParseInstallation(fixture(t, f.rel, f.file), f.prefix)
		if err != nil || !inst.Present {
			t.Errorf("%s/%s: %+v, %v", f.rel, f.file, inst, err)
		}
	}

	// zebra answers an absent route with {} and a warning code.
	absent := fixture(t, fixtureRelease, "zebra-route-absent-ipv4.json")
	absent.Warning = true
	inst, err = ParseInstallation(absent, "10.99.0.0/16")
	if err != nil || inst.Present {
		t.Errorf("absent = %+v, %v", inst, err)
	}

	wrong := fixture(t, fixtureRelease, "zebra-route-ipv4.json")
	if _, err := ParseInstallation(wrong, "10.0.0.0/8"); CodeOf(err) != CodeMalformed {
		t.Errorf("wrong prefix: %v", err)
	}
}
