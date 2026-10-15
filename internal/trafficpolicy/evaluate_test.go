// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficpolicy

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func mustPolicy(t *testing.T, rules string) Policy {
	t.Helper()
	p, errs := FromAPI(spec(t, rules), field.NewPath("spec"))
	if len(errs) > 0 {
		t.Fatalf("invalid policy: %v", errs)
	}
	return p
}

func tcp(path Path, src, dst string, sport, dport uint16) Packet {
	return Packet{Path: path, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		Proto: ProtoTCP, SrcPort: sport, DstPort: dport}
}

// TestEvaluate covers first-match semantics against hand-written expectations.
// Every case also runs through the compiled entries, which must agree.
func TestEvaluate(t *testing.T) {
	webEgress := `[
		{"name":"https-through-nat","action":"Allow","match":{"path":"PublicNAT","protocol":"TCP",
		 "destinationPorts":[{"start":443,"end":443}]}},
		{"name":"deny-all","action":"Deny"}]`
	privateIngress := `[
		{"name":"private-web-listener","action":"Allow","match":{"path":"Private","protocol":"TCP",
		 "destinationPorts":[{"start":8080,"end":8080}]}},
		{"name":"deny-all","action":"Deny"}]`
	specificDenyFirst := `[
		{"name":"block-one","action":"Deny","match":{"sourceIPs":["2001:db8::66"]}},
		{"name":"allow-net","action":"Allow","match":{"sourceCIDRs":["2001:db8::/32"]}}]`
	noCatchAll := `[{"name":"only-dns","action":"Allow","match":{"protocol":"UDP",
		"destinationPorts":[{"start":53,"end":53}]}}]`
	pair := `[{"name":"pair","action":"Allow","match":{"ipFamily":"IPv6","sourceIPs":["2001:db8:10::10"],
		"destinationIPs":["2001:db8:20::20"],"protocol":"TCP","destinationPorts":[{"start":8080,"end":8080}]}}]`
	mixed := `[{"name":"either","action":"Allow","match":{"sourceIPs":["192.0.2.1","2001:db8::1"],
		"destinationCIDRs":["198.51.100.0/24"]}}]`
	icmpv4 := `[{"name":"frag-needed","action":"Allow","match":{"protocol":"ICMP","icmp":{"type":3,"code":4}}}]`
	icmp := func(src, dst string, proto, typ, code uint8) Packet {
		return Packet{Path: PathPublicNAT, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
			Proto: proto, ICMPType: typ, ICMPCode: code}
	}
	pathRuleThenBroad := `[
		{"name":"nat-https","action":"Deny","match":{"path":"PublicNAT","protocol":"TCP",
		 "destinationPorts":[{"start":443,"end":443}]}},
		{"name":"allow-all","action":"Allow"}]`

	tests := []struct {
		name  string
		rules string
		pkt   Packet
		want  Verdict
		why   string
	}{
		{"nat https allowed", webEgress, tcp(PathPublicNAT, "2001:db8::5", "64:ff9b::c000:201", 41000, 443),
			Verdict{Allow: true, Rule: 0}, ""},
		{"same port on the private path denied by the catch-all", webEgress,
			tcp(PathPrivate, "2001:db8::5", "2001:db8::6", 41000, 443), Verdict{Rule: 1}, ""},
		{"nat reply is not an egress grant", privateIngress,
			tcp(PathPublicNAT, "64:ff9b::c000:201", "2001:db8::5", 443, 41000), Verdict{Rule: 1}, ""},
		{"specific deny wins over a later broad allow", specificDenyFirst,
			tcp(PathPrivate, "2001:db8::66", "2001:db8::1", 1, 2), Verdict{Rule: 0}, ""},
		{"broad allow for the rest", specificDenyFirst,
			tcp(PathPrivate, "2001:db8::67", "2001:db8::1", 1, 2), Verdict{Allow: true, Rule: 1}, ""},
		{"no match denies", noCatchAll, tcp(PathPrivate, "2001:db8::1", "2001:db8::2", 1, 53),
			Verdict{Rule: -1, Reason: ReasonNoMatch}, ""},
		{"source and destination both required", pair, tcp(PathPrivate, "2001:db8:10::10", "2001:db8:20::21", 1, 8080),
			Verdict{Rule: -1, Reason: ReasonNoMatch}, ""},
		{"both sides match", pair, tcp(PathPrivate, "2001:db8:10::10", "2001:db8:20::20", 1, 8080),
			Verdict{Allow: true, Rule: 0}, ""},
		{"mixed list never pairs families", mixed, tcp(PathPrivate, "2001:db8::1", "2001:db8::9", 1, 2),
			Verdict{Rule: -1, Reason: ReasonNoMatch}, "the IPv6 source entry has no IPv6 destination to pair with"},
		{"mixed list matches within a family", mixed, tcp(PathPrivate, "192.0.2.1", "198.51.100.9", 1, 2),
			Verdict{Allow: true, Rule: 0}, ""},
		{"an ipv4 literal does not match its nat64 form", mixed,
			tcp(PathPrivate, "192.0.2.1", "64:ff9b::c633:6409", 1, 2), Verdict{Rule: -1, Reason: ReasonNoMatch}, ""},
		{"icmp type and code", icmpv4, icmp("192.0.2.1", "10.0.0.1", ProtoICMP, 3, 4), Verdict{Allow: true, Rule: 0}, ""},
		{"icmp other code", icmpv4, icmp("192.0.2.1", "10.0.0.1", ProtoICMP, 3, 3),
			Verdict{Rule: -1, Reason: ReasonNoMatch}, ""},
		{"protocol 1 inside ipv6 is not icmp", icmpv4, icmp("2001:db8::1", "2001:db8::2", ProtoICMP, 3, 4),
			Verdict{Rule: -1, Reason: ReasonNoMatch}, ""},
		{"unknown path stops at a path rule the packet otherwise matches", pathRuleThenBroad,
			tcp(PathUnknown, "2001:db8::1", "2001:db8::2", 1, 443), Verdict{Rule: -1, Reason: ReasonClassificationError},
			"skipping it would reach the broader allow"},
		{"unknown path skips a path rule the packet cannot match anyway", pathRuleThenBroad,
			tcp(PathUnknown, "2001:db8::1", "2001:db8::2", 1, 80), Verdict{Allow: true, Rule: 1}, ""},
		{"default denies", `[{"name":"deny-all","action":"Deny"}]`, tcp(PathPrivate, "192.0.2.1", "192.0.2.2", 1, 25),
			Verdict{Rule: 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustPolicy(t, tt.rules)
			if got := Evaluate(p, tt.pkt); got != tt.want {
				t.Errorf("Evaluate = %+v, want %+v %s", got, tt.want, tt.why)
			}
			entries, err := Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := EvaluateEntries(entries, tt.pkt); got != tt.want {
				t.Errorf("EvaluateEntries = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestShadowed reports a rule after a catch-all and an exact duplicate.
func TestShadowed(t *testing.T) {
	p := mustPolicy(t, `[
		{"name":"web","action":"Allow","match":{"protocol":"TCP","destinationPorts":[{"start":80,"end":80}]}},
		{"name":"web-again","action":"Deny","match":{"protocol":"TCP","destinationPorts":[{"start":80,"end":80}]}},
		{"name":"deny-all","action":"Deny"},
		{"name":"never","action":"Allow","match":{"protocol":"UDP"}}]`)
	got := Shadowed(p)
	want := map[int]int{1: 0, 3: 2}
	if len(got) != len(want) || got[1] != 0 || got[3] != 2 {
		t.Errorf("Shadowed = %v, want %v", got, want)
	}
}

// TestCompileAgreesWithEvaluate is the oracle property the datapath's own
// tests build on: for random policies and packets near their boundaries, the
// compiled entries decide exactly as the rule-level evaluator does.
func TestCompileAgreesWithEvaluate(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 4000 {
		// Half the policies are built as FromAPI would build them; the
		// other half draw family, protocol and addresses independently, so
		// Compile has to drop contradictory combinations exactly as
		// Evaluate fails to match them.
		p := randomPolicy(rng, i%2 == 1)
		entries, err := Compile(p)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(entries) != p.EntryCount() {
			t.Fatalf("Compile produced %d entries, EntryCount says %d", len(entries), p.EntryCount())
		}
		assertRuleOrder(t, entries)
		for range 50 {
			pkt := randomPacket(rng)
			if a, b := Evaluate(p, pkt), EvaluateEntries(entries, pkt); a != b {
				t.Fatalf("policy %+v\npacket %+v\nEvaluate = %+v, EvaluateEntries = %+v", p, pkt, a, b)
			}
		}
	}
}

func assertRuleOrder(t *testing.T, entries []Entry) {
	t.Helper()
	for i := 1; i < len(entries); i++ {
		if entries[i].Rule < entries[i-1].Rule {
			t.Fatalf("entry %d (rule %d) follows rule %d: compilation reordered rules", i, entries[i].Rule, entries[i-1].Rule)
		}
	}
}

// The pools are small so random rules and packets collide often.
var (
	poolV4      = []string{"192.0.2.0", "192.0.2.1", "192.0.2.128", "198.51.100.7"}
	poolV6      = []string{"2001:db8::", "2001:db8::1", "2001:db8:1::1", "64:ff9b::c000:201"}
	poolPrefix4 = []int{0, 8, 24, 25, 32}
	poolPrefix6 = []int{0, 32, 64, 96, 128}
	poolPorts   = []uint16{0, 1, 53, 79, 80, 81, 443, 65535}
	poolProtos  = []uint8{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, 50}
)

func pick[T any](rng *rand.Rand, s []T) T { return s[rng.IntN(len(s))] }

func randomAddr(rng *rand.Rand, v4 bool) netip.Addr {
	if v4 {
		return netip.MustParseAddr(pick(rng, poolV4))
	}
	return netip.MustParseAddr(pick(rng, poolV6))
}

func randomPrefixes(rng *rand.Rand, fam *Family) []netip.Prefix {
	if rng.IntN(3) == 0 {
		return nil
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for range 1 + rng.IntN(3) {
		v4 := rng.IntN(2) == 0
		if fam != nil {
			v4 = *fam == FamilyIPv4
		}
		bits := pick(rng, poolPrefix6)
		if v4 {
			bits = pick(rng, poolPrefix4)
		}
		p := netip.PrefixFrom(randomAddr(rng, v4), bits).Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func randomRanges(rng *rand.Rand) []PortRange {
	if rng.IntN(2) == 0 {
		return nil
	}
	a, b := pick(rng, poolPorts), pick(rng, poolPorts)
	if a > b {
		a, b = b, a
	}
	out := []PortRange{{a, b}}
	if b < 65000 && rng.IntN(2) == 0 {
		out = append(out, PortRange{b + 1, b + 1 + uint16(rng.IntN(100))})
	}
	return out
}

func randomPolicy(rng *rand.Rand, loose bool) Policy {
	var p Policy
	for i := range 1 + rng.IntN(6) {
		r := Rule{Name: string(rune('a' + i)), Allow: rng.IntN(2) == 0}
		m := &r.Match
		if rng.IntN(2) == 0 {
			m.Path = new(Path(1 + rng.IntN(3)))
		}
		if rng.IntN(3) == 0 {
			m.Family = new(pick(rng, []Family{FamilyIPv4, FamilyIPv6}))
		}
		switch rng.IntN(4) {
		case 0:
			m.Proto = new(pick(rng, []uint8{ProtoTCP, ProtoUDP}))
			m.SourcePorts, m.DestPorts = randomRanges(rng), randomRanges(rng)
		case 1:
			if loose {
				m.Proto = new(pick(rng, []uint8{ProtoICMP, ProtoICMPv6}))
			} else if m.Family == nil || *m.Family == FamilyIPv4 {
				m.Proto = new(ProtoICMP)
			} else {
				m.Proto = new(ProtoICMPv6)
			}
			if rng.IntN(2) == 0 {
				m.ICMP = &ICMP{Type: uint8(rng.IntN(4)), Code: uint8(rng.IntN(2)), HasCode: rng.IntN(2) == 0}
			}
		}
		fam := m.Family
		if loose {
			fam = nil
		} else if m.Proto != nil && (*m.Proto == ProtoICMP || *m.Proto == ProtoICMPv6) {
			f := FamilyIPv4
			if *m.Proto == ProtoICMPv6 {
				f = FamilyIPv6
			}
			fam = &f
		}
		m.Source, m.Destination = randomPrefixes(rng, fam), randomPrefixes(rng, fam)
		p.Rules = append(p.Rules, r)
	}
	return p
}

func randomPacket(rng *rand.Rand) Packet {
	v4 := rng.IntN(2) == 0
	pkt := Packet{
		Path: Path(rng.IntN(4)),
		Src:  randomAddr(rng, v4), Dst: randomAddr(rng, v4),
		Proto: pick(rng, poolProtos),
	}
	pkt.SrcPort, pkt.DstPort = pick(rng, poolPorts), pick(rng, poolPorts)
	pkt.ICMPType, pkt.ICMPCode = uint8(rng.IntN(4)), uint8(rng.IntN(2))
	return pkt
}

// TestCompileRefusesOverTheLimit checks Compile itself, not only FromAPI,
// refuses rather than truncates.
func TestCompileRefusesOverTheLimit(t *testing.T) {
	src := make([]netip.Prefix, 0, 257)
	for i := range 257 {
		src = append(src, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32))
	}
	entries, err := Compile(Policy{Rules: []Rule{{Name: "big", Allow: true, Match: Match{Source: src}}}})
	if err == nil || entries != nil {
		t.Fatalf("Compile = %d entries, %v; want nil and an error", len(entries), err)
	}
}

// TestUnreachable reports a rule whose address lists cannot share a family.
func TestUnreachable(t *testing.T) {
	p := mustPolicy(t, `[
		{"name":"v4-to-v6","action":"Allow","match":{"sourceIPs":["192.0.2.1"],"destinationIPs":["2001:db8::1"]}},
		{"name":"deny-all","action":"Deny"}]`)
	if got := p.Unreachable(); len(got) != 1 || got[0] != 0 {
		t.Errorf("Unreachable = %v, want [0]", got)
	}
}
