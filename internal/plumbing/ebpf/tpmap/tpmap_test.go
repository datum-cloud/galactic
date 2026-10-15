// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package tpmap

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/apimachinery/pkg/util/validation/field"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/trafficpolicy"
)

const (
	tcActUnspec = ^uint32(0) // TC_ACT_UNSPEC is -1
	tcActShot   = 2

	// ifindex is the interface BPF_PROG_TEST_RUN delivers on: the test
	// network namespace's loopback.
	ifindex uint32 = 1
	token   uint64 = 0x5eed
	tableID uint32 = 7
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to load BPF programs and maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// fixture is a loaded datapath with ifindex registered as a tenant
// attachment whose VRF has no egress route, so an allowed packet leaves
// usid_egress as TC_ACT_UNSPEC and a denied one as TC_ACT_SHOT.
type fixture struct {
	objs *prog.UsidObjects
	maps *Maps
}

func newFixture(t *testing.T, mode uint32) *fixture {
	t.Helper()
	requireRoot(t)
	var objs prog.UsidObjects
	if err := prog.LoadUsidObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected the datapath:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	const block, argument = 0xABCDEF, 0x100
	if err := objs.IfindexVrfTable.Put(ifindex, prog.UsidIfindexVrfValue{Block: block, Argument: argument}); err != nil {
		t.Fatal(err)
	}
	vrfKey, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		t.Fatal(err)
	}
	if err := objs.VrfTable.Put(uint64(vrfKey), prog.UsidVrfValue{VrfTableId: tableID}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{objs: &objs, maps: FromObjects(&objs)}
	if err := f.maps.SetState(mode, true); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) iface(t *testing.T) {
	t.Helper()
	if err := f.maps.PutInterface(ifindex, token, KindTenant); err != nil {
		t.Fatal(err)
	}
}

// publish compiles rules and binds them to ifindex's egress with counter
// rows starting at base.
func (f *fixture) publish(t *testing.T, rules string, base uint32) trafficpolicy.Policy {
	t.Helper()
	p := policy(t, rules)
	entries, err := trafficpolicy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.maps.ZeroCounters(base, uint32(len(p.Rules))); err != nil {
		t.Fatal(err)
	}
	if err := f.maps.Publish(ifindex, DirEgress, token, base, entries); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) run(t *testing.T, pkt []byte) uint32 {
	t.Helper()
	ret, _, err := f.objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret
}

func policy(t *testing.T, rules string) trafficpolicy.Policy {
	t.Helper()
	var spec galacticv1alpha1.TrafficPolicySpec
	if err := json.Unmarshal([]byte(`{"rules":`+rules+`}`), &spec); err != nil {
		t.Fatal(err)
	}
	p, errs := trafficpolicy.FromAPI(spec, field.NewPath("spec"))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return p
}

func sumCounter(t *testing.T, m *ebpf.Map, key any) prog.UsidTpCounter {
	t.Helper()
	var per []prog.UsidTpCounter
	if err := m.Lookup(key, &per); err != nil {
		t.Fatalf("lookup counter %v: %v", key, err)
	}
	var sum prog.UsidTpCounter
	for _, c := range per {
		sum.Packets += c.Packets
		sum.Bytes += c.Bytes
	}
	return sum
}

// packet builds an Ethernet frame carrying p, with a TCP or UDP header, or
// an ICMP header for protocols 1 and 58.
func packet(p trafficpolicy.Packet) []byte {
	var l4 []byte
	switch p.Proto {
	case trafficpolicy.ProtoTCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:], p.SrcPort)
		binary.BigEndian.PutUint16(l4[2:], p.DstPort)
		l4[12] = 0x50
	case trafficpolicy.ProtoUDP:
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:], p.SrcPort)
		binary.BigEndian.PutUint16(l4[2:], p.DstPort)
		binary.BigEndian.PutUint16(l4[4:], 8)
	default:
		l4 = []byte{p.ICMPType, p.ICMPCode, 0, 0, 0, 0, 0, 0}
	}
	frame := []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0, 0}
	if p.Src.Is4() {
		binary.BigEndian.PutUint16(frame[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4))) //nolint:gosec // tiny
		ip[8] = 64
		ip[9] = p.Proto
		s, d := p.Src.As4(), p.Dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		return append(append(frame, ip...), l4...)
	}
	binary.BigEndian.PutUint16(frame[12:], 0x86DD)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4))) //nolint:gosec // tiny
	ip[6] = p.Proto
	ip[7] = 64
	s, d := p.Src.As16(), p.Dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(append(frame, ip...), l4...)
}

func tcp(src, dst string, sport, dport uint16) trafficpolicy.Packet {
	return trafficpolicy.Packet{Path: trafficpolicy.PathPrivate, Src: netip.MustParseAddr(src),
		Dst: netip.MustParseAddr(dst), Proto: trafficpolicy.ProtoTCP, SrcPort: sport, DstPort: dport}
}

// TestModeOffChangesNothing pins the inert default: with no state, or mode
// off, a deny-all binding does not drop.
func TestModeOffChangesNothing(t *testing.T) {
	f := newFixture(t, ModeOff)
	f.iface(t)
	f.publish(t, `[{"name":"deny-all","action":"Deny"}]`, 0)
	if got := f.run(t, packet(tcp("2001:db8::1", "2001:db8::2", 1000, 80))); got != tcActUnspec {
		t.Errorf("verdict = %d, want TC_ACT_UNSPEC with enforcement off", got)
	}
	if c := sumCounter(t, f.objs.TpRuleCounters, uint32(0)); c.Packets != 0 {
		t.Errorf("mode off counted %d packets", c.Packets)
	}
}

// TestMissingStateDenies covers the fail-closed rows of the binding table:
// no interface row, no binding, and a binding for another interface
// lifetime all deny, each counted where it can be attributed.
func TestMissingStateDenies(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	pkt := packet(tcp("2001:db8::1", "2001:db8::2", 1000, 80))

	if got := f.run(t, pkt); got != tcActShot {
		t.Fatalf("no interface row: verdict = %d, want TC_ACT_SHOT", got)
	}
	unattributed := sumCounter(t, f.objs.TpUnattributedCounters, DirEgress*reasonCount+uint32(ReasonPolicyUnavailable))
	if unattributed.Packets != 1 {
		t.Errorf("unattributed policy_unavailable = %d, want 1", unattributed.Packets)
	}

	f.iface(t)
	if got := f.run(t, pkt); got != tcActShot {
		t.Fatalf("no binding: verdict = %d, want TC_ACT_SHOT", got)
	}
	fb := sumCounter(t, f.objs.TpFallbackCounters, FallbackKey(ifindex, token, DirEgress, ReasonPolicyUnavailable))
	if fb.Packets != 1 || fb.Bytes != uint64(len(pkt)-14) {
		t.Errorf("fallback policy_unavailable = %+v, want 1 packet of %d bytes", fb, len(pkt)-14)
	}

	// A snapshot published for an earlier interface lifetime on a recycled
	// ifindex never applies.
	p := policy(t, `[{"name":"all","action":"Allow"}]`)
	entries, _ := trafficpolicy.Compile(p)
	if err := f.maps.Publish(ifindex, DirEgress, token+1, 0, entries); err != nil {
		t.Fatal(err)
	}
	if got := f.run(t, pkt); got != tcActShot {
		t.Errorf("stale token: verdict = %d, want TC_ACT_SHOT", got)
	}

	// Invalidation needs no allocation and denies at once.
	f.publish(t, `[{"name":"all","action":"Allow"}]`, 0)
	if got := f.run(t, pkt); got != tcActUnspec {
		t.Fatalf("allow-all: verdict = %d, want TC_ACT_UNSPEC", got)
	}
	if err := f.maps.Invalidate(ifindex, DirEgress); err != nil {
		t.Fatal(err)
	}
	if got := f.run(t, pkt); got != tcActShot {
		t.Errorf("after invalidation: verdict = %d, want TC_ACT_SHOT", got)
	}
}

// TestDefaultDenyCountsTheRule checks the built-in default's one rule is a
// rule hit, not a fallback.
func TestDefaultDenyCountsTheRule(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	f.publish(t, `[{"name":"deny-all","action":"Deny"}]`, 40)
	pkt := packet(tcp("192.0.2.1", "198.51.100.1", 1000, 25))
	if got := f.run(t, pkt); got != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT", got)
	}
	if c := sumCounter(t, f.objs.TpRuleCounters, uint32(40)); c.Packets != 1 || c.Bytes != uint64(len(pkt)-14) {
		t.Errorf("deny-all counter = %+v, want 1 packet of %d bytes", c, len(pkt)-14)
	}
	noMatch := FallbackKey(ifindex, token, DirEgress, ReasonNoMatch)
	if fb := sumCounter(t, f.objs.TpFallbackCounters, noMatch); fb.Packets != 0 {
		t.Errorf("no_match = %d, want 0", fb.Packets)
	}
}

// TestAuditCountsButForwards checks mode audit records the deny it would
// apply and forwards anyway.
func TestAuditCountsButForwards(t *testing.T) {
	f := newFixture(t, ModeAudit)
	f.iface(t)
	f.publish(t, `[{"name":"deny-all","action":"Deny"}]`, 0)
	if got := f.run(t, packet(tcp("2001:db8::1", "2001:db8::2", 1, 2))); got != tcActUnspec {
		t.Fatalf("verdict = %d, want TC_ACT_UNSPEC in audit", got)
	}
	if c := sumCounter(t, f.objs.TpRuleCounters, uint32(0)); c.Packets != 1 {
		t.Errorf("deny-all counted %d in audit, want 1", c.Packets)
	}
}

// TestParseErrorsBeforeRules checks fragments and malformed headers are
// dropped before any rule, so even an allow-all cannot let them through.
func TestParseErrorsBeforeRules(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	f.publish(t, `[{"name":"all","action":"Allow"}]`, 0)

	frag4 := packet(tcp("192.0.2.1", "198.51.100.1", 1, 2))
	frag4[14+6] = 0x20 // MF
	frag6 := packet(tcp("2001:db8::1", "2001:db8::2", 1, 2))
	frag6[14+6] = 44 // a Fragment header
	segmentsLeft := packet(tcp("2001:db8::1", "2001:db8::2", 1, 2))
	segmentsLeft[14+6] = 43
	copy(segmentsLeft[14+40:], []byte{6, 0, 0, 1, 0, 0, 0, 0}) // Routing, 8 bytes, segments left 1
	truncated := packet(tcp("2001:db8::1", "2001:db8::2", 1, 2))[:14+40+2]
	truncated[14+5] = 2 // payload length 2: no room for a TCP header

	for name, pkt := range map[string][]byte{
		"ipv4 fragment": frag4, "ipv6 fragment": frag6, "routing header with segments left": segmentsLeft,
		"truncated tcp": truncated,
	} {
		if got := f.run(t, pkt); got != tcActShot {
			t.Errorf("%s: verdict = %d, want TC_ACT_SHOT", name, got)
		}
	}
	parseErrors := FallbackKey(ifindex, token, DirEgress, ReasonParseError)
	if fb := sumCounter(t, f.objs.TpFallbackCounters, parseErrors); fb.Packets != 4 {
		t.Errorf("parse_error = %d, want 4", fb.Packets)
	}
	if c := sumCounter(t, f.objs.TpRuleCounters, uint32(0)); c.Packets != 0 {
		t.Errorf("allow-all counted %d, want 0: parse errors precede the rules", c.Packets)
	}
}

// TestLinkOperations checks the narrow neighbor discovery and ARP allowlist
// passes under a deny-all, and that the same message types aimed elsewhere
// are ordinary traffic.
func TestLinkOperations(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	f.publish(t, `[{"name":"deny-all","action":"Deny"}]`, 0)
	if err := f.maps.PutInterfaceAddr(ifindex, netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if err := f.objs.TenantGwTable.Put(ifindex, prog.UsidTenantGwValue{Gw4: [4]byte{192, 0, 2, 1}}); err != nil {
		t.Fatal(err)
	}

	ns := func(src, dst string, hop byte) []byte {
		p := packet(trafficpolicy.Packet{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
			Proto: trafficpolicy.ProtoICMPv6, ICMPType: 135})
		p = append(p, make([]byte, 16)...) // the target address: NS is 24 bytes
		binary.BigEndian.PutUint16(p[14+4:], 24)
		p[14+7] = hop
		return p
	}
	arp := func(sender, target string) []byte {
		p := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 2, 0x08, 0x06,
			0, 1, 0x08, 0x00, 6, 4, 0, 1, 2, 0, 0, 0, 0, 2}
		s := netip.MustParseAddr(sender).As4()
		p = append(p, s[:]...)
		p = append(p, 0, 0, 0, 0, 0, 0)
		d := netip.MustParseAddr(target).As4()
		return append(p, d[:]...)
	}
	rs := func(src, dst string) []byte {
		p := packet(trafficpolicy.Packet{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
			Proto: trafficpolicy.ProtoICMPv6, ICMPType: 133})
		p[14+7] = 255
		return p
	}
	tests := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"neighbor solicitation to a solicited-node group", ns("fe80::1", "ff02::1:ff00:2", 255), tcActUnspec},
		{"neighbor solicitation forwarded", ns("fe80::1", "ff02::1:ff00:2", 254), tcActShot},
		{"neighbor solicitation to another tenant", ns("fe80::1", "2001:db8::99", 255), tcActShot},
		{"arp for the gateway", arp("192.0.2.10", "192.0.2.1"), tcActUnspec},
		{"gratuitous arp", arp("192.0.2.10", "192.0.2.10"), tcActUnspec},
		{"arp from an address not assigned", arp("192.0.2.66", "192.0.2.1"), tcActShot},
		{"arp for another host", arp("192.0.2.10", "192.0.2.77"), tcActShot},
		{"router solicitation", rs("fe80::1", "ff02::2"), tcActUnspec},
		{"neighbor solicitation behind a hop-by-hop header", hbh(ns("fe80::1", "ff02::1:ff00:2", 255)), tcActShot},
		{"arp probe for an own address", arp("0.0.0.0", "192.0.2.10"), tcActUnspec},
		{"other ethertype", append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x88, 0xcc}, make([]byte, 46)...), tcActShot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.run(t, tt.pkt); got != tt.want {
				t.Errorf("verdict = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestPathClassification checks an egress route to a NAT shard's locator
// is PublicNAT, any other remote route Private, and that before the NAT
// locators have synced a path rule the packet otherwise matches denies.
func TestPathClassification(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	f.publish(t, `[{"name":"nat-only","action":"Allow","match":{"path":"PublicNAT"}}]`, 0)

	shard := netip.MustParseAddr("fc00:0:ff01:1::")
	peer := netip.MustParseAddr("fc00:0:2:1::")
	route := func(dst string, sid netip.Addr) {
		d := netip.MustParseAddr(dst)
		key := prog.UsidEgressRouteKey{Prefixlen: 8*5 + 128, TableId: tableID, Family: 0, Addr: d.As16()}
		if err := f.objs.EgressRouteTable.Put(key, prog.UsidEgressRouteValue{Sid: sid.As16(), LinkIfindex: 1}); err != nil {
			t.Fatal(err)
		}
	}
	route("2001:db8:aa::1", shard)
	route("2001:db8:bb::1", peer)
	if err := f.maps.AddNATLocator(shard); err != nil {
		t.Fatal(err)
	}
	// No node source address is configured, so an allowed packet leaves at
	// that check as TC_ACT_UNSPEC after being decided on the route's path.
	if got := f.run(t, packet(tcp("2001:db8::1", "2001:db8:aa::1", 1, 2))); got != tcActUnspec {
		t.Errorf("to a NAT shard: verdict = %d, want allowed", got)
	}
	if got := f.run(t, packet(tcp("2001:db8::1", "2001:db8:bb::1", 1, 2))); got != tcActShot {
		t.Errorf("to a peer: verdict = %d, want denied", got)
	}
	if err := f.maps.SetState(ModeEnforce, false); err != nil {
		t.Fatal(err)
	}
	if got := f.run(t, packet(tcp("2001:db8::1", "2001:db8:aa::1", 1, 2))); got != tcActShot {
		t.Errorf("before sync: verdict = %d, want denied", got)
	}
	ce := sumCounter(t, f.objs.TpFallbackCounters, FallbackKey(ifindex, token, DirEgress, ReasonClassificationError))
	if ce.Packets != 1 {
		t.Errorf("classification_error = %d, want 1", ce.Packets)
	}
}

// TestMatchesTheEvaluator is the datapath's oracle test: for random valid
// policies and packets, usid_egress drops exactly when the Go evaluator
// denies, and counts the evaluator's winning rule or fallback once.
func TestMatchesTheEvaluator(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	rng := rand.New(rand.NewPCG(7, 11))
	for range 150 {
		rules := randomRules(rng)
		p := f.publish(t, rules, 0)
		before := ruleCounts(t, f, len(p.Rules))
		beforeNoMatch := sumCounter(t, f.objs.TpFallbackCounters, FallbackKey(ifindex, token, DirEgress, ReasonNoMatch))
		for range 20 {
			pkt := randomPacket(rng)
			want := trafficpolicy.Evaluate(p, pkt)
			got := f.run(t, packet(pkt))
			if (got == tcActShot) != !want.Allow {
				t.Fatalf("rules %s\npacket %+v\nverdict %d, evaluator %+v", rules, pkt, got, want)
			}
			after := ruleCounts(t, f, len(p.Rules))
			afterNoMatch := sumCounter(t, f.objs.TpFallbackCounters, FallbackKey(ifindex, token, DirEgress, ReasonNoMatch))
			for i := range p.Rules {
				delta := after[i] - before[i]
				if wantDelta := uint64(b2i(want.Rule == i)); delta != wantDelta {
					t.Fatalf("rules %s\npacket %+v: rule %d counted %d, want %d", rules, pkt, i, delta, wantDelta)
				}
			}
			if d := afterNoMatch.Packets - beforeNoMatch.Packets; d != uint64(b2i(want.Reason == trafficpolicy.ReasonNoMatch)) {
				t.Fatalf("rules %s\npacket %+v: no_match counted %d", rules, pkt, d)
			}
			before, beforeNoMatch = after, afterNoMatch
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ruleCounts(t *testing.T, f *fixture, n int) []uint64 {
	t.Helper()
	out := make([]uint64, n)
	for i := range out {
		out[i] = sumCounter(t, f.objs.TpRuleCounters, uint32(i)).Packets //nolint:gosec // small
	}
	return out
}

var (
	pool4 = []string{"192.0.2.1", "192.0.2.200", "198.51.100.7"}
	pool6 = []string{"2001:db8::1", "2001:db8::ff", "2001:db8:1::1"}
)

func pick[T any](rng *rand.Rand, s []T) T { return s[rng.IntN(len(s))] }

// randomRules is a valid rules array drawn from small pools, so rules and
// packets collide often. The path is always Private or absent, since a
// route miss is a Private exit.
func randomRules(rng *rand.Rand) string {
	n := 1 + rng.IntN(5)
	rules := make([]map[string]any, 0, n)
	for i := range n {
		m := map[string]any{}
		v4 := rng.IntN(2) == 0
		if rng.IntN(3) == 0 {
			m["path"] = pick(rng, []string{"Private", "PublicNAT"})
		}
		pool, fam, bits := pool6, "IPv6", []int{0, 32, 48, 64, 128}
		if v4 {
			pool, fam, bits = pool4, "IPv4", []int{0, 8, 24, 25, 32}
		}
		if rng.IntN(2) == 0 {
			m["ipFamily"] = fam
		}
		switch rng.IntN(3) {
		case 0:
			proto := pick(rng, []string{"TCP", "UDP"})
			m["protocol"] = proto
			if rng.IntN(2) == 0 {
				lo := pick(rng, []int{0, 79, 80, 1024})
				m["destinationPorts"] = []map[string]int{{"start": lo, "end": lo + rng.IntN(3)}}
			}
		case 1:
			if v4 {
				m["protocol"] = "ICMP"
			} else {
				m["protocol"] = "ICMPv6"
			}
			if rng.IntN(2) == 0 {
				m["icmp"] = map[string]int{"type": rng.IntN(3)}
			}
		}
		if rng.IntN(2) == 0 {
			p := netip.PrefixFrom(netip.MustParseAddr(pick(rng, pool)), pick(rng, bits)).Masked()
			m["destinationCIDRs"] = []string{p.String()}
		}
		if rng.IntN(3) == 0 {
			m["sourceIPs"] = []string{pick(rng, pool)}
		}
		action := "Deny"
		if rng.IntN(2) == 0 {
			action = "Allow"
		}
		rules = append(rules, map[string]any{"name": string(rune('a' + i)), "action": action, "match": m})
	}
	b, _ := json.Marshal(rules)
	return string(b)
}

func randomPacket(rng *rand.Rand) trafficpolicy.Packet {
	pool := pool6
	icmp := trafficpolicy.ProtoICMPv6
	if rng.IntN(2) == 0 {
		pool, icmp = pool4, trafficpolicy.ProtoICMP
	}
	return trafficpolicy.Packet{
		Path:    trafficpolicy.PathPrivate,
		Src:     netip.MustParseAddr(pick(rng, pool)),
		Dst:     netip.MustParseAddr(pick(rng, pool)),
		Proto:   pick(rng, []uint8{trafficpolicy.ProtoTCP, trafficpolicy.ProtoUDP, icmp}),
		SrcPort: pick(rng, []uint16{1, 80, 1024}), DstPort: pick(rng, []uint16{0, 79, 80, 81, 1024, 1025}),
		ICMPType: uint8(rng.IntN(3)), //nolint:gosec // small
	}
}

// TestPublicationIsAtomic races snapshot replacement against packets: every
// packet's verdict must come from one whole snapshot, and its count land in
// that snapshot's own row, which is never freed while it can still be
// written.
func TestPublicationIsAtomic(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	alloc := NewCounterAllocator(RuleCounterRows)
	allow := policy(t, `[{"name":"all","action":"Allow"}]`)
	deny := policy(t, `[{"name":"all","action":"Deny"}]`)
	allowEntries, _ := trafficpolicy.Compile(allow)
	denyEntries, _ := trafficpolicy.Compile(deny)

	var (
		mu        sync.Mutex
		allowRows []uint32 // rows of every allow snapshot ever published
		denyRows  []uint32
		stop      atomic.Bool
		pubErr    error
		wg        sync.WaitGroup
	)
	publish := func(entries []trafficpolicy.Entry, isAllow bool) (uint32, error) {
		base, err := alloc.Allocate(1)
		if err != nil {
			return 0, err
		}
		if err := f.maps.ZeroCounters(base, 1); err != nil {
			return 0, err
		}
		mu.Lock()
		if isAllow {
			allowRows = append(allowRows, base)
		} else {
			denyRows = append(denyRows, base)
		}
		mu.Unlock()
		return base, f.maps.Publish(ifindex, DirEgress, token, base, entries)
	}
	if _, err := publish(allowEntries, true); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load() && i < 400; i++ {
			// Alternate; rows are never freed here, so a late count still
			// lands in the row its snapshot named.
			if _, err := publish(map[bool][]trafficpolicy.Entry{true: allowEntries, false: denyEntries}[i%2 == 1],
				i%2 == 1); err != nil {
				pubErr = err
				return
			}
		}
	}()
	var allowed, denied uint64
	pkt := packet(tcp("2001:db8::1", "2001:db8::2", 1, 2))
	for range 3000 {
		if f.run(t, pkt) == tcActShot {
			denied++
		} else {
			allowed++
		}
	}
	stop.Store(true)
	wg.Wait()
	if pubErr != nil {
		t.Fatal(pubErr)
	}
	sum := func(rows []uint32) uint64 {
		var n uint64
		for _, r := range rows {
			n += sumCounter(t, f.objs.TpRuleCounters, r).Packets
		}
		return n
	}
	if got := sum(allowRows); got != allowed {
		t.Errorf("allow rows counted %d, %d packets were allowed", got, allowed)
	}
	if got := sum(denyRows); got != denied {
		t.Errorf("deny rows counted %d, %d packets were denied", got, denied)
	}
}

// hbh inserts an 8-byte Hop-by-Hop header after pkt's IPv6 header.
func hbh(pkt []byte) []byte {
	out := append([]byte{}, pkt[:14+40]...)
	next := out[14+6]
	out[14+6] = 0 // Hop-by-Hop
	binary.BigEndian.PutUint16(out[14+4:], binary.BigEndian.Uint16(out[14+4:])+8)
	out = append(out, next, 0, 1, 4, 0, 0, 0, 0) // PadN
	return append(out, pkt[14+40:]...)
}

// TestExtensionHeaders checks an allowed extension header leaves the ports
// visible to the rules, and ESP is matched by protocol alone.
func TestExtensionHeaders(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.iface(t)
	f.publish(t, `[{"name":"web","action":"Allow","match":{"protocol":"TCP","destinationPorts":[{"start":80,"end":80}]}},
		{"name":"echo","action":"Allow","match":{"protocol":"ICMPv6","icmp":{"type":128}}}]`, 0)
	if got := f.run(t, hbh(packet(tcp("2001:db8::1", "2001:db8::2", 1, 80)))); got != tcActUnspec {
		t.Errorf("tcp/80 behind hop-by-hop: verdict = %d, want allowed", got)
	}
	if got := f.run(t, hbh(packet(tcp("2001:db8::1", "2001:db8::2", 1, 81)))); got != tcActShot {
		t.Errorf("tcp/81 behind hop-by-hop: verdict = %d, want denied", got)
	}
	esp := packet(tcp("2001:db8::1", "2001:db8::2", 1, 80))
	esp[14+6] = 50
	if got := f.run(t, esp); got != tcActShot {
		t.Errorf("esp: verdict = %d, want denied: no rule names it", got)
	}
}
