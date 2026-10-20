// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficpolicy

import (
	"net/netip"
	"reflect"
)

// Packet is the parsed packet a policy decides: the tenant-visible addresses
// and transport fields at the evaluation point, and its forwarding path.
// Ports are read only when Proto is TCP or UDP, ICMP fields only when Proto
// is ICMP or ICMPv6. Src and Dst are always of one family, as on the wire.
type Packet struct {
	Path     Path
	Src, Dst netip.Addr
	Proto    uint8
	SrcPort  uint16
	DstPort  uint16
	ICMPType uint8
	ICMPCode uint8
}

// Family is the packet's address family.
func (p Packet) Family() Family { return familyOf(p.Src) }

// Reason is why a verdict was reached.
type Reason uint8

const (
	// ReasonRule is a verdict a rule supplied.
	ReasonRule Reason = iota
	// ReasonNoMatch is a deny because no rule matched.
	ReasonNoMatch
	// ReasonClassificationError is a deny because a rule naming a path
	// matched every other field of a packet whose path is unknown.
	ReasonClassificationError
)

// String returns the reason's metric label value.
func (r Reason) String() string {
	switch r {
	case ReasonRule:
		return "rule"
	case ReasonNoMatch:
		return "no_match"
	default:
		return "classification_error"
	}
}

// Verdict is a policy decision. Rule is the winning rule's index, or -1 when
// Reason is not ReasonRule.
type Verdict struct {
	Allow  bool
	Rule   int
	Reason Reason
}

// Evaluate decides pkt against p: the first rule that matches supplies the
// verdict, and a packet no rule matches is denied.
//
// A packet whose path is unknown is still evaluated. A rule without a path
// is matched normally. A rule with a path whose other fields do not match is
// skipped, since it could not decide the packet on any path. A rule with a
// path whose other fields all match ends evaluation with a classification
// deny, so a failed classification can never skip an earlier rule and reach
// a broader Allow.
func Evaluate(p Policy, pkt Packet) Verdict {
	for i, r := range p.Rules {
		if !matchesExceptPath(&r.Match, pkt) {
			continue
		}
		if r.Match.Path != nil {
			if pkt.Path == PathUnknown {
				return Verdict{Rule: -1, Reason: ReasonClassificationError}
			}
			if *r.Match.Path != pkt.Path {
				continue
			}
		}
		return Verdict{Allow: r.Allow, Rule: i, Reason: ReasonRule}
	}
	return Verdict{Rule: -1, Reason: ReasonNoMatch}
}

func matchesExceptPath(m *Match, pkt Packet) bool {
	fam := pkt.Family()
	if m.Family != nil && *m.Family != fam {
		return false
	}
	if m.Proto != nil {
		if *m.Proto != pkt.Proto {
			return false
		}
		// Protocol 1 inside IPv6, or 58 inside IPv4, is not the ICMP the
		// rule names.
		if (*m.Proto == ProtoICMP && fam != FamilyIPv4) || (*m.Proto == ProtoICMPv6 && fam != FamilyIPv6) {
			return false
		}
	}
	if len(m.Source) > 0 && !anyContains(m.Source, pkt.Src) {
		return false
	}
	if len(m.Destination) > 0 && !anyContains(m.Destination, pkt.Dst) {
		return false
	}
	if len(m.SourcePorts) > 0 && !anyPort(m.SourcePorts, pkt.SrcPort) {
		return false
	}
	if len(m.DestPorts) > 0 && !anyPort(m.DestPorts, pkt.DstPort) {
		return false
	}
	if m.ICMP != nil && (pkt.ICMPType != m.ICMP.Type || (m.ICMP.HasCode && pkt.ICMPCode != m.ICMP.Code)) {
		return false
	}
	return true
}

// anyContains reports whether a is in any of ps. A prefix never contains an
// address of the other family.
func anyContains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func anyPort(rs []PortRange, port uint16) bool {
	for _, r := range rs {
		if r.Contains(port) {
			return true
		}
	}
	return false
}

// Shadowed returns, for each rule an earlier rule fully covers, the index of
// that earlier rule. It recognizes a catch-all and an identical match; it is
// a warning aid, not a complete subsumption check.
func Shadowed(p Policy) map[int]int {
	out := map[int]int{}
	for i, r := range p.Rules {
		for j := range i {
			if reflect.DeepEqual(p.Rules[j].Match, Match{}) || reflect.DeepEqual(p.Rules[j].Match, r.Match) {
				out[i] = j
				break
			}
		}
	}
	return out
}
