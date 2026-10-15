// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficpolicy

import (
	"fmt"
	"net/netip"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// EntryFlag marks which fields of an Entry take part in matching. A clear
// flag means the field matches anything.
type EntryFlag uint16

const (
	// FlagAllow makes a matching entry allow; clear, it denies.
	FlagAllow EntryFlag = 1 << iota
	// FlagPath matches Entry.Path.
	FlagPath
	// FlagFamily matches Entry.Family.
	FlagFamily
	// FlagProto matches Entry.Proto.
	FlagProto
	// FlagSource matches Entry.Source.
	FlagSource
	// FlagDestination matches Entry.Destination.
	FlagDestination
	// FlagSourcePorts matches Entry.SourcePorts.
	FlagSourcePorts
	// FlagDestPorts matches Entry.DestPorts.
	FlagDestPorts
	// FlagICMPType matches Entry.ICMPType.
	FlagICMPType
	// FlagICMPCode matches Entry.ICMPCode.
	FlagICMPCode
)

// Entry is one compiled datapath entry: a conjunction of single-valued
// matches. A rule compiles to one entry per combination of its source,
// destination and port alternatives, all carrying the rule's index, so the
// entries a rule expands to share that rule's one counter.
type Entry struct {
	Flags       EntryFlag
	Rule        uint16
	Path        Path
	Family      Family
	Proto       uint8
	ICMPType    uint8
	ICMPCode    uint8
	Source      netip.Prefix
	Destination netip.Prefix
	SourcePorts PortRange
	DestPorts   PortRange
}

// EntryCount is how many entries p compiles to.
func (p Policy) EntryCount() int {
	n := 0
	for i, r := range p.Rules {
		n += len(expandRule(uint16(i), r))
	}
	return n
}

// Unreachable returns the indexes of rules that compile to no entries
// because no packet can satisfy them, such as an IPv4-only source list with
// an IPv6-only destination list. They are valid but never match.
func (p Policy) Unreachable() []int {
	var out []int
	for i, r := range p.Rules {
		if len(expandRule(uint16(i), r)) == 0 {
			out = append(out, i)
		}
	}
	return out
}

// addressPair is one source and destination combination; an invalid prefix
// means that side is unconstrained.
type addressPair struct{ src, dst netip.Prefix }

// addressPairs returns the address combinations of m, leaving out the ones
// whose sides are of different families: a packet has one family, so such a
// pair can never match.
func addressPairs(m *Match) []addressPair {
	srcs, dsts := m.Source, m.Destination
	if len(srcs) == 0 {
		srcs = []netip.Prefix{{}}
	}
	if len(dsts) == 0 {
		dsts = []netip.Prefix{{}}
	}
	out := make([]addressPair, 0, len(srcs)*len(dsts))
	for _, s := range srcs {
		for _, d := range dsts {
			if s.IsValid() && d.IsValid() && s.Addr().Is4() != d.Addr().Is4() {
				continue
			}
			out = append(out, addressPair{s, d})
		}
	}
	return out
}

// Compile lowers p to datapath entries in rule order. It fails when p
// compiles to more than MaxCompiledEntries; it never truncates or reorders.
func Compile(p Policy) ([]Entry, error) {
	if len(p.Rules) > galacticv1alpha1.MaxRules {
		return nil, fmt.Errorf("policy has %d rules, more than the limit of %d", len(p.Rules), galacticv1alpha1.MaxRules)
	}
	var out []Entry
	for i, r := range p.Rules {
		out = append(out, expandRule(uint16(i), r)...)
		if len(out) > galacticv1alpha1.MaxCompiledEntries {
			return nil, fmt.Errorf("policy compiles to %d entries, more than the limit of %d",
				p.EntryCount(), galacticv1alpha1.MaxCompiledEntries)
		}
	}
	return out, nil
}

// expandRule is the entries of rule r, one per combination of its address
// and port alternatives. A combination whose address family contradicts the
// rule's own family (from ipFamily or an ICMP protocol) is left out, as is a
// source and destination pair of different families: no packet could match
// it, so Evaluate never would either.
func expandRule(index uint16, r Rule) []Entry {
	if f, ok := protoFamily(r.Match.Proto); ok && r.Match.Family != nil && *r.Match.Family != f {
		return nil // ICMPv6 under ipFamily IPv4, or ICMP under IPv6
	}
	base := baseEntry(index, r)
	sports, dports := r.Match.SourcePorts, r.Match.DestPorts
	if len(sports) == 0 {
		sports = []PortRange{{}}
	}
	if len(dports) == 0 {
		dports = []PortRange{{}}
	}
	var out []Entry
	for _, ap := range addressPairs(&r.Match) {
		e := base
		if ap.src.IsValid() {
			e.Flags |= FlagSource
			e.Source = ap.src
		}
		if ap.dst.IsValid() {
			e.Flags |= FlagDestination
			e.Destination = ap.dst
		}
		if fam, ok := pairFamily(ap); ok {
			if base.Flags&FlagFamily != 0 && base.Family != fam {
				continue
			}
			e.Flags |= FlagFamily
			e.Family = fam
		}
		for _, sp := range sports {
			for _, dp := range dports {
				pe := e
				if len(r.Match.SourcePorts) > 0 {
					pe.Flags |= FlagSourcePorts
					pe.SourcePorts = sp
				}
				if len(r.Match.DestPorts) > 0 {
					pe.Flags |= FlagDestPorts
					pe.DestPorts = dp
				}
				out = append(out, pe)
			}
		}
	}
	return out
}

// protoFamily is the family an ICMP protocol implies, if any.
func protoFamily(proto *uint8) (Family, bool) {
	switch {
	case proto == nil:
		return 0, false
	case *proto == ProtoICMP:
		return FamilyIPv4, true
	case *proto == ProtoICMPv6:
		return FamilyIPv6, true
	}
	return 0, false
}

// pairFamily is the family a constrained side of ap fixes, if any.
func pairFamily(ap addressPair) (Family, bool) {
	switch {
	case ap.src.IsValid():
		return familyOf(ap.src.Addr()), true
	case ap.dst.IsValid():
		return familyOf(ap.dst.Addr()), true
	}
	return 0, false
}

// baseEntry is the part of every entry of rule r that does not vary between
// its alternatives.
func baseEntry(index uint16, r Rule) Entry {
	e := Entry{Rule: index}
	m := &r.Match
	if r.Allow {
		e.Flags |= FlagAllow
	}
	if m.Path != nil {
		e.Flags |= FlagPath
		e.Path = *m.Path
	}
	if m.Family != nil {
		e.Flags |= FlagFamily
		e.Family = *m.Family
	}
	if m.Proto != nil {
		e.Flags |= FlagProto
		e.Proto = *m.Proto
		if f, ok := protoFamily(m.Proto); ok {
			e.Flags |= FlagFamily
			e.Family = f
		}
	}
	if m.ICMP != nil {
		e.Flags |= FlagICMPType
		e.ICMPType = m.ICMP.Type
		if m.ICMP.HasCode {
			e.Flags |= FlagICMPCode
			e.ICMPCode = m.ICMP.Code
		}
	}
	return e
}

// EvaluateEntries decides pkt against compiled entries the way the datapath
// does: a linear first-match walk. It must agree with Evaluate on the policy
// the entries were compiled from; the tests hold it to that.
func EvaluateEntries(entries []Entry, pkt Packet) Verdict {
	for _, e := range entries {
		if !entryMatchesExceptPath(&e, pkt) {
			continue
		}
		if e.Flags&FlagPath != 0 {
			if pkt.Path == PathUnknown {
				return Verdict{Rule: -1, Reason: ReasonClassificationError}
			}
			if e.Path != pkt.Path {
				continue
			}
		}
		return Verdict{Allow: e.Flags&FlagAllow != 0, Rule: int(e.Rule), Reason: ReasonRule}
	}
	return Verdict{Rule: -1, Reason: ReasonNoMatch}
}

func entryMatchesExceptPath(e *Entry, pkt Packet) bool {
	switch {
	case e.Flags&FlagFamily != 0 && e.Family != pkt.Family():
		return false
	case e.Flags&FlagProto != 0 && e.Proto != pkt.Proto:
		return false
	case e.Flags&FlagSource != 0 && !e.Source.Contains(pkt.Src):
		return false
	case e.Flags&FlagDestination != 0 && !e.Destination.Contains(pkt.Dst):
		return false
	case e.Flags&FlagSourcePorts != 0 && !e.SourcePorts.Contains(pkt.SrcPort):
		return false
	case e.Flags&FlagDestPorts != 0 && !e.DestPorts.Contains(pkt.DstPort):
		return false
	case e.Flags&FlagICMPType != 0 && e.ICMPType != pkt.ICMPType:
		return false
	case e.Flags&FlagICMPCode != 0 && e.ICMPCode != pkt.ICMPCode:
		return false
	}
	return true
}
