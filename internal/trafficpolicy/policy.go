// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficpolicy is the reference semantics of a TrafficPolicy: a
// validated in-memory model, an evaluator that decides a packet against it,
// and a compiler that lowers it to the fixed-size entries the CNI datapath
// walks. The evaluator is the oracle the datapath's tests compare against; it
// is never on the packet path.
//
// See docs/enhancements/networking/interface-traffic-policy for the design.
package trafficpolicy

import (
	"fmt"
	"net/netip"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation/field"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Path is a packet's forwarding path. PathUnknown means classification
// failed; it is never a value a rule can name.
type Path uint8

const (
	// PathUnknown is a packet whose forwarding path could not be classified.
	PathUnknown Path = iota
	// PathPrivate is private VPC routing.
	PathPrivate
	// PathPublicNAT is traffic to or from a NAT shard.
	PathPublicNAT
	// PathPublicService is public service delivery and its replies.
	PathPublicService
)

// String returns the API spelling of p.
func (p Path) String() string {
	switch p {
	case PathPrivate:
		return string(galacticv1alpha1.PathPrivate)
	case PathPublicNAT:
		return string(galacticv1alpha1.PathPublicNAT)
	case PathPublicService:
		return string(galacticv1alpha1.PathPublicService)
	default:
		return "Unknown"
	}
}

// IP protocol numbers a rule can name.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// Family is 4 or 6.
type Family uint8

const (
	// FamilyIPv4 is IPv4.
	FamilyIPv4 Family = 4
	// FamilyIPv6 is IPv6.
	FamilyIPv6 Family = 6
)

// PortRange is an inclusive port range.
type PortRange struct {
	Start, End uint16
}

// Contains reports whether port is inside r.
func (r PortRange) Contains(port uint16) bool { return port >= r.Start && port <= r.End }

// ICMP matches a type and, when HasCode, a code.
type ICMP struct {
	Type    uint8
	Code    uint8
	HasCode bool
}

// Match is a validated TrafficRuleMatch. A nil pointer or empty slice means
// the field was omitted and matches anything. Exact addresses are stored as
// full-length prefixes, so Source and Destination each hold either the IP
// list or the CIDR list of their side, never both.
type Match struct {
	Path        *Path
	Family      *Family
	Proto       *uint8
	Source      []netip.Prefix
	Destination []netip.Prefix
	SourcePorts []PortRange
	DestPorts   []PortRange
	ICMP        *ICMP
}

// Rule is one validated rule.
type Rule struct {
	Name  string
	Allow bool
	Match Match
}

// Policy is a validated, ordered rule list.
type Policy struct {
	Rules []Rule
}

// Default is the built-in default policy: one rule that denies everything.
func Default() Policy {
	return Policy{Rules: []Rule{{Name: galacticv1alpha1.DefaultRuleName}}}
}

var ruleName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// FromAPI validates spec and returns its model. It re-checks everything the
// CRD schema checks, since a client can reach storage without it, and adds
// what the schema cannot express: duplicate addresses after canonicalization
// and the compiled entry limit. The errors are rooted at path.
//
// An explicit null cannot be seen here: decoding has already turned it into
// an omission. The admission webhook rejects nulls from the raw object
// before calling this.
func FromAPI(spec galacticv1alpha1.TrafficPolicySpec, path *field.Path) (Policy, field.ErrorList) {
	var errs field.ErrorList
	rulesPath := path.Child("rules")
	switch {
	case len(spec.Rules) == 0:
		errs = append(errs, field.Required(rulesPath, "a policy needs at least one rule"))
	case len(spec.Rules) > galacticv1alpha1.MaxRules:
		errs = append(errs, field.TooMany(rulesPath, len(spec.Rules), galacticv1alpha1.MaxRules))
	}

	p := Policy{Rules: make([]Rule, 0, len(spec.Rules))}
	seen := make(map[string]int, len(spec.Rules))
	for i, r := range spec.Rules {
		rp := rulesPath.Index(i)
		if !ruleName.MatchString(r.Name) || len(r.Name) > 63 {
			errs = append(errs, field.Invalid(rp.Child("name"), r.Name, "must be a DNS label"))
		}
		if j, dup := seen[r.Name]; dup {
			errs = append(errs, field.Duplicate(rp.Child("name"), fmt.Sprintf("%s (also rule %d)", r.Name, j)))
		}
		seen[r.Name] = i

		rule := Rule{Name: r.Name}
		switch r.Action {
		case galacticv1alpha1.ActionAllow:
			rule.Allow = true
		case galacticv1alpha1.ActionDeny:
		default:
			errs = append(errs, field.NotSupported(rp.Child("action"), r.Action,
				[]galacticv1alpha1.RuleAction{galacticv1alpha1.ActionAllow, galacticv1alpha1.ActionDeny}))
		}
		if r.Match != nil {
			m, merrs := matchFromAPI(*r.Match, rp.Child("match"))
			rule.Match = m
			errs = append(errs, merrs...)
		}
		p.Rules = append(p.Rules, rule)
	}
	if len(errs) > 0 {
		return Policy{}, errs
	}
	if n := p.EntryCount(); n > galacticv1alpha1.MaxCompiledEntries {
		return Policy{}, field.ErrorList{field.Invalid(rulesPath, n,
			fmt.Sprintf("compiles to %d datapath entries, more than the limit of %d; "+
				"a rule compiles to the product of its source, destination and port alternatives",
				n, galacticv1alpha1.MaxCompiledEntries))}
	}
	return p, nil
}

func matchFromAPI(in galacticv1alpha1.TrafficRuleMatch, path *field.Path) (Match, field.ErrorList) {
	var (
		m    Match
		errs field.ErrorList
	)
	if in.Path != nil {
		pth, err := pathFromAPI(*in.Path)
		if err != nil {
			errs = append(errs, field.NotSupported(path.Child("path"), *in.Path, []galacticv1alpha1.ForwardingPath{
				galacticv1alpha1.PathPrivate, galacticv1alpha1.PathPublicNAT, galacticv1alpha1.PathPublicService,
			}))
		} else {
			m.Path = &pth
		}
	}
	if in.IPFamily != nil {
		switch *in.IPFamily {
		case galacticv1alpha1.IPv4:
			m.Family = new(FamilyIPv4)
		case galacticv1alpha1.IPv6:
			m.Family = new(FamilyIPv6)
		default:
			errs = append(errs, field.NotSupported(path.Child("ipFamily"), *in.IPFamily,
				[]galacticv1alpha1.IPFamily{galacticv1alpha1.IPv4, galacticv1alpha1.IPv6}))
		}
	}
	var protoFamily *Family
	if in.Protocol != nil {
		switch *in.Protocol {
		case galacticv1alpha1.ProtocolTCP:
			m.Proto = new(ProtoTCP)
		case galacticv1alpha1.ProtocolUDP:
			m.Proto = new(ProtoUDP)
		case galacticv1alpha1.ProtocolICMP:
			m.Proto = new(ProtoICMP)
			protoFamily = new(FamilyIPv4)
		case galacticv1alpha1.ProtocolICMPv6:
			m.Proto = new(ProtoICMPv6)
			protoFamily = new(FamilyIPv6)
		default:
			errs = append(errs, field.NotSupported(path.Child("protocol"), *in.Protocol, []galacticv1alpha1.Protocol{
				galacticv1alpha1.ProtocolTCP, galacticv1alpha1.ProtocolUDP,
				galacticv1alpha1.ProtocolICMP, galacticv1alpha1.ProtocolICMPv6,
			}))
		}
	}
	if protoFamily != nil && m.Family != nil && *protoFamily != *m.Family {
		errs = append(errs, field.Invalid(path.Child("ipFamily"), *in.IPFamily,
			fmt.Sprintf("protocol %s requires ipFamily IPv%d", *in.Protocol, *protoFamily)))
	}
	want := m.Family
	if want == nil {
		want = protoFamily
	}

	if in.SourceIPs != nil && in.SourceCIDRs != nil {
		errs = append(errs, field.Forbidden(path.Child("sourceCIDRs"), "sourceIPs and sourceCIDRs are mutually exclusive"))
	}
	if in.DestinationIPs != nil && in.DestinationCIDRs != nil {
		errs = append(errs, field.Forbidden(path.Child("destinationCIDRs"),
			"destinationIPs and destinationCIDRs are mutually exclusive"))
	}
	var e field.ErrorList
	m.Source, e = addresses(in.SourceIPs, path.Child("sourceIPs"), want)
	errs = append(errs, e...)
	if in.SourceCIDRs != nil {
		m.Source, e = prefixes(in.SourceCIDRs, path.Child("sourceCIDRs"), want)
		errs = append(errs, e...)
	}
	m.Destination, e = addresses(in.DestinationIPs, path.Child("destinationIPs"), want)
	errs = append(errs, e...)
	if in.DestinationCIDRs != nil {
		m.Destination, e = prefixes(in.DestinationCIDRs, path.Child("destinationCIDRs"), want)
		errs = append(errs, e...)
	}

	hasPorts := in.SourcePorts != nil || in.DestinationPorts != nil
	if hasPorts && (m.Proto == nil || (*m.Proto != ProtoTCP && *m.Proto != ProtoUDP)) {
		errs = append(errs, field.Forbidden(path.Child("protocol"), "ports require protocol TCP or UDP"))
	}
	m.SourcePorts, e = portRanges(in.SourcePorts, path.Child("sourcePorts"))
	errs = append(errs, e...)
	m.DestPorts, e = portRanges(in.DestinationPorts, path.Child("destinationPorts"))
	errs = append(errs, e...)

	if in.ICMP != nil {
		if m.Proto == nil || (*m.Proto != ProtoICMP && *m.Proto != ProtoICMPv6) {
			errs = append(errs, field.Forbidden(path.Child("icmp"), "icmp requires protocol ICMP or ICMPv6"))
		}
		icmp, e := icmpFromAPI(*in.ICMP, path.Child("icmp"))
		m.ICMP = icmp
		errs = append(errs, e...)
	}
	return m, errs
}

func pathFromAPI(p galacticv1alpha1.ForwardingPath) (Path, error) {
	switch p {
	case galacticv1alpha1.PathPrivate:
		return PathPrivate, nil
	case galacticv1alpha1.PathPublicNAT:
		return PathPublicNAT, nil
	case galacticv1alpha1.PathPublicService:
		return PathPublicService, nil
	}
	return PathUnknown, fmt.Errorf("unknown path %q", p)
}

func familyOf(a netip.Addr) Family {
	if a.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// listBounds checks an optional list's length: omitted (nil) is the
// wildcard, and an explicit empty list is invalid.
func listBounds(n int, isNil bool, path *field.Path, maxItems int) field.ErrorList {
	switch {
	case isNil:
		return nil
	case n == 0:
		return field.ErrorList{field.Invalid(path, "[]", "must not be empty; omit the field to match anything")}
	case n > maxItems:
		return field.ErrorList{field.TooMany(path, n, maxItems)}
	}
	return nil
}

func checkFamily(f Family, want *Family, path *field.Path, value string) *field.Error {
	if want != nil && f != *want {
		return field.Invalid(path, value, fmt.Sprintf("must be an IPv%d address to match the rule's family", *want))
	}
	return nil
}

func addresses(in []string, path *field.Path, want *Family) ([]netip.Prefix, field.ErrorList) {
	errs := listBounds(len(in), in == nil, path, galacticv1alpha1.MaxAddresses)
	if in == nil || len(errs) > 0 {
		return nil, errs
	}
	out := make([]netip.Prefix, 0, len(in))
	seen := make(map[netip.Addr]int, len(in))
	for i, s := range in {
		ip := path.Index(i)
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
			errs = append(errs, field.Invalid(ip, s, "must be an IPv4 or IPv6 address"))
			continue
		case a.Zone() != "":
			errs = append(errs, field.Invalid(ip, s, "must not carry a zone"))
			continue
		case a.Is4In6():
			errs = append(errs, field.Invalid(ip, s, "must not be an IPv4-mapped IPv6 address"))
			continue
		}
		if j, dup := seen[a]; dup {
			errs = append(errs, field.Duplicate(ip, fmt.Sprintf("%s (same address as entry %d)", s, j)))
			continue
		}
		seen[a] = i
		if e := checkFamily(familyOf(a), want, ip, s); e != nil {
			errs = append(errs, e)
			continue
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, errs
}

func prefixes(in []string, path *field.Path, want *Family) ([]netip.Prefix, field.ErrorList) {
	errs := listBounds(len(in), in == nil, path, galacticv1alpha1.MaxAddresses)
	if in == nil || len(errs) > 0 {
		return nil, errs
	}
	out := make([]netip.Prefix, 0, len(in))
	seen := make(map[netip.Prefix]int, len(in))
	for i, s := range in {
		ip := path.Index(i)
		p, err := netip.ParsePrefix(s)
		switch {
		case err != nil:
			errs = append(errs, field.Invalid(ip, s, "must be an IPv4 or IPv6 prefix"))
			continue
		case p.Addr().Is4In6():
			errs = append(errs, field.Invalid(ip, s, "must not be an IPv4-mapped IPv6 prefix"))
			continue
		case p.Masked() != p:
			errs = append(errs, field.Invalid(ip, s, "must have no host bits set; did you mean "+p.Masked().String()+"?"))
			continue
		}
		if j, dup := seen[p]; dup {
			errs = append(errs, field.Duplicate(ip, fmt.Sprintf("%s (same prefix as entry %d)", s, j)))
			continue
		}
		seen[p] = i
		if e := checkFamily(familyOf(p.Addr()), want, ip, s); e != nil {
			errs = append(errs, e)
			continue
		}
		out = append(out, p)
	}
	return out, errs
}

func portRanges(in []galacticv1alpha1.PortRange, path *field.Path) ([]PortRange, field.ErrorList) {
	errs := listBounds(len(in), in == nil, path, galacticv1alpha1.MaxPortRanges)
	if in == nil || len(errs) > 0 {
		return nil, errs
	}
	out := make([]PortRange, 0, len(in))
	for i, r := range in {
		rp := path.Index(i)
		if r.Start < 0 || r.Start > 65535 || r.End < 0 || r.End > 65535 {
			errs = append(errs, field.Invalid(rp, fmt.Sprintf("%d-%d", r.Start, r.End), "ports must be from 0 to 65535"))
			continue
		}
		if r.Start > r.End {
			errs = append(errs, field.Invalid(rp, fmt.Sprintf("%d-%d", r.Start, r.End), "start must not exceed end"))
			continue
		}
		pr := PortRange{Start: uint16(r.Start), End: uint16(r.End)}
		for j, o := range out {
			if pr.Start <= o.End && o.Start <= pr.End {
				errs = append(errs, field.Invalid(rp, fmt.Sprintf("%d-%d", r.Start, r.End),
					fmt.Sprintf("overlaps range %d", j)))
			}
		}
		out = append(out, pr)
	}
	return out, errs
}

func icmpFromAPI(in galacticv1alpha1.ICMPMatch, path *field.Path) (*ICMP, field.ErrorList) {
	var errs field.ErrorList
	if in.Type < 0 || in.Type > 255 {
		errs = append(errs, field.Invalid(path.Child("type"), in.Type, "must be from 0 to 255"))
	}
	out := &ICMP{Type: uint8(in.Type)}
	if in.Code != nil {
		if *in.Code < 0 || *in.Code > 255 {
			errs = append(errs, field.Invalid(path.Child("code"), *in.Code, "must be from 0 to 255"))
		}
		out.Code, out.HasCode = uint8(*in.Code), true
	}
	return out, errs
}
