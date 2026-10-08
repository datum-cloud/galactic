// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package query defines the canonical looking-glass query: its types, the
// rules that validate and canonicalize a target, the probe destination policy,
// and the default result budgets.
//
// Every boundary that accepts a query (the public API's admission, the cell
// gateway, the node sidecar) runs the same Canonicalize, so a request means
// the same thing at each hop. The package imports nothing from the rest of
// galactic so it can move to the network repository unchanged, where NSO and
// galactic would both import it.
package query

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Type is a looking-glass query type.
type Type string

// Query types. The values are the public API's enum values.
const (
	TypeRouteLookup    Type = "RouteLookup"
	TypeASPath         Type = "ASPath"
	TypeCommunity      Type = "Community"
	TypeLargeCommunity Type = "LargeCommunity"
	TypeBGPSummary     Type = "BGPSummary"
	TypePing           Type = "Ping"
	TypeTraceroute     Type = "Traceroute"
)

// Types lists every query type in a stable order.
var Types = []Type{
	TypeRouteLookup, TypeASPath, TypeCommunity, TypeLargeCommunity,
	TypeBGPSummary, TypePing, TypeTraceroute,
}

// Expensive reports whether t searches the whole BGP table. Expensive types
// share a separate execution budget and are release-gated on load tests.
func (t Type) Expensive() bool {
	switch t {
	case TypeASPath, TypeCommunity, TypeLargeCommunity:
		return true
	}
	return false
}

// Probe reports whether t sends packets rather than reading FRR state.
func (t Type) Probe() bool {
	return t == TypePing || t == TypeTraceroute
}

// Valid reports whether t is a known query type.
func (t Type) Valid() bool { return slices.Contains(Types, t) }

// AddressFamily selects the IPv4 or IPv6 unicast table, or the probe family.
type AddressFamily string

// Address families.
const (
	IPv4 AddressFamily = "IPv4"
	IPv6 AddressFamily = "IPv6"
)

// Valid reports whether f is IPv4 or IPv6.
func (f AddressFamily) Valid() bool { return f == IPv4 || f == IPv6 }

// LookupKind tells an exact-prefix route lookup from a longest-prefix-match
// lookup of an address.
type LookupKind string

// Lookup kinds.
const (
	// LookupExact matches only the exact prefix given.
	LookupExact LookupKind = "Exact"
	// LookupLongestMatch returns the most specific prefix covering the
	// address given, which may be a default route.
	LookupLongestMatch LookupKind = "LongestMatch"
)

// Bounds on targets.
const (
	// MaxTargetLength bounds every target, in bytes.
	MaxTargetLength = 255
	// MaxASPathExpressionLength bounds an AS-path regular expression, in
	// bytes.
	MaxASPathExpressionLength = 128
	// maxHostnameLength is the DNS limit on a name in text form.
	maxHostnameLength = 253
)

// Query is a looking-glass request. Canonicalize turns a request as written
// by a caller into its canonical form.
type Query struct {
	// Type selects what to run.
	Type Type
	// Target is the prefix, address, AS-path expression, community, large
	// community, or probe destination. Empty for BGPSummary.
	Target string
	// AddressFamily selects the table or probe family. Empty means infer it
	// from a literal target, else IPv4.
	AddressFamily AddressFamily
}

// ErrorCode classifies a validation failure. Codes are part of the public
// contract.
type ErrorCode string

// Validation error codes.
const (
	CodeInvalidType      ErrorCode = "InvalidType"
	CodeInvalidTarget    ErrorCode = "InvalidTarget"
	CodeTargetRequired   ErrorCode = "TargetRequired"
	CodeTargetForbidden  ErrorCode = "TargetForbidden"
	CodeFamilyConflict   ErrorCode = "AddressFamilyConflict"
	CodeInvalidFamily    ErrorCode = "InvalidAddressFamily"
	CodeDestinationDeny  ErrorCode = "DestinationNotAllowed"
	CodeHostnameRequired ErrorCode = "NumericDestinationRequired"
)

// Error is a validation failure with a typed code.
type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

func errorf(code ErrorCode, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the code of a validation error, or "" for any other error.
func CodeOf(err error) ErrorCode {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	return ""
}

// Canonicalize validates q and returns its canonical form: the target in a
// single spelling and the address family resolved. It never resolves DNS; a
// probe target may stay a hostname, which ResolvedProbe later requires to be
// numeric.
func Canonicalize(q Query) (Query, error) {
	if !q.Type.Valid() {
		return Query{}, errorf(CodeInvalidType, "unknown query type %q", q.Type)
	}
	if q.AddressFamily != "" && !q.AddressFamily.Valid() {
		return Query{}, errorf(CodeInvalidFamily, "address family must be IPv4 or IPv6, not %q", q.AddressFamily)
	}
	if len(q.Target) > MaxTargetLength {
		return Query{}, errorf(CodeInvalidTarget, "target is longer than %d bytes", MaxTargetLength)
	}
	if err := checkPrintable(q.Target); err != nil {
		return Query{}, err
	}

	out := q
	switch q.Type {
	case TypeBGPSummary:
		if q.Target != "" {
			return Query{}, errorf(CodeTargetForbidden, "BGPSummary takes no target")
		}
	case TypeRouteLookup:
		target, family, err := canonicalRouteTarget(q.Target)
		if err != nil {
			return Query{}, err
		}
		out.Target = target
		if err := inferFamily(&out, family); err != nil {
			return Query{}, err
		}
	case TypeASPath:
		if err := checkASPathExpression(q.Target); err != nil {
			return Query{}, err
		}
	case TypeCommunity:
		c, err := canonicalCommunity(q.Target)
		if err != nil {
			return Query{}, err
		}
		out.Target = c
	case TypeLargeCommunity:
		c, err := canonicalLargeCommunity(q.Target)
		if err != nil {
			return Query{}, err
		}
		out.Target = c
	case TypePing, TypeTraceroute:
		target, family, err := canonicalProbeTarget(q.Target)
		if err != nil {
			return Query{}, err
		}
		out.Target = target
		if err := inferFamily(&out, family); err != nil {
			return Query{}, err
		}
	}
	if out.AddressFamily == "" {
		out.AddressFamily = IPv4
	}
	return out, nil
}

// Lookup returns the kind of a canonical RouteLookup: exact for a prefix,
// longest-match for an address.
func Lookup(q Query) LookupKind {
	if strings.Contains(q.Target, "/") {
		return LookupExact
	}
	return LookupLongestMatch
}

// inferFamily sets q's family from a literal target's family, rejecting an
// explicit family that conflicts with it. family is "" for a non-literal
// target.
func inferFamily(q *Query, family AddressFamily) error {
	if family == "" {
		return nil
	}
	if q.AddressFamily != "" && q.AddressFamily != family {
		return errorf(CodeFamilyConflict, "target %s is %s but addressFamily is %s", q.Target, family, q.AddressFamily)
	}
	q.AddressFamily = family
	return nil
}

func familyOf(a netip.Addr) AddressFamily {
	if a.Is4() {
		return IPv4
	}
	return IPv6
}

// checkPrintable rejects control characters, which would otherwise reach
// FRR's command parser.
func checkPrintable(s string) error {
	for _, r := range s {
		if r == unicode.ReplacementChar || unicode.IsControl(r) || r > unicode.MaxASCII {
			return errorf(CodeInvalidTarget, "target contains a control or non-ASCII character")
		}
	}
	return nil
}

// canonicalRouteTarget accepts a CIDR prefix or a bare address. A prefix must
// have no host bits set; an IPv4-mapped IPv6 address is rejected rather than
// guessed at.
func canonicalRouteTarget(s string) (string, AddressFamily, error) {
	if s == "" {
		return "", "", errorf(CodeTargetRequired, "RouteLookup needs a prefix or address")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", "", errorf(CodeInvalidTarget, "%q is not a prefix", s)
		}
		if p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return "", "", errorf(CodeInvalidTarget, "%q is not a plain IPv4 or IPv6 prefix", s)
		}
		if p.Masked() != p {
			return "", "", errorf(CodeInvalidTarget, "%q has host bits set; did you mean %s?", s, p.Masked())
		}
		return p.String(), familyOf(p.Addr()), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4In6() || a.Zone() != "" {
		return "", "", errorf(CodeInvalidTarget, "%q is not an IPv4 or IPv6 address or prefix", s)
	}
	return a.String(), familyOf(a), nil
}

// asPathChars is the closed character set of an AS-path expression. It has no
// space, so an expression is always one FRR command token, and no letters, so
// it can never be read as the json keyword.
var asPathChars = regexp.MustCompile(`^[0-9^$_.*+?\[\]()|-]+$`)

// checkASPathExpression validates an AS-path regular expression against the
// closed grammar FRR's regexp search accepts. FRR uses POSIX extended regular
// expressions with _ standing for an AS boundary; the expression is checked
// with that substitution under Go's POSIX parser, and FRR's own compile
// result is still authoritative at the node.
func checkASPathExpression(s string) error {
	if s == "" {
		return errorf(CodeTargetRequired, "ASPath needs a regular expression")
	}
	if len(s) > MaxASPathExpressionLength {
		return errorf(CodeInvalidTarget, "AS-path expression is longer than %d bytes", MaxASPathExpressionLength)
	}
	if !asPathChars.MatchString(s) {
		return errorf(CodeInvalidTarget, "AS-path expression may only contain digits and ^ $ _ . * + ? [ ] ( ) | -")
	}
	posix := strings.ReplaceAll(s, "_", "(^|[,{}() ]|$)")
	if _, err := regexp.CompilePOSIX(posix); err != nil {
		return errorf(CodeInvalidTarget, "AS-path expression does not compile: %v", err)
	}
	return nil
}

// wellKnownCommunities maps the well-known community names FRR's community
// search accepts to their canonical spelling.
var wellKnownCommunities = map[string]string{
	"no-export":         "no-export",
	"no-advertise":      "no-advertise",
	"local-as":          "local-AS",
	"no-peer":           "no-peer",
	"blackhole":         "blackhole",
	"graceful-shutdown": "graceful-shutdown",
	"accept-own":        "accept-own",
}

// canonicalCommunity accepts AA:NN with both halves 0-65535, or a well-known
// community name, and returns it without leading zeros.
func canonicalCommunity(s string) (string, error) {
	if s == "" {
		return "", errorf(CodeTargetRequired, "Community needs a community value")
	}
	if name, ok := wellKnownCommunities[strings.ToLower(s)]; ok {
		return name, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", errorf(CodeInvalidTarget, "%q is not a community (ASN:value)", s)
	}
	out := make([]string, 2)
	for i, p := range parts {
		n, err := parseUint(p, 16)
		if err != nil {
			return "", errorf(CodeInvalidTarget, "%q is not a community: each half must be 0-65535", s)
		}
		out[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(out, ":"), nil
}

// canonicalLargeCommunity accepts GA:LD1:LD2 with each part 0-4294967295.
func canonicalLargeCommunity(s string) (string, error) {
	if s == "" {
		return "", errorf(CodeTargetRequired, "LargeCommunity needs a large community value")
	}
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return "", errorf(CodeInvalidTarget, "%q is not a large community (ASN:value:value)", s)
	}
	out := make([]string, 3)
	for i, p := range parts {
		n, err := parseUint(p, 32)
		if err != nil {
			return "", errorf(CodeInvalidTarget, "%q is not a large community: each part must be 0-4294967295", s)
		}
		out[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(out, ":"), nil
}

// parseUint parses a decimal of at most bits bits, digits only.
func parseUint(s string, bits int) (uint64, error) {
	if s == "" || len(s) > 10 {
		return 0, errors.New("bad length")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a digit")
		}
	}
	return strconv.ParseUint(s, 10, bits)
}

// hostnameLabel is one RFC 1123 label.
var hostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// canonicalProbeTarget accepts an IP address or a DNS hostname. A hostname is
// lowercased with any trailing dot removed and must have at least two labels.
// Syntax only: whether the destination may be probed is CheckProbeDestination's
// decision, made on the resolved address.
func canonicalProbeTarget(s string) (string, AddressFamily, error) {
	if s == "" {
		return "", "", errorf(CodeTargetRequired, "a probe needs a destination")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Is4In6() || a.Zone() != "" {
			return "", "", errorf(CodeInvalidTarget, "%q is not a plain IPv4 or IPv6 address", s)
		}
		return a.String(), familyOf(a), nil
	}
	h := strings.TrimSuffix(strings.ToLower(s), ".")
	if len(h) == 0 || len(h) > maxHostnameLength {
		return "", "", errorf(CodeInvalidTarget, "%q is not a hostname", s)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", "", errorf(CodeInvalidTarget, "%q is not a fully qualified hostname", s)
	}
	for _, l := range labels {
		if !hostnameLabel.MatchString(l) {
			return "", "", errorf(CodeInvalidTarget, "%q is not a hostname", s)
		}
	}
	// A final label of digits only would make the name look like an address.
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "", "", errorf(CodeInvalidTarget, "%q is not a hostname", s)
	}
	return h, "", nil
}
