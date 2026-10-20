// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// spec decodes a rules array the way the API server would hand it over.
func spec(t *testing.T, rules string) galacticv1alpha1.TrafficPolicySpec {
	t.Helper()
	var s galacticv1alpha1.TrafficPolicySpec
	if err := json.Unmarshal([]byte(`{"rules":`+rules+`}`), &s); err != nil {
		t.Fatalf("bad spec JSON: %v", err)
	}
	return s
}

// allowOne wraps a single Allow rule named "a" around a match object.
func allowOne(match string) string {
	return `[{"name":"a","action":"Allow","match":` + match + `}]`
}

// TestFromAPI re-checks the schema's rules and adds the ones only Go can
// express. Every rejection names the field it is about.
func TestFromAPI(t *testing.T) {
	const srcCIDR0 = "spec.rules[0].match.sourceCIDRs[0]"
	tests := []struct {
		name      string
		rules     string
		wantField string // the field path of the first error; empty means valid
	}{
		{name: "catch-all deny", rules: `[{"name":"deny-all","action":"Deny"}]`},
		{name: "nat https", rules: allowOne(
			`{"path":"PublicNAT","protocol":"TCP","destinationPorts":[{"start":443,"end":443}]}`)},
		{name: "mixed families without ipFamily", rules: allowOne(`{"sourceIPs":["192.0.2.1","2001:db8::1"]}`)},
		{name: "ip one side, cidr the other", rules: allowOne(
			`{"sourceIPs":["192.0.2.1"],"destinationCIDRs":["198.51.100.0/24"]}`)},

		{name: "no rules", rules: `[]`, wantField: "spec.rules"},
		{name: "bad action", rules: `[{"name":"a","action":"Reject"}]`, wantField: "spec.rules[0].action"},
		{name: "duplicate names", rules: `[{"name":"a","action":"Allow"},{"name":"a","action":"Deny"}]`,
			wantField: "spec.rules[1].name"},
		{name: "empty list", rules: allowOne(`{"sourceIPs":[]}`), wantField: "spec.rules[0].match.sourceIPs"},
		{name: "zone", rules: allowOne(`{"sourceIPs":["fe80::1%eth0"]}`), wantField: "spec.rules[0].match.sourceIPs[0]"},
		{name: "ipv4-mapped", rules: allowOne(`{"sourceIPs":["::ffff:192.0.2.1"]}`),
			wantField: "spec.rules[0].match.sourceIPs[0]"},
		{name: "ipv4-mapped prefix", rules: allowOne(`{"sourceCIDRs":["::ffff:192.0.2.0/120"]}`),
			wantField: srcCIDR0},
		{name: "duplicate after canonicalization",
			rules:     allowOne(`{"destinationIPs":["2001:DB8::1","2001:db8:0:0::1"]}`),
			wantField: "spec.rules[0].match.destinationIPs[1]"},
		{name: "duplicate prefix after canonicalization", rules: allowOne(
			`{"destinationCIDRs":["2001:DB8:0::/32","2001:db8::/32"]}`),
			wantField: "spec.rules[0].match.destinationCIDRs[1]"},
		{name: "host bits", rules: allowOne(`{"sourceCIDRs":["192.0.2.1/24"]}`),
			wantField: srcCIDR0},
		{name: "ip and cidr same side", rules: allowOne(
			`{"sourceIPs":["192.0.2.1"],"sourceCIDRs":["198.51.100.0/24"]}`),
			wantField: "spec.rules[0].match.sourceCIDRs"},
		{name: "family mismatch", rules: allowOne(`{"ipFamily":"IPv4","destinationIPs":["2001:db8::1"]}`),
			wantField: "spec.rules[0].match.destinationIPs[0]"},
		{name: "icmp with v6 prefix", rules: allowOne(`{"protocol":"ICMP","sourceCIDRs":["2001:db8::/32"]}`),
			wantField: srcCIDR0},
		{name: "icmpv6 with ipv4 family", rules: allowOne(`{"protocol":"ICMPv6","ipFamily":"IPv4"}`),
			wantField: "spec.rules[0].match.ipFamily"},
		{name: "ports without protocol", rules: allowOne(`{"destinationPorts":[{"start":80,"end":80}]}`),
			wantField: "spec.rules[0].match.protocol"},
		{name: "reversed range", rules: allowOne(`{"protocol":"TCP","sourcePorts":[{"start":9,"end":8}]}`),
			wantField: "spec.rules[0].match.sourcePorts[0]"},
		{name: "overlapping ranges", rules: allowOne(
			`{"protocol":"TCP","sourcePorts":[{"start":1,"end":9},{"start":9,"end":10}]}`),
			wantField: "spec.rules[0].match.sourcePorts[1]"},
		{name: "icmp without protocol", rules: allowOne(`{"icmp":{"type":8}}`),
			wantField: "spec.rules[0].match.icmp"},
		{name: "bad family", rules: allowOne(`{"ipFamily":"IPv5"}`), wantField: "spec.rules[0].match.ipFamily"},
		{name: "bad protocol", rules: allowOne(`{"protocol":"SCTP"}`), wantField: "spec.rules[0].match.protocol"},
		{name: "bad path", rules: allowOne(`{"path":"Any"}`), wantField: "spec.rules[0].match.path"},
		{name: "port too high", rules: allowOne(`{"protocol":"TCP","destinationPorts":[{"start":1,"end":65536}]}`),
			wantField: "spec.rules[0].match.destinationPorts[0]"},
		{name: "negative port", rules: allowOne(`{"protocol":"TCP","destinationPorts":[{"start":-1,"end":1}]}`),
			wantField: "spec.rules[0].match.destinationPorts[0]"},
		{name: "icmp type too high", rules: allowOne(`{"protocol":"ICMP","icmp":{"type":256}}`),
			wantField: "spec.rules[0].match.icmp.type"},
		{name: "icmp code too high", rules: allowOne(`{"protocol":"ICMP","icmp":{"type":3,"code":256}}`),
			wantField: "spec.rules[0].match.icmp.code"},
		{name: "bad rule name", rules: `[{"name":"Allow_All","action":"Allow"}]`, wantField: "spec.rules[0].name"},
		{name: "rule name too long", rules: `[{"name":"` + strings.Repeat("a", 64) + `","action":"Allow"}]`,
			wantField: "spec.rules[0].name"},
		{name: "icmp with v6 destination", rules: allowOne(`{"protocol":"ICMP","destinationCIDRs":["2001:db8::/32"]}`),
			wantField: "spec.rules[0].match.destinationCIDRs[0]"},
		{name: "empty ports", rules: allowOne(`{"protocol":"TCP","sourcePorts":[]}`),
			wantField: "spec.rules[0].match.sourcePorts"},
		{name: "empty cidrs", rules: allowOne(`{"destinationCIDRs":[]}`), wantField: "spec.rules[0].match.destinationCIDRs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := FromAPI(spec(t, tt.rules), field.NewPath("spec"))
			switch {
			case tt.wantField == "" && len(errs) > 0:
				t.Fatalf("rejected: %v", errs)
			case tt.wantField != "" && len(errs) == 0:
				t.Fatalf("admitted, want an error at %s", tt.wantField)
			case tt.wantField != "" && errs[0].Field != tt.wantField:
				t.Fatalf("first error at %s (%v), want %s", errs[0].Field, errs, tt.wantField)
			}
		})
	}
}

// TestFromAPIListBounds checks the list limits the schema also enforces.
func TestFromAPIListBounds(t *testing.T) {
	rules := make([]string, 65)
	for i := range rules {
		rules[i] = fmt.Sprintf(`{"name":"r%d","action":"Deny"}`, i)
	}
	if _, errs := FromAPI(spec(t, "["+strings.Join(rules, ",")+"]"), field.NewPath("spec")); len(errs) == 0 ||
		errs[0].Type != field.ErrorTypeTooMany {
		t.Errorf("65 rules: errs = %v, want TooMany", errs)
	}
	ips := make([]string, 65)
	for i := range ips {
		ips[i] = fmt.Sprintf(`"10.0.0.%d"`, i)
	}
	manyIPs := allowOne(`{"sourceIPs":[` + strings.Join(ips, ",") + `]}`)
	if _, errs := FromAPI(spec(t, manyIPs), field.NewPath("spec")); len(errs) == 0 ||
		errs[0].Type != field.ErrorTypeTooMany {
		t.Errorf("65 addresses: errs = %v, want TooMany", errs)
	}
	ranges := make([]string, 17)
	for i := range ranges {
		ranges[i] = fmt.Sprintf(`{"start":%d,"end":%d}`, i*10, i*10+1)
	}
	if _, errs := FromAPI(spec(t, allowOne(`{"protocol":"UDP","sourcePorts":[`+strings.Join(ranges, ",")+`]}`)),
		field.NewPath("spec")); len(errs) == 0 || errs[0].Type != field.ErrorTypeTooMany {
		t.Errorf("17 ranges: errs = %v, want TooMany", errs)
	}
}

// TestFromAPIRejectsOverTheEntryLimit checks that a policy the schema admits
// but that would compile past the datapath's capacity is refused, not
// truncated.
func TestFromAPIRejectsOverTheEntryLimit(t *testing.T) {
	// 17 x 16 = 272 source and destination pairs, over the limit of 256.
	srcs := make([]string, 17)
	dsts := make([]string, 16)
	for i := range srcs {
		srcs[i] = fmt.Sprintf(`"192.0.2.%d"`, i)
	}
	for i := range dsts {
		dsts[i] = fmt.Sprintf(`"198.51.100.%d"`, i)
	}
	pairs := func(srcs, dsts []string) string {
		return allowOne(`{"sourceIPs":[` + strings.Join(srcs, ",") + `],"destinationIPs":[` + strings.Join(dsts, ",") + `]}`)
	}
	rules := pairs(srcs, dsts)
	_, errs := FromAPI(spec(t, rules), field.NewPath("spec"))
	if len(errs) != 1 || !strings.Contains(errs[0].Detail, "272 datapath entries") {
		t.Fatalf("errs = %v, want one entry-limit error naming 272 entries", errs)
	}

	// 16 x 16 fits exactly.
	rules = pairs(srcs[:16], dsts)
	p, errs := FromAPI(spec(t, rules), field.NewPath("spec"))
	if len(errs) > 0 {
		t.Fatalf("256 entries rejected: %v", errs)
	}
	if n := p.EntryCount(); n != galacticv1alpha1.MaxCompiledEntries {
		t.Errorf("EntryCount = %d, want %d", n, galacticv1alpha1.MaxCompiledEntries)
	}
}

// TestDefault checks the built-in default is exactly one deny-all rule and
// carries no port-specific rule of any kind.
func TestDefault(t *testing.T) {
	d := Default()
	if len(d.Rules) != 1 {
		t.Fatalf("default has %d rules, want 1", len(d.Rules))
	}
	r := d.Rules[0]
	if r.Name != galacticv1alpha1.DefaultRuleName || r.Allow || !matchIsEmpty(r.Match) {
		t.Errorf("default rule = %+v, want a catch-all deny named %s", r, galacticv1alpha1.DefaultRuleName)
	}
}

func matchIsEmpty(m Match) bool {
	return m.Path == nil && m.Family == nil && m.Proto == nil && m.Source == nil && m.Destination == nil &&
		m.SourcePorts == nil && m.DestPorts == nil && m.ICMP == nil
}
