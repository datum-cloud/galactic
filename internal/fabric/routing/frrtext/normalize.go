// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package frrtext compares FRR configurations by meaning rather than by
// text. It splits a configuration into the contexts FRR's own reload tool
// works with (a top-level line, a router bgp block, each address family and
// BMP target inside it, each route-map entry) and ignores what FRR ignores:
// comments (lines starting with ! or #), blank lines, indentation, the order of contexts and of lines
// within one, and leading zeros or host bits in prefixes.
//
// It also applies the pinned FRR's display rules, so a legacy file compares
// equal to the configuration FRR shows after loading it: community-list
// entries are numbered 5, 10, 15, ...; set community values are sorted;
// `log syslog debugging` reads as `log syslog`; `ip forwarding`,
// `ipv6 forwarding`, `bgp ebgp-requires-policy`, enabling `send-community`
// lines and the `frr version` banner are dropped. The Docker-backed parity test checks those rules
// against the real build.
//
// It is the fast, Docker-free half of the parity check, not a replacement
// for FRR's own comparison.
package frrtext

import (
	"bufio"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Config is a normalized configuration: each context's key mapped to the
// lines inside it, counted. A top-level line is its own context with no
// lines.
type Config map[string]map[string]int

// Normalize parses text.
func Normalize(text string) Config {
	cfg := Config{}
	var stack []string // open context keys, outermost first
	listSeq := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := sc.Text()
		line := canonicalLine(raw)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || hidden(line) {
			continue
		}
		line = numberCommunityList(line, listSeq)
		indented := strings.HasPrefix(raw, " ")
		switch {
		case line == "exit-address-family" || (line == "exit" && len(stack) > 1 && indented):
			stack = stack[:len(stack)-1]
			continue
		case line == "exit":
			stack = nil
			continue
		}
		if !indented {
			stack = nil
		}
		if len(stack) == 0 && !indented {
			if strings.HasPrefix(line, "router bgp ") || strings.HasPrefix(line, "route-map ") {
				stack = []string{line}
			}
			cfg.add(line, "")
			continue
		}
		if len(stack) == 1 && strings.HasPrefix(stack[0], "router bgp ") &&
			(strings.HasPrefix(line, "address-family ") || strings.HasPrefix(line, "bmp targets ")) {
			stack = append(stack, stack[0]+" / "+line)
			cfg.add(stack[1], "")
			continue
		}
		if len(stack) == 0 {
			// An indented line outside any context: keep it visible.
			cfg.add(line, "")
			continue
		}
		cfg.add(stack[len(stack)-1], line)
	}
	return cfg
}

func (c Config) add(context, line string) {
	if c[context] == nil {
		c[context] = map[string]int{}
	}
	if line != "" {
		c[context][line]++
	}
}

// Diff returns the lines want has that got lacks, prefixed "-", and the
// lines got has that want lacks, prefixed "+", each with its context. An
// empty result means the configurations are equivalent.
func Diff(want, got Config) []string {
	var out []string
	for _, ctx := range keys(want) {
		if _, ok := got[ctx]; !ok {
			out = append(out, "- "+ctx)
			continue
		}
		for _, l := range keys(want[ctx]) {
			for range want[ctx][l] - got[ctx][l] {
				out = append(out, "- "+ctx+" :: "+l)
			}
		}
	}
	for _, ctx := range keys(got) {
		if _, ok := want[ctx]; !ok {
			out = append(out, "+ "+ctx)
			continue
		}
		for _, l := range keys(got[ctx]) {
			for range got[ctx][l] - want[ctx][l] {
				out = append(out, "+ "+ctx+" :: "+l)
			}
		}
	}
	return out
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// canonicalLine collapses whitespace, writes every prefix the way FRR
// stores it and sorts set community values. Descriptions are free text and
// keep their spacing.
func canonicalLine(raw string) string {
	trimmed := strings.TrimSpace(raw)
	f := strings.Fields(trimmed)
	if len(f) == 0 {
		return ""
	}
	if f[0] == "description" {
		return trimmed
	}
	if len(f) == 3 && f[0] == "log" && f[1] == "syslog" && f[2] == "debugging" {
		// The default level, which FRR leaves out.
		return "log syslog"
	}
	if len(f) > 3 && f[0] == "neighbor" && f[2] == "description" {
		return strings.Join(f[:3], " ") + " " + strings.TrimSpace(strings.SplitN(trimmed, " description ", 2)[1])
	}
	for i, tok := range f {
		if p, err := netip.ParsePrefix(tok); err == nil {
			f[i] = p.Masked().String()
		}
	}
	if len(f) > 2 && f[0] == "set" && (f[1] == "community" || f[1] == "large-community") {
		values, tail := f[2:], []string(nil)
		if values[len(values)-1] == "additive" {
			values, tail = values[:len(values)-1], []string{"additive"}
		}
		if f[1] == "community" {
			values = SortedStandard(values)
		} else {
			values = SortedLarge(values)
		}
		f = append(append(f[:2:2], values...), tail...)
	}
	return strings.Join(f, " ")
}

// hidden reports a line the pinned FRR accepts but never displays.
func hidden(line string) bool {
	f := strings.Fields(line)
	switch {
	case line == "ip forwarding", line == "ipv6 forwarding", strings.HasPrefix(line, "frr version "):
		return true
	case line == "bgp ebgp-requires-policy":
		// On by default in the traditional profile.
		return true
	case len(f) >= 3 && len(f) <= 4 && f[0] == "neighbor" && f[2] == "send-community":
		return true
	}
	return false
}

// numberCommunityList gives an unnumbered community-list entry the seq
// number FRR assigns it: 5 for a list's first entry, then 10, 15, ...
func numberCommunityList(line string, next map[string]int) string {
	f := strings.Fields(line)
	if len(f) < 6 || f[0] != "bgp" || (f[1] != "community-list" && f[1] != "large-community-list") || f[2] != "standard" {
		return line
	}
	key := f[1] + " " + f[3]
	if f[4] == "seq" {
		return line
	}
	next[key] += 5
	return strings.Join(append(f[:4:4], append([]string{"seq", strconv.Itoa(next[key])}, f[4:]...)...), " ")
}
