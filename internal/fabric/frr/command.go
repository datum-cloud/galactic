// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"fmt"
	"net/netip"
	"strings"

	"go.datum.net/galactic/internal/fabric/query"
)

// Command is one FRR command bound to the daemon that runs it. Its fields are
// unexported so the only way to build one is through the constructors below,
// each of which maps a typed operation onto one fixed template. There is no
// constructor taking free text, and no other code path writes to a vty
// socket.
type Command struct {
	daemon Daemon
	text   string
}

// String returns the command text.
func (c Command) String() string { return c.text }

// Daemon returns the daemon the command is sent to.
func (c Command) Daemon() Daemon { return c.daemon }

// VersionCommand is `show version`, answered by bgpd.
func VersionCommand() Command {
	return Command{daemon: DaemonBGP, text: "show version"}
}

// SummaryCommand is `show bgp <afi> unicast summary json`.
func SummaryCommand(f query.AddressFamily) (Command, error) {
	afi, err := bgpAFI(f)
	if err != nil {
		return Command{}, err
	}
	return build(DaemonBGP, "show bgp %s unicast summary json", afi)
}

// LookupCommand is `show bgp <afi> unicast <prefix|address> json` for a
// canonical RouteLookup: FRR matches a prefix exactly and an address by
// longest prefix.
func LookupCommand(q query.Query) (Command, error) {
	if q.Type != query.TypeRouteLookup {
		return Command{}, fmt.Errorf("lookup command for %s query", q.Type)
	}
	afi, err := bgpAFI(q.AddressFamily)
	if err != nil {
		return Command{}, err
	}
	target, err := routeTarget(q.Target, q.AddressFamily)
	if err != nil {
		return Command{}, err
	}
	return build(DaemonBGP, "show bgp %s unicast %s json", afi, target)
}

// SearchCommand is the table search for a canonical ASPath, Community or
// LargeCommunity query: `show bgp <afi> unicast regexp|community|
// large-community <value> json`.
func SearchCommand(q query.Query) (Command, error) {
	canon, err := query.Canonicalize(q)
	if err != nil {
		return Command{}, err
	}
	if canon != q {
		return Command{}, fmt.Errorf("search target %q is not canonical", q.Target)
	}
	afi, err := bgpAFI(q.AddressFamily)
	if err != nil {
		return Command{}, err
	}
	var keyword string
	switch q.Type {
	case query.TypeASPath:
		keyword = "regexp"
	case query.TypeCommunity:
		keyword = "community"
	case query.TypeLargeCommunity:
		keyword = "large-community"
	default:
		return Command{}, fmt.Errorf("search command for %s query", q.Type)
	}
	return build(DaemonBGP, "show bgp %s unicast %s %s json", afi, keyword, q.Target)
}

// RouteCommand is zebra's `show ip[v6] route <prefix> json`, the installation
// evidence for one exact prefix.
func RouteCommand(prefix netip.Prefix) (Command, error) {
	if !prefix.IsValid() || prefix.Masked() != prefix || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return Command{}, fmt.Errorf("route command needs a canonical prefix, got %s", prefix)
	}
	afi := "ip"
	if prefix.Addr().Is6() {
		afi = "ipv6"
	}
	return build(DaemonZebra, "show %s route %s json", afi, prefix)
}

func bgpAFI(f query.AddressFamily) (string, error) {
	switch f {
	case query.IPv4:
		return "ipv4", nil
	case query.IPv6:
		return "ipv6", nil
	}
	return "", fmt.Errorf("unknown address family %q", f)
}

// routeTarget re-parses a lookup target and checks it against the family, so
// the text sent to FRR is always netip's own rendering.
func routeTarget(s string, f query.AddressFamily) (string, error) {
	var a netip.Addr
	var out string
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p {
			return "", fmt.Errorf("lookup target %q is not a canonical prefix", s)
		}
		a, out = p.Addr(), p.String()
	} else {
		var err error
		if a, err = netip.ParseAddr(s); err != nil {
			return "", fmt.Errorf("lookup target %q is not an address", s)
		}
		out = a.String()
	}
	if a.Zone() != "" || a.Is4In6() || (a.Is4() != (f == query.IPv4)) {
		return "", fmt.Errorf("lookup target %q does not match family %s", s, f)
	}
	return out, nil
}

// build renders a template and applies the last line of defence: every
// command is a single show command made of printable ASCII.
func build(d Daemon, format string, args ...any) (Command, error) {
	text := fmt.Sprintf(format, args...)
	if !strings.HasPrefix(text, "show ") {
		return Command{}, fmt.Errorf("refusing non-show command %q", text)
	}
	for _, r := range text {
		if r < 0x21 && r != ' ' || r > 0x7e {
			return Command{}, fmt.Errorf("refusing command with control character: %q", text)
		}
	}
	return Command{daemon: d, text: text}, nil
}
