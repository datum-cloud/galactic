// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"os"
	"strings"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
)

// routeListFn and linkByIndexFn are package-level function variables so
// tests can substitute a fake netlink view without touching the real host
// network stack -- the same override-var pattern internal/installer uses
// for addrListFn.
var (
	routeListFn = func() ([]netlink.Route, error) {
		return netlink.RouteList(nil, netlink.FAMILY_V6)
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		return netlink.LinkByIndex(index)
	}
)

// ResolveInterfaces returns the set of interface names the uSID datapath
// should attach its TC-BPF ingress hook to (design plan §4.1).
//
// If config.EnvCNIEBPFInterfaces is set, it is parsed as a comma-separated
// list of interface names (whitespace trimmed, duplicates and empty
// entries removed) and returned directly -- no auto-detection is
// performed. This is the explicit override for multi-homed nodes where
// auto-detection is ambiguous.
//
// Otherwise, the interface(s) carrying the default IPv6 route are
// auto-detected. Attaching to the wrong (or too few) interfaces fails as
// silent blackholing of overlay traffic (design plan §4.1), so callers
// that get an error here must not proceed with a partial or empty
// interface set.
func ResolveInterfaces() ([]string, error) {
	if override := strings.TrimSpace(os.Getenv(config.EnvCNIEBPFInterfaces)); override != "" {
		names := parseInterfaceList(override)
		if len(names) == 0 {
			return nil, fmt.Errorf("attach: %s is set to %q but contains no usable interface names",
				config.EnvCNIEBPFInterfaces, override)
		}
		return names, nil
	}
	return autoDetectInterfaces()
}

// parseInterfaceList splits a comma-separated interface list, trimming
// whitespace and removing duplicate/empty entries while preserving order.
func parseInterfaceList(v string) []string {
	var out []string
	seen := make(map[string]bool)
	for part := range strings.SplitSeq(v, ",") {
		name := strings.TrimSpace(part)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// autoDetectInterfaces returns the deduplicated set of interface names
// carrying an IPv6 default route (::/0), in the order netlink reports them
// -- analogous to the existing GALACTIC_ROUTER_BGP_LOCAL_ADDRESS
// auto-detection-from-`lo` pattern (internal/plumbing/loaddr), but over
// routes rather than addresses.
func autoDetectInterfaces() ([]string, error) {
	routes, err := routeListFn()
	if err != nil {
		return nil, fmt.Errorf("attach: list IPv6 routes for auto-detection: %w", err)
	}

	var names []string
	seen := make(map[string]bool)
	for _, r := range routes {
		if !isDefaultRoute(r) || r.LinkIndex <= 0 {
			continue
		}
		link, err := linkByIndexFn(r.LinkIndex)
		if err != nil {
			// A route pointing at an interface we can't resolve isn't
			// actionable here; skip it rather than failing the whole
			// detection over one stale/racing route.
			continue
		}
		name := link.Attrs().Name
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}

	if len(names) == 0 {
		return nil, fmt.Errorf(
			"attach: no default IPv6 route found to auto-detect the SRv6/underlay-facing interface; "+
				"set %s to override", config.EnvCNIEBPFInterfaces)
	}
	return names, nil
}

// isDefaultRoute reports whether r is an IPv6 default route (::/0).
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	return ones == 0 && bits == 128
}
