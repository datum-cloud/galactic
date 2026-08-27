// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
)

// routeListFn and linkByIndexFn are package-level function variables so
// tests can substitute a fake netlink view without touching the real host
// network stack -- the same override-var pattern internal/installer uses
// for addrListFn.
//
// routeListFn deliberately lists routes across every routing table, not
// just the main table: passing RT_FILTER_TABLE with an unfiltered
// (RT_TABLE_UNSPEC) Table lifts vishvananda/netlink's own default of
// skipping any non-main-table route, rather than narrowing the result to
// one specific table. A default route relevant to this node's
// underlay/overlay interface selection may legitimately live in a
// non-main table (e.g. a VRF-scoped underlay), and restricting
// auto-detection to the main table only would make that topology
// undetectable -- the caller (autoDetectInterfaces) still just looks for
// any IPv6 default route, wherever it lives, exactly as before.
var (
	routeListFn = func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
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
//
// Skips wireguard-type links (excludedLinkType): a WireGuard mesh
// interface can install its own IPv6 default-ish route alongside the real
// fabric NIC's, and if netlink reports the mesh interface's route first,
// ResolveNodeSourceAddress would bake the mesh interface's ULA in as this
// node's SRv6 outer-header source address for every encapsulated packet.
// That address is never reachable off-node (it's not advertised anywhere
// outside the WireGuard mesh), so every cross-site SRv6 packet would leave
// the box correctly SID-routed but with a source no intermediate network
// would forward on (or a receiving node would recognize as this peer) --
// silent packet loss with no error on either side. A WireGuard tunnel can
// never legitimately be "the real fabric NIC" this datapath pushes raw
// SRv6-encapsulated Ethernet frames onto, so it's excluded categorically
// rather than by interface name (the specific mesh interface name is
// deployment-specific; the underlying failure mode -- a tunnel interface
// racing a real NIC for the default route -- is not).
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
		if link.Type() == excludedLinkType {
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

// excludedLinkType is the vishvananda/netlink Link.Type() value
// autoDetectInterfaces never treats as a candidate fabric interface -- see
// autoDetectInterfaces' own doc comment for why.
const excludedLinkType = "wireguard"

// isDefaultRoute reports whether r is an IPv6 default route (::/0).
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	return ones == 0 && bits == 128
}
