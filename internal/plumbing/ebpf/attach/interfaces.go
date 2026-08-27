// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"log/slog"
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
	// linkListFn enumerates every link on the host, for expandBondSlaves'
	// slave lookup below. linkByNameFn (resolving one name to its Link) is
	// already declared in health.go -- reused here rather than redeclared.
	linkListFn = func() ([]netlink.Link, error) {
		return netlink.LinkList()
	}
)

// ResolveInterfaces returns the set of interface names the uSID datapath
// should attach its TC-BPF ingress hook to (design plan §4.1).
//
// If config.EnvCNIEBPFInterfaces is set, it is parsed as a comma-separated
// list of interface names (whitespace trimmed, duplicates and empty
// entries removed) and used directly -- no auto-detection is performed.
// This is the explicit override for multi-homed nodes where auto-detection
// is ambiguous.
//
// Otherwise, the interface(s) carrying the default IPv6 route are
// auto-detected. Attaching to the wrong (or too few) interfaces fails as
// silent blackholing of overlay traffic (design plan §4.1), so callers
// that get an error here must not proceed with a partial or empty
// interface set.
//
// Either way, the resolved set is then run through expandBondSlaves: any
// interface that is itself a Linux bonding master is expanded to include
// its slave interfaces too, since ingress tc/eBPF classification on a
// bonded interface happens on the slaves, not the master -- see
// expandBondSlaves' own doc comment. This applies uniformly to both paths
// above, so an operator using the override only needs to name the bond
// master, not hand-list every slave alongside it.
func ResolveInterfaces() ([]string, error) {
	var (
		names []string
		err   error
	)
	if override := strings.TrimSpace(os.Getenv(config.EnvCNIEBPFInterfaces)); override != "" {
		names = parseInterfaceList(override)
		if len(names) == 0 {
			return nil, fmt.Errorf("attach: %s is set to %q but contains no usable interface names",
				config.EnvCNIEBPFInterfaces, override)
		}
	} else {
		names, err = autoDetectInterfaces()
		if err != nil {
			return nil, err
		}
	}
	return expandBondSlaves(names)
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

// bondLinkType is the vishvananda/netlink Link.Type() value expandBondSlaves
// checks for -- see its own doc comment for why.
const bondLinkType = "bond"

// expandBondSlaves expands any bonding-master interface in names to also
// include its slave interfaces, leaving every non-bond interface unchanged.
//
// On a Linux bonding master, RX ingress tc/eBPF classification happens on
// the slave devices, not the bond master itself -- a well-known kernel
// behavior (confirmed live: `tc filter show dev bond0 ingress` showed this
// package's own filter correctly attached, `tc filter show dev <slave>
// ingress` showed nothing on either slave, and every uSID datapath map
// counter -- locator_table, function_table, vrf_table, drop_reasons --
// stayed at zero despite tcpdump confirming packets arriving on the wire).
// The bond master still carries the IP/route configuration ResolveInterfaces
// resolves from (auto-detect) or an operator names directly (the
// GALACTIC_CNI_EBPF_INTERFACES override), but attaching the ingress hook to
// only the master silently never sees any traffic that arrives while
// bonded -- so both master and slaves are attached, mirroring the
// tc/bonding gotcha this replaces the historical per-node "list the master
// plus every slave name in GALACTIC_CNI_EBPF_INTERFACES by hand" workaround.
//
// A name that can't be resolved at all is passed through unchanged (logged,
// not failed): ResolveInterfaces' override path has never required its
// named interfaces to actually exist on the host at resolution time (e.g.
// internal/installer's static-conflist generation resolves this purely to
// produce a config string, independent of whether/when this init
// container's netns can see the interface) -- callers that do need the
// interface to genuinely exist still get that failure from attachOne at
// actual attach time, unchanged from before this function existed. Once a
// name does resolve to a real bonding master, though, failing to enumerate
// its slaves is treated as fatal -- silently falling back to "just the
// master" would reproduce the exact bug this function exists to fix.
func expandBondSlaves(names []string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	add := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}

	for _, name := range names {
		add(name)

		link, err := linkByNameFn(name)
		if err != nil {
			slog.Warn("attach: could not resolve interface to check whether it's a bonding master, "+
				"leaving it as-is", "interface", name, "err", err)
			continue
		}
		if link.Type() != bondLinkType {
			continue
		}

		slaves, err := bondSlaveNames(link)
		if err != nil {
			return nil, fmt.Errorf("attach: enumerate slaves of bonding master %q: %w", name, err)
		}
		for _, slave := range slaves {
			add(slave)
		}
	}
	return out, nil
}

// bondSlaveNames returns the names of every link enslaved to master (i.e.
// every link whose MasterIndex, populated from netlink's IFLA_MASTER
// attribute, equals master's own index), in whatever order linkListFn
// reports them.
func bondSlaveNames(master netlink.Link) ([]string, error) {
	links, err := linkListFn()
	if err != nil {
		return nil, err
	}

	masterIndex := master.Attrs().Index
	var slaves []string
	for _, l := range links {
		if l.Attrs().MasterIndex == masterIndex {
			slaves = append(slaves, l.Attrs().Name)
		}
	}
	return slaves, nil
}

// isDefaultRoute reports whether r is an IPv6 default route (::/0).
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	return ones == 0 && bits == 128
}
