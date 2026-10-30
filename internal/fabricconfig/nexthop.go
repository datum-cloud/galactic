// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"go.miloapis.com/instrumentation/metrics"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

// ReasonMappedNextHopReset is raised on the agent's Pod each time NextHopGuard
// resets a session that announces an IPv4-mapped next hop.
const ReasonMappedNextHopReset = "MappedNextHopReset"

const (
	defaultNextHopCheckInterval = 30 * time.Second
	defaultNextHopResetBackoff  = 10 * time.Minute

	// stateEstablished is FRR's bgpState for an established session.
	stateEstablished = "Established"
	// protocolBGP is zebra's protocol name for routes learned from bgpd.
	protocolBGP = "bgp"
	// protocolConnected is zebra's protocol name for the routes it derives
	// from interface addresses.
	protocolConnected = "connected"

	// loopbackIfIndex is the loopback's interface index, which Linux fixes at
	// 1 in every network namespace (LOOPBACK_IFINDEX).
	loopbackIfIndex = 1

	// afiIPv4 and afiIPv6 label the uninstalled-routes and missing
	// connected-routes metrics.
	afiIPv4 = "ipv4"
	afiIPv6 = "ipv6"
)

// zebraFamilies names each address family as vtysh's show commands take it
// and as the metrics label it.
var zebraFamilies = []struct {
	cmd, label string
	is4        bool
}{{"ip", afiIPv4, true}, {"ipv6", afiIPv6, false}}

// BGP reads and resets BGP state in the running FRR instance.
type BGP interface {
	// Neighbors returns the output of `show bgp neighbors json`.
	Neighbors(ctx context.Context) ([]byte, error)
	// Routes returns the output of `show <afi> route json` for afi "ip" or
	// "ipv6".
	Routes(ctx context.Context, afi string) ([]byte, error)
	// ConnectedRoutes returns the output of `show <afi> route connected
	// json` for afi "ip" or "ipv6".
	ConnectedRoutes(ctx context.Context, afi string) ([]byte, error)
	// ResetNeighbor hard-resets the IPv6 session to neighbor.
	ResetNeighbor(ctx context.Context, neighbor string) error
}

// NextHopMetrics holds NextHopGuard's Prometheus instrumentation.
type NextHopMetrics struct {
	mapped           *prometheus.GaugeVec
	resets           *prometheus.CounterVec
	uninstalled      *prometheus.GaugeVec
	connectedMissing *prometheus.GaugeVec
}

// NewNextHopMetrics creates NextHopMetrics on the instrumentation library's
// registry. The registry keeps the series across calls, so each call starts
// them over.
func NewNextHopMetrics() *NextHopMetrics {
	m := &NextHopMetrics{
		mapped: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_router_bgp_mapped_nexthop",
			Help: "1 when an established session sourced from a global IPv6 address announces an IPv4-mapped " +
				"next hop, 0 when it announces a usable one.",
		}, []string{"peer"}),
		resets: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_router_bgp_mapped_nexthop_resets_total",
			Help: "Hard resets of sessions that announced an IPv4-mapped next hop.",
		}, []string{"peer"}),
		uninstalled: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_router_bgp_uninstalled_routes",
			Help: "Prefixes with a BGP route in zebra and no route of any protocol installed in the kernel.",
		}, []string{"afi"}),
		connectedMissing: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_router_connected_routes_missing",
			Help: "Global addresses on the loopback with no selected connected route for their prefix in zebra, " +
				"so redistribute connected does not announce them.",
		}, []string{"afi"}),
	}
	m.mapped.Reset()
	m.resets.Reset()
	m.uninstalled.Reset()
	m.connectedMissing.Reset()
	return m
}

// NextHopGuard finds IPv6 sessions announcing an IPv4-mapped next hop and
// hard-resets them, counts BGP routes zebra failed to install, and counts
// loopback addresses zebra holds no connected route for.
//
// FRR 10.7 can come up after a restart announcing ::ffff:<router-id> instead
// of the session's own IPv6 address. Once its stored next hop is mapped, every
// later update reuses it, and only a hard reset recomputes it from the
// socket. Receiving routers resolve the mapped next hop over IPv4 only and
// never install the route.
//
// FRR has also been seen to come up after a restart with the node's own
// loopback address in the kernel, and even listed on zebra's interface, but
// with no connected route for it. redistribute connected then never exports
// the address, and the node silently stops announcing its loopback. The guard
// only reports this; it changes nothing.
type NextHopGuard struct {
	// BGP reads and resets BGP state.
	BGP BGP
	// Metrics receives the guard's metrics. Nil disables them.
	Metrics *NextHopMetrics
	// Recorder emits events. Nil disables events.
	Recorder events.EventRecorder
	// Pod is the subject of events. Nil disables events.
	Pod *corev1.Pod
	// NodeName names the node in event notes.
	NodeName string
	// Lock is the node's FRR writer lock, held for each reset. Nil means no
	// other writer exists.
	Lock Locker

	// Interval is the time between checks. Zero selects 30s.
	Interval time.Duration
	// ResetBackoff is the minimum time between two resets of one session, so
	// a next hop that stays mapped raises an alert rather than a reset loop.
	// Zero selects 10m.
	ResetBackoff time.Duration
	// DetectOnly reports mapped next hops in the metrics without resetting
	// the sessions.
	DetectOnly bool
	// Addresses lists the addresses of every interface in the network
	// namespace FRR runs in. Nil lists them over netlink in the calling
	// thread's namespace, the host's, since fabric-router runs with host
	// networking.
	Addresses func() ([]netlink.Addr, error)

	// now returns the current time; nil selects time.Now.
	now func() time.Time
	// lastReset is when each neighbor was last reset.
	lastReset map[string]time.Time
}

// Run checks every Interval until ctx is done. A failed check is logged and
// retried at the next interval.
func (g *NextHopGuard) Run(ctx context.Context) {
	interval := g.Interval
	if interval <= 0 {
		interval = defaultNextHopCheckInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := g.Check(ctx); err != nil {
			slog.Error("could not check BGP next hops", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check makes one pass: it resets every session with a mapped next hop whose
// backoff has passed, then counts uninstalled routes and loopback addresses
// with no connected route. It returns the first error reading FRR's or the
// kernel's state, after finishing the rest of the pass. A count that could not
// be read keeps its previous value.
func (g *NextHopGuard) Check(ctx context.Context) error {
	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := g.checkNeighbors(ctx); err != nil {
		keep(err)
	}
	for _, afi := range zebraFamilies {
		out, err := g.BGP.Routes(ctx, afi.cmd)
		if err != nil {
			keep(fmt.Errorf("read %s routes: %w", afi.label, err))
			continue
		}
		n, err := uninstalledBGPRoutes(out)
		if err != nil {
			keep(fmt.Errorf("parse %s routes: %w", afi.label, err))
			continue
		}
		if g.Metrics != nil {
			g.Metrics.uninstalled.WithLabelValues(afi.label).Set(float64(n))
		}
	}
	if err := g.checkConnected(ctx); err != nil {
		keep(err)
	}
	return firstErr
}

// checkConnected counts, per address family, the global addresses on the
// loopback whose prefix has no selected connected route in zebra, and sets
// the missing connected-routes gauge. A family whose routes cannot be read
// keeps its gauge while the other is still counted; when the addresses
// cannot be listed, neither gauge changes. It returns the first error.
func (g *NextHopGuard) checkConnected(ctx context.Context) error {
	list := g.Addresses
	if list == nil {
		list = listAddresses
	}
	addrs, err := list()
	if err != nil {
		return fmt.Errorf("list interface addresses: %w", err)
	}
	want := loopbackPrefixes(addrs)

	var firstErr error
	for _, afi := range zebraFamilies {
		out, err := g.BGP.ConnectedRoutes(ctx, afi.cmd)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read %s connected routes: %w", afi.label, err)
			}
			continue
		}
		have, err := selectedConnectedPrefixes(out)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("parse %s connected routes: %w", afi.label, err)
			}
			continue
		}
		n := 0
		for _, p := range want {
			if p.Addr().Is4() == afi.is4 && !have[p] {
				n++
			}
		}
		if g.Metrics != nil {
			g.Metrics.connectedMissing.WithLabelValues(afi.label).Set(float64(n))
		}
	}
	return firstErr
}

// listAddresses returns every interface's addresses in the calling thread's
// network namespace.
func listAddresses() ([]netlink.Addr, error) {
	return nldump.AddrList(nil, netlink.FAMILY_ALL)
}

// loopbackPrefixes returns, for each global unicast address on the loopback,
// the prefix of the connected route zebra derives from it. It skips addresses
// on other interfaces, addresses not of universe scope (::1, 127.0.0.1),
// link-local and other non-global addresses, and addresses added with
// noprefixroute, for which zebra adds no connected route.
func loopbackPrefixes(addrs []netlink.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		if a.LinkIndex != loopbackIfIndex || a.IPNet == nil || a.Scope != unix.RT_SCOPE_UNIVERSE ||
			a.Flags&unix.IFA_F_NOPREFIXROUTE != 0 {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() {
			continue
		}
		ones, _ := a.Mask.Size()
		p, err := ip.Prefix(ones)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// selectedConnectedPrefixes returns the prefixes in `show ip[v6] route
// connected json` that have a selected connected route.
func selectedConnectedPrefixes(out []byte) (map[netip.Prefix]bool, error) {
	var prefixes map[string][]zebraRoute
	if err := json.Unmarshal(out, &prefixes); err != nil {
		return nil, err
	}
	have := make(map[netip.Prefix]bool, len(prefixes))
	for key, routes := range prefixes {
		p, err := netip.ParsePrefix(key)
		if err != nil {
			continue
		}
		for _, r := range routes {
			if r.Protocol == protocolConnected && r.Selected {
				have[p.Masked()] = true
			}
		}
	}
	return have, nil
}

// checkNeighbors resets each session with a mapped next hop and updates the
// mapped gauge.
func (g *NextHopGuard) checkNeighbors(ctx context.Context) error {
	out, err := g.BGP.Neighbors(ctx)
	if err != nil {
		return fmt.Errorf("read BGP neighbors: %w", err)
	}
	neighbors, err := parseNeighbors(out)
	if err != nil {
		return fmt.Errorf("parse BGP neighbors: %w", err)
	}

	if g.Metrics != nil {
		g.Metrics.mapped.Reset()
	}
	if g.lastReset == nil {
		g.lastReset = make(map[string]time.Time)
	}
	backoff := g.ResetBackoff
	if backoff <= 0 {
		backoff = defaultNextHopResetBackoff
	}
	now := time.Now
	if g.now != nil {
		now = g.now
	}

	for _, n := range neighbors {
		mapped, ok := n.mappedNextHop()
		if !ok {
			continue
		}
		if g.Metrics != nil {
			g.Metrics.mapped.WithLabelValues(n.Peer).Set(boolToFloat(mapped))
		}
		if !mapped || g.DetectOnly {
			continue
		}
		if last, ok := g.lastReset[n.Peer]; ok && now().Sub(last) < backoff {
			continue
		}
		g.lastReset[n.Peer] = now()
		note := fmt.Sprintf("session %s -> %s on node %s announced IPv4-mapped next hop %s; resetting it",
			n.HostLocal, n.Peer, g.NodeName, n.NexthopGlobal)
		slog.Warn(note, "reason", ReasonMappedNextHopReset)
		if err := withLock(ctx, g.Lock, func() error { return g.BGP.ResetNeighbor(ctx, n.Peer) }); err != nil {
			slog.Error("could not reset BGP session", "peer", n.Peer, "error", err)
			continue
		}
		if g.Metrics != nil {
			g.Metrics.resets.WithLabelValues(n.Peer).Inc()
		}
		if g.Recorder != nil && g.Pod != nil {
			g.Recorder.Eventf(g.Pod, nil, corev1.EventTypeWarning, ReasonMappedNextHopReset, "Reset", "%s", note)
		}
	}
	return nil
}

// neighbor is the part of one entry of `show bgp neighbors json` the guard
// reads.
type neighbor struct {
	Peer          string `json:"-"`
	BGPState      string `json:"bgpState"`
	HostLocal     string `json:"hostLocal"`
	NexthopGlobal string `json:"nexthopGlobal"`
}

// mappedNextHop reports whether n announces an IPv4-mapped next hop. ok is
// false for a session the check does not apply to: one not established, or
// one whose own local address is not a global IPv6 address.
func (n neighbor) mappedNextHop() (mapped, ok bool) {
	if n.BGPState != stateEstablished {
		return false, false
	}
	local, err := netip.ParseAddr(n.HostLocal)
	if err != nil || !local.Is6() || local.Is4In6() || !local.IsGlobalUnicast() {
		return false, false
	}
	nh, err := netip.ParseAddr(n.NexthopGlobal)
	if err != nil {
		return false, true
	}
	return nh.Is4In6(), true
}

// parseNeighbors parses `show bgp neighbors json`, an object keyed by
// neighbor address, into neighbors sorted by address. Entries that are not
// objects are skipped.
func parseNeighbors(out []byte) ([]neighbor, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	neighbors := make([]neighbor, 0, len(raw))
	for peer, v := range raw {
		var n neighbor
		if err := json.Unmarshal(v, &n); err != nil {
			continue
		}
		n.Peer = peer
		neighbors = append(neighbors, n)
	}
	sort.Slice(neighbors, func(i, j int) bool { return neighbors[i].Peer < neighbors[j].Peer })
	return neighbors, nil
}

// zebraRoute is the part of one route entry of `show ip[v6] route json` the
// guard reads.
type zebraRoute struct {
	Protocol  string `json:"protocol"`
	Selected  bool   `json:"selected"`
	Installed bool   `json:"installed"`
}

// uninstalledBGPRoutes counts the prefixes in `show ip[v6] route json` that
// have a BGP route and no route of any protocol installed. A BGP route that
// loses to an installed connected or static route is not counted.
func uninstalledBGPRoutes(out []byte) (int, error) {
	var prefixes map[string][]zebraRoute
	if err := json.Unmarshal(out, &prefixes); err != nil {
		return 0, err
	}
	n := 0
	for _, routes := range prefixes {
		hasBGP, installed := false, false
		for _, r := range routes {
			hasBGP = hasBGP || r.Protocol == protocolBGP
			installed = installed || r.Installed
		}
		if hasBGP && !installed {
			n++
		}
	}
	return n, nil
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
