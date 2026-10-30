// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
)

// Neighbors as `show bgp neighbors json` reports them: one session announcing
// an IPv4-mapped next hop, one healthy IPv6 session, an IPv4 session, one not
// yet established, and one sourced from a link-local address.
const neighborsJSON = `{
  "2001:db8:0:3f::39b": {
    "bgpState": "Established",
    "hostLocal": "2001:db8:0:48::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1": {
    "bgpState": "Established",
    "hostLocal": "2001:db8:0:48::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "2001:db8:0:48::2",
    "nexthopLocal": "::"
  },
  "10.1.30.1": {
    "bgpState": "Established",
    "hostLocal": "10.1.30.2",
    "nexthop": "10.1.30.2",
    "nexthopGlobal": "::ffff:10.1.30.2",
    "nexthopLocal": "::"
  },
  "fd00::ffff:2": {
    "bgpState": "Active",
    "hostLocal": "Unknown",
    "nexthop": "Unknown",
    "nexthopGlobal": "Unknown",
    "nexthopLocal": "Unknown"
  },
  "fe80::1": {
    "bgpState": "Established",
    "hostLocal": "fe80::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "fe80::2"
  }
}`

const mappedPeer = "2001:db8:0:3f::39b"

// Routes as `show ipv6 route json` reports them: a BGP route with no installed
// route, an installed BGP route, a BGP route that loses to an installed static
// route, and a connected route.
const routesJSON = `{
  "2001:db8:10d::1:0:1/128": [
    {"protocol": "bgp", "selected": true, "distance": 200}
  ],
  "fc00:0:5::/48": [
    {"protocol": "bgp", "selected": true, "installed": true, "distance": 200}
  ],
  "fc00:0:4::/48": [
    {"protocol": "static", "selected": true, "installed": true, "distance": 1},
    {"protocol": "bgp", "distance": 200}
  ],
  "2001:db8:0:48::/64": [
    {"protocol": "connected", "selected": true, "installed": true}
  ]
}`

// Connected routes as FRR 10.7's `show ipv6 route connected json` and `show
// ip route connected json` report them, captured from zebra and readdressed:
// the loopback's own /128 and /32, a link-local /64 on another interface, and
// a connected route zebra holds but has not selected, which FRR reports
// without a "selected" key. Only line breaks are added to zebra's output.
const (
	connectedV6JSON = `{"2001:db8:ffff::7/128":[{"protocol":"connected","selected":true,"destSelected":true,
  "distance":0,"metric":0,"installed":true,"nexthopGroupId":9,"vrfId":0,"vrfName":"default","uptime":"00:00:03",
  "prefix":"2001:db8:ffff::7/128","prefixLen":128,"table":254,"internalStatus":16,"internalFlags":8,
  "internalNextHopNum":1,"internalNextHopActiveNum":1,"internalNextHopFibInstalledNum":1,
  "installedNexthopGroupId":9,"receivedNexthopGroupId":9,"nexthops":[{"flags":3,"fib":true,
  "directlyConnected":true,"interfaceIndex":1,"interfaceName":"lo","active":true,"weight":1}]}]
,"2001:db8:ffff::8/128":[{"protocol":"connected",
  "distance":0,"metric":600,"installed":true,"nexthopGroupId":10,"vrfId":0,"vrfName":"default","uptime":"00:00:03",
  "prefix":"2001:db8:ffff::8/128","prefixLen":128,"table":254,"internalStatus":16,"internalFlags":0,
  "internalNextHopNum":1,"internalNextHopActiveNum":1,"internalNextHopFibInstalledNum":1,
  "receivedNexthopGroupId":10,"nexthops":[{"flags":3,"fib":true,
  "directlyConnected":true,"interfaceIndex":2,"interfaceName":"eth0","active":true,"weight":1}]}]
,"fe80::/64":[{"protocol":"connected","selected":true,"destSelected":true,
  "distance":0,"metric":0,"installed":true,"nexthopGroupId":10,"vrfId":0,"vrfName":"default","uptime":"00:00:02",
  "prefix":"fe80::/64","prefixLen":64,"table":254,"internalStatus":16,"internalFlags":8,
  "internalNextHopNum":1,"internalNextHopActiveNum":1,"internalNextHopFibInstalledNum":1,
  "installedNexthopGroupId":10,"receivedNexthopGroupId":10,"nexthops":[{"flags":3,"fib":true,
  "directlyConnected":true,"interfaceIndex":2,"interfaceName":"eth0","active":true,"weight":1}]}]
}`
	connectedV4JSON = `{"192.0.2.7/32":[{"protocol":"connected","selected":true,"destSelected":true,
  "distance":0,"metric":0,"installed":true,"nexthopGroupId":7,"vrfId":0,"vrfName":"default","uptime":"00:00:03",
  "prefix":"192.0.2.7/32","prefixLen":32,"table":254,"internalStatus":16,"internalFlags":8,
  "internalNextHopNum":1,"internalNextHopActiveNum":1,"internalNextHopFibInstalledNum":1,
  "installedNexthopGroupId":7,"receivedNexthopGroupId":7,"nexthops":[{"flags":3,"fib":true,
  "directlyConnected":true,"interfaceIndex":1,"interfaceName":"lo","active":true,"weight":1}]}]
,"198.51.100.0/24":[{"protocol":"connected","selected":true,"destSelected":true,
  "distance":0,"metric":600,"installed":true,"nexthopGroupId":8,"vrfId":0,"vrfName":"default","uptime":"00:00:03",
  "prefix":"198.51.100.0/24","prefixLen":24,"table":254,"internalStatus":16,"internalFlags":8,
  "internalNextHopNum":1,"internalNextHopActiveNum":1,"internalNextHopFibInstalledNum":1,
  "installedNexthopGroupId":8,"receivedNexthopGroupId":8,"nexthops":[{"flags":3,"fib":true,
  "directlyConnected":true,"interfaceIndex":2,"interfaceName":"eth0","active":true,"weight":1}]}]
}`
)

type fakeBGP struct {
	neighbors    string
	routes       string
	connected    map[string]string
	neighborErr  error
	connectedErr map[string]error
	resetErr     error
	resets       []string
}

func (f *fakeBGP) Neighbors(context.Context) ([]byte, error) {
	if f.neighborErr != nil {
		return nil, f.neighborErr
	}
	return []byte(f.neighbors), nil
}

func (f *fakeBGP) Routes(context.Context, string) ([]byte, error) {
	return []byte(f.routes), nil
}

// ConnectedRoutes returns f.connected keyed by the family's metric label, or
// "{}" when it has none.
func (f *fakeBGP) ConnectedRoutes(_ context.Context, cmd string) ([]byte, error) {
	label := ""
	for _, fam := range zebraFamilies {
		if fam.cmd == cmd {
			label = fam.label
		}
	}
	if err := f.connectedErr[label]; err != nil {
		return nil, err
	}
	if out, ok := f.connected[label]; ok {
		return []byte(out), nil
	}
	return []byte("{}"), nil
}

func (f *fakeBGP) ResetNeighbor(_ context.Context, neighbor string) error {
	f.resets = append(f.resets, neighbor)
	return f.resetErr
}

// fakeAddresses lists a fixed set of interface addresses, or fails with err.
type fakeAddresses struct {
	addrs []netlink.Addr
	err   error
}

func (f *fakeAddresses) list() ([]netlink.Addr, error) { return f.addrs, f.err }

// ifAddr builds an address on the interface with index link, as netlink
// reports it.
func ifAddr(t *testing.T, link int, cidr string, scope, flags int) netlink.Addr {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %q: %v", cidr, err)
	}
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, LinkIndex: link, Scope: scope, Flags: flags}
}

func newTestGuard(bgp *fakeBGP) (*NextHopGuard, *events.FakeRecorder, *time.Time) {
	now := time.Date(2026, 10, 2, 14, 25, 0, 0, time.UTC)
	rec := events.NewFakeRecorder(10)
	g := &NextHopGuard{
		BGP:       bgp,
		Metrics:   NewNextHopMetrics(),
		Recorder:  rec,
		Pod:       &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "fabric-router-abcde", Namespace: testNamespace}},
		NodeName:  "edge-1",
		Addresses: (&fakeAddresses{}).list,
		now:       func() time.Time { return now },
	}
	return g, rec, &now
}

func TestNextHopGuardResetsMappedSession(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, rec, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(bgp.resets) != 1 || bgp.resets[0] != mappedPeer {
		t.Fatalf("resets = %v, want [%s]", bgp.resets, mappedPeer)
	}
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, ReasonMappedNextHopReset) || !strings.Contains(e, mappedPeer) {
			t.Errorf("event = %q, want %s for %s", e, ReasonMappedNextHopReset, mappedPeer)
		}
	default:
		t.Error("no event recorded")
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("mapped{%s} = %v, want 1", mappedPeer, got)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues("fd00::ffff:1")); got != 0 {
		t.Errorf("mapped{fd00::ffff:1} = %v, want 0", got)
	}
	// Only the two established sessions sourced from a global IPv6 address
	// are reported; the IPv4, down and link-local sessions are not.
	if got := testutil.CollectAndCount(g.Metrics.mapped); got != 2 {
		t.Errorf("mapped series = %d, want 2", got)
	}
	if got := testutil.ToFloat64(g.Metrics.resets.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("resets{%s} = %v, want 1", mappedPeer, got)
	}
}

func TestNextHopGuardBacksOffRepeatedResets(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, now := newTestGuard(bgp)
	g.ResetBackoff = 10 * time.Minute
	ctx := context.Background()

	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 1},
		{time.Minute, 1},
		{5 * time.Minute, 1},
		{5 * time.Minute, 2},
	} {
		*now = now.Add(step.advance)
		if err := g.Check(ctx); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(bgp.resets) != step.want {
			t.Fatalf("after %v: resets = %d, want %d", step.advance, len(bgp.resets), step.want)
		}
	}
}

func TestNextHopGuardDetectOnly(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, _ := newTestGuard(bgp)
	g.DetectOnly = true

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(bgp.resets) != 0 {
		t.Errorf("resets = %v, want none", bgp.resets)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("mapped{%s} = %v, want 1", mappedPeer, got)
	}
}

func TestNextHopGuardClearsRecoveredSession(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, _ := newTestGuard(bgp)
	ctx := context.Background()
	if err := g.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}

	bgp.neighbors = strings.Replace(neighborsJSON, `"nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1"`, `"nexthopGlobal": "2001:db8:0:48::2",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1"`, 1)
	if err := g.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 0 {
		t.Errorf("mapped{%s} = %v after recovery, want 0", mappedPeer, got)
	}
	if len(bgp.resets) != 1 {
		t.Errorf("resets = %d, want 1", len(bgp.resets))
	}
}

func TestNextHopGuardCountsUninstalledRoutes(t *testing.T) {
	bgp := &fakeBGP{neighbors: "{}", routes: routesJSON}
	g, _, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, afi := range []string{afiIPv4, afiIPv6} {
		if got := testutil.ToFloat64(g.Metrics.uninstalled.WithLabelValues(afi)); got != 1 {
			t.Errorf("uninstalled{%s} = %v, want 1", afi, got)
		}
	}
}

func TestNextHopGuardReportsReadErrors(t *testing.T) {
	bgp := &fakeBGP{neighborErr: errors.New("bgpd is not running"), routes: routesJSON}
	g, _, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err == nil {
		t.Fatal("Check: want error, got nil")
	}
	// The route count still runs after the neighbor read fails.
	if got := testutil.ToFloat64(g.Metrics.uninstalled.WithLabelValues(afiIPv6)); got != 1 {
		t.Errorf("uninstalled{ipv6} = %v, want 1", got)
	}
}

func TestNextHopGuardResetFailureRaisesNoEvent(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON, resetErr: errors.New("vtysh failed")}
	g, rec, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	select {
	case e := <-rec.Events:
		t.Errorf("unexpected event %q for a failed reset", e)
	default:
	}
	if got := testutil.ToFloat64(g.Metrics.resets.WithLabelValues(mappedPeer)); got != 0 {
		t.Errorf("resets{%s} = %v, want 0", mappedPeer, got)
	}
}

func TestNextHopGuardCountsMissingConnectedRoutes(t *testing.T) {
	const lo, eth0 = loopbackIfIndex, 2
	universe, host, link := unix.RT_SCOPE_UNIVERSE, unix.RT_SCOPE_HOST, unix.RT_SCOPE_LINK
	tests := []struct {
		name         string
		addrs        func(t *testing.T) []netlink.Addr
		wantV4       float64
		wantV6       float64
		connectedFor map[string]string
	}{
		{
			name: "loopback addresses with connected routes",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{
					ifAddr(t, lo, "2001:db8:ffff::7/128", universe, 0),
					ifAddr(t, lo, "192.0.2.7/32", universe, 0),
				}
			},
		},
		{
			name: "IPv6 loopback address without a connected route",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{
					ifAddr(t, lo, "2001:db8:ffff::7/128", universe, 0),
					ifAddr(t, lo, "2001:db8:ffff::9/128", universe, 0),
					ifAddr(t, lo, "192.0.2.7/32", universe, 0),
				}
			},
			wantV6: 1,
		},
		{
			name: "both families without connected routes",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{
					ifAddr(t, lo, "2001:db8:ffff::7/128", universe, 0),
					ifAddr(t, lo, "192.0.2.7/32", universe, 0),
				}
			},
			connectedFor: map[string]string{afiIPv4: "{}", afiIPv6: "{}"},
			wantV4:       1,
			wantV6:       1,
		},
		{
			name: "a connected route zebra has not selected is missing",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{ifAddr(t, lo, "2001:db8:ffff::8/128", universe, 0)}
			},
			wantV6: 1,
		},
		{
			name: "a loopback address shorter than a host route matches its network",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{ifAddr(t, lo, "198.51.100.9/24", universe, 0)}
			},
		},
		{
			name: "addresses the check does not apply to are ignored",
			addrs: func(t *testing.T) []netlink.Addr {
				return []netlink.Addr{
					// On another interface.
					ifAddr(t, eth0, "2001:db8:ffff::10/64", universe, 0),
					ifAddr(t, eth0, "203.0.113.10/24", universe, 0),
					// Host and link scope.
					ifAddr(t, lo, "::1/128", host, 0),
					ifAddr(t, lo, "127.0.0.1/8", host, 0),
					ifAddr(t, lo, "fe80::1/64", link, 0),
					// Not global unicast, though reported with universe scope.
					ifAddr(t, lo, "fe80::2/64", universe, 0),
					ifAddr(t, lo, "169.254.0.1/32", universe, 0),
					ifAddr(t, lo, "ff02::1/128", universe, 0),
					// Added with noprefixroute, so zebra adds no route for it.
					ifAddr(t, lo, "2001:db8:ffff::11/128", universe, unix.IFA_F_NOPREFIXROUTE),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connected := map[string]string{afiIPv4: connectedV4JSON, afiIPv6: connectedV6JSON}
			for afi, out := range tt.connectedFor {
				connected[afi] = out
			}
			bgp := &fakeBGP{neighbors: "{}", routes: "{}", connected: connected}
			g, _, _ := newTestGuard(bgp)
			g.Addresses = (&fakeAddresses{addrs: tt.addrs(t)}).list

			if err := g.Check(context.Background()); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv4)); got != tt.wantV4 {
				t.Errorf("connected_routes_missing{ipv4} = %v, want %v", got, tt.wantV4)
			}
			if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv6)); got != tt.wantV6 {
				t.Errorf("connected_routes_missing{ipv6} = %v, want %v", got, tt.wantV6)
			}
		})
	}
}

// missingConnectedGuard returns a guard whose first pass counted one missing
// connected route in each family.
func missingConnectedGuard(t *testing.T) (*NextHopGuard, *fakeBGP, *fakeAddresses) {
	t.Helper()
	bgp := &fakeBGP{neighbors: "{}", routes: routesJSON, connected: map[string]string{afiIPv4: "{}", afiIPv6: "{}"}}
	addrs := &fakeAddresses{addrs: []netlink.Addr{
		ifAddr(t, loopbackIfIndex, "2001:db8:ffff::7/128", unix.RT_SCOPE_UNIVERSE, 0),
		ifAddr(t, loopbackIfIndex, "192.0.2.7/32", unix.RT_SCOPE_UNIVERSE, 0),
	}}
	g, _, _ := newTestGuard(bgp)
	g.Addresses = addrs.list
	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, afi := range []string{afiIPv4, afiIPv6} {
		if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afi)); got != 1 {
			t.Fatalf("connected_routes_missing{%s} = %v after the first pass, want 1", afi, got)
		}
	}
	return g, bgp, addrs
}

func TestNextHopGuardConnectedAddressListError(t *testing.T) {
	g, bgp, addrs := missingConnectedGuard(t)
	// The routes come back, but the addresses can no longer be listed.
	bgp.connected = map[string]string{afiIPv4: connectedV4JSON, afiIPv6: connectedV6JSON}
	addrs.err = errors.New("netlink: operation not permitted")

	err := g.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "list interface addresses") {
		t.Fatalf("Check error = %v, want the address listing error", err)
	}
	// Neither family is zeroed by a pass that could not read the addresses.
	for _, afi := range []string{afiIPv4, afiIPv6} {
		if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afi)); got != 1 {
			t.Errorf("connected_routes_missing{%s} = %v, want 1 kept", afi, got)
		}
	}
	// The rest of the pass still ran.
	if got := testutil.ToFloat64(g.Metrics.uninstalled.WithLabelValues(afiIPv6)); got != 1 {
		t.Errorf("uninstalled{ipv6} = %v, want 1", got)
	}
}

func TestNextHopGuardConnectedRouteReadError(t *testing.T) {
	g, bgp, _ := missingConnectedGuard(t)
	// IPv4's connected route is back; IPv6's routes cannot be read.
	bgp.connected = map[string]string{afiIPv4: connectedV4JSON}
	bgp.connectedErr = map[string]error{afiIPv6: errors.New("zebra is not running")}

	err := g.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read ipv6 connected routes") {
		t.Fatalf("Check error = %v, want the ipv6 read error", err)
	}
	if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv4)); got != 0 {
		t.Errorf("connected_routes_missing{ipv4} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv6)); got != 1 {
		t.Errorf("connected_routes_missing{ipv6} = %v, want 1 kept", got)
	}
}

func TestNextHopGuardConnectedRouteParseError(t *testing.T) {
	g, bgp, _ := missingConnectedGuard(t)
	bgp.connected = map[string]string{afiIPv4: "% Unknown command", afiIPv6: connectedV6JSON}

	err := g.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse ipv4 connected routes") {
		t.Fatalf("Check error = %v, want the ipv4 parse error", err)
	}
	if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv4)); got != 1 {
		t.Errorf("connected_routes_missing{ipv4} = %v, want 1 kept", got)
	}
	if got := testutil.ToFloat64(g.Metrics.connectedMissing.WithLabelValues(afiIPv6)); got != 0 {
		t.Errorf("connected_routes_missing{ipv6} = %v, want 0", got)
	}
}

// TestListAddressesReadsLoopback checks, in a fresh network namespace, that
// the default address lister reports the loopback's addresses with the
// loopback's index, so the check finds them, and another link's addresses
// with another index, so it skips them.
func TestListAddressesReadsLoopback(t *testing.T) {
	requireRoot(t)

	netns, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer netns.Close() //nolint:errcheck // best-effort cleanup

	var got []netip.Prefix
	err = netns.Do(func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return err
		}
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0"}}); err != nil {
			return err
		}
		dummy, err := netlink.LinkByName("dummy0")
		if err != nil {
			return err
		}
		for _, a := range []struct {
			link  netlink.Link
			cidr  string
			flags int
		}{
			{lo, "2001:db8:ffff::7/128", 0},
			{lo, "192.0.2.7/32", 0},
			{lo, "2001:db8:ffff::11/128", unix.IFA_F_NOPREFIXROUTE},
			{dummy, "2001:db8:ffff::10/64", 0},
		} {
			addr, err := netlink.ParseAddr(a.cidr)
			if err != nil {
				return err
			}
			addr.Flags = a.flags
			if err := netlink.AddrAdd(a.link, addr); err != nil {
				return fmt.Errorf("add %s: %w", a.cidr, err)
			}
		}
		addrs, err := listAddresses()
		if err != nil {
			return err
		}
		got = loopbackPrefixes(addrs)
		return nil
	})
	if err != nil {
		t.Fatalf("in test netns: %v", err)
	}

	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("2001:db8:ffff::7/128")}
	sort.Slice(got, func(i, j int) bool { return got[i].Addr().Less(got[j].Addr()) })
	if !slices.Equal(got, want) {
		t.Errorf("loopback prefixes = %v, want %v", got, want)
	}
}

// requireRoot skips the test when not running as root. Network namespace
// operations require CAP_SYS_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN)")
	}
}
