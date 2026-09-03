// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testNamespace = "galactic-system"
	testLocator   = "2607:ed40:8002::/48"
)

// newRouterClient builds a fake client holding routers, so the derivation can
// be exercised without a kernel or an API server. nodeLocatorPrefix is the
// half of ensureLocatorLocalRoute worth testing: the netlink call needs root
// and a real lo, but getting the prefix wrong would install a local route for
// address space this node does not own.
func newRouterClient(t *testing.T, routers ...*bgpv1alpha1.BGPRouter) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, r := range routers {
		b = b.WithObjects(r)
	}
	return b.Build()
}

func router(target, locator string, nodeID int32) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Name: target},
			SRv6Locator: locator,
			NodeID:      nodeID,
		},
	}
}

// TestNodeLocatorPrefix_DerivesBlockPlusNodeID pins the layout the whole fix
// depends on: Node-ID sits at bits 49-64, immediately after the 48-bit Block,
// and the result is the /64 covering every SID this node can compute.
func TestNodeLocatorPrefix_DerivesBlockPlusNodeID(t *testing.T) {
	for _, tc := range []struct {
		name, locator string
		nodeID        int32
		want          string
	}{
		{"node 1", testLocator, 1, "2607:ed40:8002:1::/64"},
		{"node 6", testLocator, 6, "2607:ed40:8002:6::/64"},
		{"two-byte node id", testLocator, 0x0142, "2607:ed40:8002:142::/64"},
		{"max node id", "2607:ed40:8001::/48", 0xDFFF, "2607:ed40:8001:dfff::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRouterClient(t, router("n1", tc.locator, tc.nodeID))
			got, err := nodeLocatorPrefix(context.Background(), c, testNamespace, "n1")
			if err != nil {
				t.Fatalf("nodeLocatorPrefix() error = %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("nodeLocatorPrefix() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNodeLocatorPrefix_AbsentIsNotAnError covers the ordinary bring-up
// states: this node has no BGPRouter yet, or one that carries no locator.
// Both must read as "nothing to install", never as a failure, or the
// installer daemon would report an error on every refresh on a node that
// simply is not an SRv6 node.
func TestNodeLocatorPrefix_AbsentIsNotAnError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routers []*bgpv1alpha1.BGPRouter
		node    string
	}{
		{"no routers at all", nil, "n1"},
		{"router targets another node", []*bgpv1alpha1.BGPRouter{router("other", testLocator, 1)}, "n1"},
		{"no locator configured", []*bgpv1alpha1.BGPRouter{router("n1", "", 1)}, "n1"},
		{"no node id configured", []*bgpv1alpha1.BGPRouter{router("n1", testLocator, 0)}, "n1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRouterClient(t, tc.routers...)
			got, err := nodeLocatorPrefix(context.Background(), c, testNamespace, tc.node)
			if err != nil {
				t.Fatalf("nodeLocatorPrefix() error = %v, want nil", err)
			}
			if got.IsValid() {
				t.Errorf("nodeLocatorPrefix() = %s, want the zero Prefix", got)
			}
		})
	}
}

// TestNodeLocatorPrefix_RejectsBadLocator guards the other direction: a
// locator that is not a /48 uSID Block, or a Node-ID out of range, must fail
// loudly rather than silently produce a prefix for space this node does not
// own -- installing a local route for someone else's locator would blackhole
// their SIDs on this node.
func TestNodeLocatorPrefix_RejectsBadLocator(t *testing.T) {
	for _, tc := range []struct {
		name, locator string
		nodeID        int32
		wantSubstr    string
	}{
		{"not a /48", "2607:ed40:8002::/56", 1, "uSID Block"},
		{"ipv4", "10.0.0.0/48", 1, ""},
		{"unparseable", "not-a-prefix", 1, "parse SRv6 locator"},
		{"node id too large", testLocator, 0x10000, "outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRouterClient(t, router("n1", tc.locator, tc.nodeID))
			_, err := nodeLocatorPrefix(context.Background(), c, testNamespace, "n1")
			if err == nil {
				t.Fatalf("nodeLocatorPrefix() error = nil, want an error")
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("nodeLocatorPrefix() error = %q, want it to mention %q", err, tc.wantSubstr)
			}
		})
	}
}

// TestEnsureLocatorLocalRoute_NoIdentityIsNoop covers the guard that keeps
// this inert on a node with no configured identity, before any netlink call
// is attempted -- so it is safe on a node where the installer runs without a
// name or client.
func TestEnsureLocatorLocalRoute_NoIdentityIsNoop(t *testing.T) {
	if err := ensureLocatorLocalRoute(context.Background(), nil, testNamespace, ""); err != nil {
		t.Errorf("ensureLocatorLocalRoute(nil, \"\") error = %v, want nil", err)
	}
	c := newRouterClient(t)
	if err := ensureLocatorLocalRoute(context.Background(), c, testNamespace, ""); err != nil {
		t.Errorf("ensureLocatorLocalRoute(_, \"\") error = %v, want nil", err)
	}
}

// localRoute builds a local-table route the way the kernel reports one, so
// the cases below differ only in the field under test.
func localRoute(dst string, loIndex int, opts ...func(*netlink.Route)) netlink.Route {
	_, n, err := net.ParseCIDR(dst)
	if err != nil {
		panic(err)
	}
	r := netlink.Route{
		Dst:       n,
		LinkIndex: loIndex,
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

// TestStaleLocatorLocalRoute is the safety argument for pruning, written as
// the cases that must NOT be deleted. This predicate deletes from the local
// table, which is mostly the kernel's; matching one of the node's own address
// routes would black-hole that address. Every "want false" below is a route
// that has to survive.
func TestStaleLocatorLocalRoute(t *testing.T) {
	const lo = 1
	keep := netip.MustParsePrefix("2607:ed40:8002:6::/64")
	kernel := func(r *netlink.Route) { r.Protocol = unix.RTPROT_KERNEL }

	for _, tc := range []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		// The bug this fixes: a node moved to a different Block leaves the
		// old /64 local on lo, claiming space it no longer owns.
		{"our route for a locator we no longer own", localRoute("2607:ed40:8006:6::/64", lo), true},
		{"a different Node-ID in the same Block", localRoute("2607:ed40:8002:1::/64", lo), true},

		{"the prefix we want to keep", localRoute("2607:ed40:8002:6::/64", lo), false},

		// Kernel-derived entries: one per assigned address. Deleting the
		// loopback's would take this node's router-id address away.
		{"kernel loopback host route", localRoute("2607:ed40:1fe::4/128", lo, kernel), false},
		{"kernel ::1", localRoute("::1/128", lo, kernel), false},
		// A /64 that the kernel derived, which we must still not touch even
		// though its length matches ours.
		{"kernel-derived /64", localRoute("2607:ed40:8006:6::/64", lo, kernel), false},

		{"another link's route", localRoute("2607:ed40:8006:6::/64", lo+1), false},
		{"another table", localRoute("2607:ed40:8006:6::/64", lo,
			func(r *netlink.Route) { r.Table = unix.RT_TABLE_MAIN }), false},
		{"not a local route", localRoute("2607:ed40:8006:6::/64", lo,
			func(r *netlink.Route) { r.Type = unix.RTN_UNICAST }), false},

		// Only the /64 this component writes qualifies. A /48 Block discard
		// or a /128 SID is somebody else's business.
		{"the /48 Block, not a node locator", localRoute("2607:ed40:8006::/48", lo), false},
		{"a single SID", localRoute("2607:ed40:8006:6::1/128", lo), false},

		{"no destination", netlink.Route{LinkIndex: lo, Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL}, false},
		{"ipv4", localRoute("10.0.0.0/24", lo), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := staleLocatorLocalRoute(tc.route, lo, keep); got != tc.want {
				t.Errorf("staleLocatorLocalRoute(%v) = %v, want %v", tc.route.Dst, got, tc.want)
			}
		})
	}
}

// TestPruneStaleLocatorLocalRoutes_UnknownLinkIsQuiet records the kernel
// behaviour this relies on to stay inert on a host with no matching routes:
// a filtered list against an ifindex that does not exist comes back empty
// rather than failing, so pruning finds nothing to do and reports no error.
// Pinned so this does not start warning on every refresh tick.
func TestPruneStaleLocatorLocalRoutes_UnknownLinkIsQuiet(t *testing.T) {
	err := pruneStaleLocatorLocalRoutes(0x7fffffff, netip.MustParsePrefix("2607:ed40:8002:6::/64"))
	if err != nil {
		t.Errorf("pruneStaleLocatorLocalRoutes() on a nonexistent link error = %v, want nil", err)
	}
}
