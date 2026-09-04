// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testSidecarNode = "worker-8b4e1647-dfw"
	testSidecarAddr = "fd30:e2e:3a5:6094:7c95:22a:4aec:a4a9"
)

// newAdvClient builds a fake client holding advertisements, so endpoint
// selection can be exercised without an API server. The counterpart to
// locatorroute_test.go's newRouterClient, which holds BGPRouters.
func newAdvClient(t *testing.T, advs ...*bgpv1alpha1.BGPAdvertisement) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(s)
	for _, a := range advs {
		b = b.WithObjects(a)
	}
	return b.Build()
}

// gatewayAdv builds a BGPAdvertisement shaped like one the ingress sidecar
// publishes, named exactly the way crdnames does it so the recognition
// under test is exercised against the real encoder rather than a literal.
func gatewayAdv(vpc, node, prefix string, vrfID int32) *bgpv1alpha1.BGPAdvertisement {
	fn := bgpv1alpha1.SRv6FunctionEndDT46
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(vpc, crdnames.IngressAttachment, node),
			Namespace: testNamespace,
			Annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "24",
				crdnames.AnnotationIngressHostMAC:     "9a:91:c0:8d:83:f1",
			},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef: bgpv1alpha1.RouterRef{Name: node},
			Prefixes:  []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix)},
			VRFID:     &vrfID,
			Function:  &fn,
		},
	}
}

// podAdv builds the advertisement a *real* CNI attachment publishes for a
// pod address: same shape (one /128, an Argument, End.DT46), different
// middle name segment. These must never be picked up here -- see
// TestSidecarGatewayEndpoints_IgnoresPodAdvertisements.
func podAdv(vpc, attachment, node, prefix string, vrfID int32) *bgpv1alpha1.BGPAdvertisement {
	adv := gatewayAdv(vpc, node, prefix, vrfID)
	adv.Name = crdnames.BGPAdvertisementName(vpc, attachment, node)
	return adv
}

// TestIngressAdvertisementSegment_MatchesTheEncoder pins the one value both
// ends of this feature depend on. internal/ingresssidecar names its
// advertisements through BGPAdvertisementName and the host side recognizes
// them by this segment; if the encoding of "ingress" ever changed, the
// sidecar would keep publishing and the host would silently stop installing
// return paths, with nothing failing anywhere.
func TestIngressAdvertisementSegment_MatchesTheEncoder(t *testing.T) {
	got := crdnames.IngressAdvertisementSegment()
	// The middle segment of a real advertisement name, extracted the same
	// way isIngressAdvertisementName does.
	name := crdnames.BGPAdvertisementName("2", crdnames.IngressAttachment, testSidecarNode)
	if !isIngressAdvertisementName(name, testSidecarNode, got) {
		t.Fatalf("IngressAdvertisementSegment() = %q does not match name %q it must recognize", got, name)
	}
}

// TestIsIngressAdvertisementName covers the matching that decides whether a
// return path gets installed at all. The node-name cases are the ones worth
// having: a node name contains the same separator the name segments are
// joined with, so matching from the left would mis-split every real node
// name in this fleet.
func TestIsIngressAdvertisementName(t *testing.T) {
	seg := crdnames.IngressAdvertisementSegment()
	for _, tc := range []struct {
		name, advName, node string
		want                bool
	}{
		{
			name:    "sidecar advertisement on a hyphenated node",
			advName: crdnames.BGPAdvertisementName("2", crdnames.IngressAttachment, testSidecarNode),
			node:    testSidecarNode, want: true,
		},
		{
			name:    "sidecar advertisement on a single-word node",
			advName: crdnames.BGPAdvertisementName("2", crdnames.IngressAttachment, "eris-giune"),
			node:    "eris-giune", want: true,
		},
		// A pod's own advertisement: identical shape, different segment.
		{
			name:    "pod attachment advertisement",
			advName: crdnames.BGPAdvertisementName("2", "0mg", testSidecarNode),
			node:    testSidecarNode, want: false,
		},
		// The same sidecar advertisement, but originated by another node.
		{
			name:    "another node's sidecar advertisement",
			advName: crdnames.BGPAdvertisementName("2", crdnames.IngressAttachment, "eris-giune"),
			node:    testSidecarNode, want: false,
		},
		{name: "empty", advName: "", node: testSidecarNode, want: false},
		{name: "node name only", advName: testSidecarNode, node: testSidecarNode, want: false},
		{
			name:    "segment present but not in the middle position",
			advName: seg + "-" + testSidecarNode,
			node:    testSidecarNode, want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIngressAdvertisementName(tc.advName, tc.node, seg); got != tc.want {
				t.Errorf("isIngressAdvertisementName(%q, %q) = %v, want %v",
					tc.advName, tc.node, got, tc.want)
			}
		})
	}
}

// TestSidecarReturnTableID_StaysInTheReservedRange pins the mapping the
// prune predicate's safety depends on: every table this file can allocate
// has to land inside the range staleSidecarReturnRoute will consider, and
// nothing else may.
func TestSidecarReturnTableID_StaysInTheReservedRange(t *testing.T) {
	for _, vrfID := range []uint16{uformat.ArgumentMin, 1, 6, 2048, uformat.ArgumentMax} {
		got, err := sidecarReturnTableID(vrfID)
		if err != nil {
			t.Fatalf("sidecarReturnTableID(%d) error = %v", vrfID, err)
		}
		if got < sidecarReturnTableBase || got > sidecarReturnTableMax {
			t.Errorf("sidecarReturnTableID(%d) = %d, outside the reserved range [%d,%d]",
				vrfID, got, sidecarReturnTableBase, sidecarReturnTableMax)
		}
	}
}

// TestSidecarReturnTableID_RejectsOutOfRange guards the other direction. A
// zero Argument is the reserved value uformat excludes, and anything past
// ArgumentMax cannot have arrived in a SID at all -- either would compute a
// table id outside the reserved range and put pruning in reach of somebody
// else's routes.
func TestSidecarReturnTableID_RejectsOutOfRange(t *testing.T) {
	for _, vrfID := range []uint16{0, uformat.ArgumentMax + 1, 0xFFFF} {
		if _, err := sidecarReturnTableID(vrfID); err == nil {
			t.Errorf("sidecarReturnTableID(%d) error = nil, want an error", vrfID)
		}
	}
}

// returnRoute builds a route the way the kernel reports one from this file's
// own table range, so the cases below differ only in the field under test.
func returnRoute(dst string, table int) netlink.Route {
	_, n, err := net.ParseCIDR(dst)
	if err != nil {
		panic(err)
	}
	return netlink.Route{Dst: n, Table: table}
}

// TestStaleSidecarReturnRoute is the safety argument for pruning, written
// as the cases that must NOT be deleted. This predicate deletes routes, so
// every "want false" is a route that has to survive -- most importantly
// anything outside the reserved table range, which is every route the
// kernel and every other component on the node own.
func TestStaleSidecarReturnRoute(t *testing.T) {
	const vrfID = 1
	table, err := sidecarReturnTableID(vrfID)
	if err != nil {
		t.Fatalf("sidecarReturnTableID: %v", err)
	}
	keep := netip.MustParseAddr(testSidecarAddr)
	live := map[uint32]netip.Addr{table: keep}

	for _, tc := range []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{"the route we want to keep", returnRoute(testSidecarAddr+"/128", int(table)), false},

		// The bug this prunes: the advertisement moved to a different
		// address, or was withdrawn and another took its table.
		{"a different address in a live table", returnRoute("fd30:e2e:1::1/128", int(table)), true},
		{"a table no live endpoint maps to", returnRoute(testSidecarAddr+"/128", sidecarReturnTableBase+9), true},

		// Everything outside the range belongs to somebody else.
		{"the main table", returnRoute(testSidecarAddr+"/128", 254), false},
		{"a tenant VRF table", returnRoute(testSidecarAddr+"/128", 1), false},
		{"just below the range", returnRoute(testSidecarAddr+"/128", sidecarReturnTableBase-1), false},
		{"just above the range", returnRoute(testSidecarAddr+"/128", sidecarReturnTableMax+1), false},

		{"no destination", netlink.Route{Table: int(table)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := staleSidecarReturnRoute(tc.route, live); got != tc.want {
				t.Errorf("staleSidecarReturnRoute(%v, table %d) = %v, want %v",
					tc.route.Dst, tc.route.Table, got, tc.want)
			}
		})
	}
}

// TestSidecarGatewayEndpoints_ReadsAdvertisedArgument is the point of the
// whole file: the Argument used here must be the one the advertisement
// carries, because that is what a remote node encodes into the SID it sends.
// The sidecar's own vrf_table registrations use a different number for the
// same VPC (its pod-netns table id), so reading the wrong one would install
// a return path keyed on an Argument nothing ever arrives with.
func TestSidecarGatewayEndpoints_ReadsAdvertisedArgument(t *testing.T) {
	c := newAdvClient(t,
		gatewayAdv("2", testSidecarNode, testSidecarAddr+"/128", 1),
		gatewayAdv("4", testSidecarNode, "fd30:e2e:55d2::1/128", 6),
	)
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("sidecarGatewayEndpoints() returned %d endpoints, want 2: %+v", len(got), got)
	}
	byAddr := map[string]uint16{}
	for _, e := range got {
		byAddr[e.addr.String()] = e.vrfID
	}
	if byAddr[testSidecarAddr] != 1 {
		t.Errorf("endpoint %s vrfID = %d, want the advertised 1", testSidecarAddr, byAddr[testSidecarAddr])
	}
	if byAddr["fd30:e2e:55d2::1"] != 6 {
		t.Errorf("endpoint fd30:e2e:55d2::1 vrfID = %d, want the advertised 6", byAddr["fd30:e2e:55d2::1"])
	}
}

// TestSidecarGatewayEndpoints_IgnoresPodAdvertisements is the isolation this
// feature needs most. A pod's own advertisement is the same shape as a
// sidecar's, and internal/cnibgp has already registered a vrf_table entry
// for it pointing at that pod's real host-netns VRF. Picking one up here
// would overwrite that entry with a table this file owns and break a
// working tenant attachment.
func TestSidecarGatewayEndpoints_IgnoresPodAdvertisements(t *testing.T) {
	c := newAdvClient(t,
		podAdv("2", "0mg", testSidecarNode, "fd20:0:2::3:0:0/128", 1),
		podAdv("2", "eFz", testSidecarNode, "fd20:0:2::2:0:0/128", 1),
	)
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("sidecarGatewayEndpoints() = %+v, want none: pod attachments are not this file's business", got)
	}
}

// TestSidecarGatewayEndpoints_IgnoresOtherNodes covers the fleet case: every
// Envoy node publishes a gateway advertisement for the same VPCs, and all of
// them are visible in this namespace. Installing another node's would point
// this node's return path at an address that lives somewhere else.
func TestSidecarGatewayEndpoints_IgnoresOtherNodes(t *testing.T) {
	c := newAdvClient(t,
		gatewayAdv("2", "eris-giune", "fd30:e2e:af7::1/128", 1),
		gatewayAdv("2", testSidecarNode, testSidecarAddr+"/128", 1),
	)
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v", err)
	}
	if len(got) != 1 || got[0].addr.String() != testSidecarAddr {
		t.Errorf("sidecarGatewayEndpoints() = %+v, want only this node's %s", got, testSidecarAddr)
	}
}

// TestSidecarGatewayEndpoints_SkipsUnusable covers the advertisements that
// exist but cannot be acted on. An advertisement with no VRFID has no
// Argument to key a vrf_table entry on, and a prefix that is not a single
// host route is not something a return path can point at one namespace --
// both must be skipped quietly rather than erroring the whole sweep, since
// the sweep also serves other VPCs.
func TestSidecarGatewayEndpoints_SkipsUnusable(t *testing.T) {
	noVRFID := gatewayAdv("2", testSidecarNode, testSidecarAddr+"/128", 1)
	noVRFID.Spec.VRFID = nil

	subnet := gatewayAdv("4", testSidecarNode, "fd30:e2e:55d2::/64", 6)
	unparseable := gatewayAdv("5", testSidecarNode, "not-a-prefix", 7)

	c := newAdvClient(t, noVRFID, subnet, unparseable)
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("sidecarGatewayEndpoints() = %+v, want none", got)
	}
}

// TestNodeLocatorIdentity_DecodesBlockAndNodeID pins that the Block and
// Node-ID this file keys locator_table/function_table on come out of the
// same prefix ensureLocatorLocalRoute installs, so the two can never
// disagree about which locator this node owns.
func TestNodeLocatorIdentity_DecodesBlockAndNodeID(t *testing.T) {
	c := newRouterClient(t, router(testSidecarNode, testLocator, 6))
	block, nodeID, ok, err := nodeLocatorIdentity(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("nodeLocatorIdentity() error = %v", err)
	}
	if !ok {
		t.Fatal("nodeLocatorIdentity() ok = false, want a configured identity")
	}
	if block != 0x2607ed408002 {
		t.Errorf("block = %#x, want 0x2607ed408002", block)
	}
	if nodeID != 6 {
		t.Errorf("nodeID = %d, want 6", nodeID)
	}
}

// TestNodeLocatorIdentity_AbsentIsNotAnError covers the ordinary bring-up
// state on a node whose BGPRouter has no SRv6 identity yet: it must read as
// "nothing to install", not as a failure, or the installer would warn on
// every tick on a node that simply is not an SRv6 node.
func TestNodeLocatorIdentity_AbsentIsNotAnError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routers []*bgpv1alpha1.BGPRouter
	}{
		{"no routers at all", nil},
		{"no locator configured", []*bgpv1alpha1.BGPRouter{router(testSidecarNode, "", 6)}},
		{"no node id configured", []*bgpv1alpha1.BGPRouter{router(testSidecarNode, testLocator, 0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRouterClient(t, tc.routers...)
			_, _, ok, err := nodeLocatorIdentity(context.Background(), c, testNamespace, testSidecarNode)
			if err != nil {
				t.Fatalf("nodeLocatorIdentity() error = %v, want nil", err)
			}
			if ok {
				t.Error("nodeLocatorIdentity() ok = true, want false with no identity configured")
			}
		})
	}
}

// TestIngressEntryPointAnnotations covers the values that become a route
// and a permanent neighbor for a tenant address. They arrive from another
// component through the API server, so every rejection here is a value that
// must not reach netlink -- a zero or negative ifindex would name no
// interface, and a malformed MAC would be written into the neighbor table.
func TestIngressEntryPointAnnotations(t *testing.T) {
	const mac = "9a:91:c0:8d:83:f1"
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantOK      bool
		wantIfindex int
	}{
		{
			name: "both present",
			annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "24",
				crdnames.AnnotationIngressHostMAC:     mac,
			},
			wantOK: true, wantIfindex: 24,
		},
		// What an advertisement from a sidecar that predates this feature
		// looks like. Must read as "not published yet", not as a failure.
		{name: "nil annotations", annotations: nil, wantOK: false},
		{name: "empty annotations", annotations: map[string]string{}, wantOK: false},
		{
			name:        "ifindex only",
			annotations: map[string]string{crdnames.AnnotationIngressHostIfindex: "24"},
			wantOK:      false,
		},
		{
			name:        "mac only",
			annotations: map[string]string{crdnames.AnnotationIngressHostMAC: mac},
			wantOK:      false,
		},
		{
			name: "zero ifindex names no interface",
			annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "0",
				crdnames.AnnotationIngressHostMAC:     mac,
			},
			wantOK: false,
		},
		{
			name: "negative ifindex",
			annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "-1",
				crdnames.AnnotationIngressHostMAC:     mac,
			},
			wantOK: false,
		},
		{
			name: "unparseable ifindex",
			annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "not-a-number",
				crdnames.AnnotationIngressHostMAC:     mac,
			},
			wantOK: false,
		},
		{
			name: "malformed mac",
			annotations: map[string]string{
				crdnames.AnnotationIngressHostIfindex: "24",
				crdnames.AnnotationIngressHostMAC:     "not-a-mac",
			},
			wantOK: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ifindex, mac, ok := ingressEntryPointAnnotations(tc.annotations)
			if ok != tc.wantOK {
				t.Fatalf("ingressEntryPointAnnotations() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ifindex != tc.wantIfindex {
				t.Errorf("ifindex = %d, want %d", ifindex, tc.wantIfindex)
			}
			if len(mac) != 6 {
				t.Errorf("mac = %v, want a 6-byte hardware address", mac)
			}
		})
	}
}

// TestSidecarGatewayEndpoints_SkipsUnannotated covers the rollout window.
// A sidecar that has not yet republished leaves an advertisement with no
// entry point on it; picking it up would mean guessing an interface, so it
// has to be skipped and retried instead.
func TestSidecarGatewayEndpoints_SkipsUnannotated(t *testing.T) {
	adv := gatewayAdv("2", testSidecarNode, testSidecarAddr+"/128", 1)
	adv.Annotations = nil

	c := newAdvClient(t, adv)
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("sidecarGatewayEndpoints() = %+v, want none until the entry point is published", got)
	}
}

// TestSidecarGatewayEndpoints_CarriesEntryPoint pins that the endpoint the
// install step acts on is the one the sidecar published, since that is the
// only source for it.
func TestSidecarGatewayEndpoints_CarriesEntryPoint(t *testing.T) {
	c := newAdvClient(t, gatewayAdv("2", testSidecarNode, testSidecarAddr+"/128", 1))
	got, err := sidecarGatewayEndpoints(context.Background(), c, testNamespace, testSidecarNode)
	if err != nil {
		t.Fatalf("sidecarGatewayEndpoints() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("sidecarGatewayEndpoints() returned %d endpoints, want 1", len(got))
	}
	if got[0].hostIfindex != 24 {
		t.Errorf("hostIfindex = %d, want the annotated 24", got[0].hostIfindex)
	}
	if got[0].hostMAC.String() != "9a:91:c0:8d:83:f1" {
		t.Errorf("hostMAC = %s, want the annotated 9a:91:c0:8d:83:f1", got[0].hostMAC)
	}
}

// TestEnsureSidecarReturnPath_NoAdvertisementsIsQuiet covers the common case
// on every node that is not running an Envoy pod: with nothing advertised
// the sweep must install nothing and report no error, so it does not warn
// on every tick across the fleet. It still prunes, which on a host with no
// routes in the reserved range finds nothing to do.
func TestEnsureSidecarReturnPath_NoAdvertisementsIsQuiet(t *testing.T) {
	c := newAdvClient(t)
	if err := ensureSidecarReturnPath(
		context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Errorf("ensureSidecarReturnPath() error = %v, want nil", err)
	}
}
