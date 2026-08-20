// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// extCommAttr builds a PathAttributeExtendedCommunities attribute from
// route-target strings, mirroring buildEVPNPaths' own construction in
// paths.go.
func extCommAttr(t *testing.T, rts ...string) bgp.PathAttributeInterface {
	t.Helper()
	parsed, err := parseRouteTargets(rts)
	if err != nil {
		t.Fatalf("parseRouteTargets(%v): %v", rts, err)
	}
	return bgp.NewPathAttributeExtendedCommunities(parsed)
}

// TestMatchTableID_VRFScopedPath covers the pre-existing behavior: a path
// carrying a Route Target this node has a configured VRF for resolves to
// that VRF's table, tagged for RouteEgressAdd's SEG6 encap (plain=false).
func TestMatchTableID_VRFScopedPath(t *testing.T) {
	r := &GoBGPRuntime{rtIndex: map[string]uint32{testRT100: 42}}

	got, ok := r.matchTableID([]bgp.PathAttributeInterface{extCommAttr(t, testRT100)})
	if !ok {
		t.Fatalf("matchTableID() ok = false, want true (RT %s is configured)", testRT100)
	}
	if got.tableID != 42 {
		t.Errorf("tableID = %d, want 42", got.tableID)
	}
	if got.plain {
		t.Errorf("plain = true, want false (VRF-scoped path must use RouteEgressAdd's SEG6 encap)")
	}
}

// TestMatchTableID_UnknownVRFSkipped covers a path carrying Route Targets,
// none of which match any VRF configured on this node: it must be skipped
// entirely (ok=false), not installed into main by accident -- the whole
// reason matchTableID gates the RT-less case on the *absence* of any RT,
// not merely a lookup miss.
func TestMatchTableID_UnknownVRFSkipped(t *testing.T) {
	r := &GoBGPRuntime{rtIndex: map[string]uint32{testRT100: 42}}

	_, ok := r.matchTableID([]bgp.PathAttributeInterface{extCommAttr(t, testRT200)})
	if ok {
		t.Errorf("matchTableID() ok = true, want false (RT %s matches no configured VRF)", testRT200)
	}
}

// TestMatchTableID_RTLessPathUsesMainTable covers the fix: a path with no
// Route Target extended community at all -- e.g. NetworkGatewayReconciler's
// anycast ingress-VIP advertisements (buildEVPNPaths never attaches the
// attribute when adv.Communities is empty) -- must resolve to the main
// table (0) via RouteMainAdd's plain routing (plain=true), not be silently
// dropped. This is the exact bug found live in containerlab: an ns60
// NetworkRule's VIP BGPAdvertisement reported Advertised/Ready, but no
// receiving node anywhere in the mesh ever installed a route for it.
func TestMatchTableID_RTLessPathUsesMainTable(t *testing.T) {
	r := &GoBGPRuntime{rtIndex: map[string]uint32{testRT100: 42}}

	got, ok := r.matchTableID(nil)
	if !ok {
		t.Fatalf("matchTableID(nil attrs) ok = false, want true (no RT at all must resolve to main table)")
	}
	if !got.plain {
		t.Errorf("plain = false, want true (RT-less path must use RouteMainAdd, not SEG6 encap)")
	}
	if got.tableID != 0 {
		t.Errorf("tableID = %d, want 0 (main table)", got.tableID)
	}
}

// TestMatchTableID_NoExtendedCommunitiesAttributeAtAll covers the same
// RT-less case as TestMatchTableID_RTLessPathUsesMainTable, but via attrs
// containing other, unrelated path attributes rather than none at all --
// the realistic shape of an actual EVPN path (which always carries Origin
// and MpReachNLRI, see buildEVPNPaths).
func TestMatchTableID_NoExtendedCommunitiesAttributeAtAll(t *testing.T) {
	r := &GoBGPRuntime{rtIndex: map[string]uint32{testRT100: 42}}

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	}
	got, ok := r.matchTableID(attrs)
	if !ok {
		t.Fatalf("matchTableID() ok = false, want true")
	}
	if !got.plain || got.tableID != 0 {
		t.Errorf("routeInstall = %+v, want {tableID:0 plain:true}", got)
	}
}
