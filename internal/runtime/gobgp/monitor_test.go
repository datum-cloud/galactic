// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"math"
	"strings"
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

// TestVRFTableID_DecodesHexSegmentBackToBase62 is a regression test for the
// bug documented in the "vrfTableID hex/base62 mismatch" note: the CRD name
// carries the VPC hex-encoded (crdnames.BGPVRFInstanceName/VPCSegment), but
// the kernel VRF interface is named from the raw base62 VPC
// (intf.GenerateInterfaceNameVRF). Feeding the hex segment straight into
// vrfpkg.TableID built the wrong interface name entirely — "3e" (hex for
// base62 "10") looked up "G00000003eV" instead of the real "G000000010V".
// There's no VRF interface in the test sandbox for either name, so this
// asserts on the interface name vrfpkg.TableID reports missing rather than
// on a successful lookup.
func TestVRFTableID_DecodesHexSegmentBackToBase62(t *testing.T) {
	_, err := vrfTableID("3e-dfw-worker", 1)
	if err == nil {
		t.Fatalf("vrfTableID() error = nil, want a 'VRF ID not found' error (no such kernel VRF in test env)")
	}
	if !strings.Contains(err.Error(), "G000000010V") {
		t.Errorf("vrfTableID() error = %q, want it to reference the base62-decoded interface name G000000010V", err)
	}
	if strings.Contains(err.Error(), "G00000003eV") {
		t.Errorf("vrfTableID() error = %q, looked up the raw hex segment as an interface name instead of decoding it", err)
	}
}

// TestVRFTableID_HashFallbackSegmentErrors covers the SHA-256 hash fallback
// form (crdnames.nameSegment's "x..." prefix, used for VPCs that don't
// cleanly hex-encode) — intf.HexToBase62 can't decode it back to a real
// interface name, so vrfTableID must fail fast on the decode rather than
// attempt a kernel lookup with a garbage name.
func TestVRFTableID_HashFallbackSegmentErrors(t *testing.T) {
	_, err := vrfTableID("x0123456789ab-dfw-worker", 1)
	if err == nil {
		t.Fatalf("vrfTableID() error = nil, want a base62-decode error for a hash-fallback segment")
	}
}

// TestVRFTableID_NoDashErrors covers the pre-existing malformed-input guard:
// a VRF name with no '-' at all can't be split into a VPC segment and a
// node name.
func TestVRFTableID_NoDashErrors(t *testing.T) {
	_, err := vrfTableID("nodash", 1)
	if err == nil {
		t.Fatalf("vrfTableID(\"nodash\") error = nil, want a \"does not contain '-'\" error")
	}
}

// TestVRFTableID_FallbackErrorMentionsBothAttempts covers the case this
// fallback exists for: a VRF whose interface genuinely does not exist in
// this process's own root netns (galactic-router's normal case for a VRF
// #855's ingress sidecar created instead, inside Envoy's own pod netns —
// see vrfTableID's own doc comment). With no bpffs mount in this test
// environment either, both attempts fail, and the combined error must
// still surface the original local-netlink failure (mentioning the
// base62-decoded interface name), not just the fallback's own error, so
// an operator reading the log doesn't lose the first, usually more
// familiar signal.
func TestVRFTableID_FallbackErrorMentionsBothAttempts(t *testing.T) {
	_, err := vrfTableID("3e-dfw-worker", 7)
	if err == nil {
		t.Fatal("vrfTableID() error = nil, want an error (no kernel VRF and no pinned vrf_table in the test env)")
	}
	if !strings.Contains(err.Error(), "G000000010V") {
		t.Errorf("vrfTableID() error = %q, want it to still mention the local netlink failure", err)
	}
	if !strings.Contains(err.Error(), "vrf_table") {
		t.Errorf("vrfTableID() error = %q, want it to also mention the vrf_table fallback attempt", err)
	}
}

// TestVRFTableIDFromRegistry_RejectsOutOfRangeArgument covers the bounds
// check on argument: model.DesiredVRFInstance.VRFID is an int32 (RFC 4364
// route-distinguisher assignment compatibility), but a uSID Argument is
// only ever 16 bits (uformat.ValidateArgument) — this must reject a value
// that can't round-trip through uint16 before ever touching a pinned map,
// rather than silently truncating it into a lookup for the wrong key.
func TestVRFTableIDFromRegistry_RejectsOutOfRangeArgument(t *testing.T) {
	for _, argument := range []int32{-1, math.MaxUint16 + 1} {
		if _, _, err := vrfTableIDFromRegistry("2", argument); err == nil {
			t.Errorf("vrfTableIDFromRegistry(%d) error = nil, want an out-of-range error", argument)
		}
	}
}

// TestVRFTableIDFromRegistry_MissingPinReturnsError covers the "eBPF uSID
// datapath not loaded on this node" case (a route-reflector/control-role
// node, or simply not yet attached) — pinDir points at this test's own
// temp directory instead of a real bpffs mount, so OpenPinnedRegistry's
// own open() calls fail exactly as they would against a genuinely absent
// pin, with no real bpffs mount or root privilege needed to exercise it.
func TestVRFTableIDFromRegistry_MissingPinReturnsError(t *testing.T) {
	old := pinDir
	pinDir = t.TempDir()
	t.Cleanup(func() { pinDir = old })

	_, _, err := vrfTableIDFromRegistry("2", 1)
	if err == nil {
		t.Fatal("vrfTableIDFromRegistry() error = nil, want an error opening a non-existent pinned map")
	}
	if !strings.Contains(err.Error(), "vrf_table") {
		t.Errorf("vrfTableIDFromRegistry() error = %q, want it to name vrf_table", err)
	}
}
