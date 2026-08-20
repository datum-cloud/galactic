// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"go.datum.net/galactic/internal/model"
)

// TestAnycastSpike_TwoGatewayNodesSamePrefixSurviveIndependently is a
// go/no-go spike for the DSR/Maglev redesign's anycast premise (every
// gateway node advertises the same VIP prefix at equal preference — see the
// kitt design doc's §0). The specific risk under test: an earlier, rejected
// design (docs referenced: `~/.claude/datum/plans/merry-percolating-tulip.md`
// §4) avoided colocating the gateway in a tenant VRF specifically to sidestep
// two named GoBGP issues — monitor.go's processEVPNPath skipping local paths
// before RT match, and rtIndex being 1:1 not fan-out. Reading those two
// functions directly (see monitor.go) shows both are scoped to advertisements
// that carry a VRFID/Function (tenant-VRF SEG6 kernel-route installation) —
// a gateway VIP/self-address advertisement carries neither (see
// publishSelfAddress's doc comment), so it never reaches that code path at
// all. Those two issues are real but irrelevant to this design.
//
// What actually determines whether two gateway nodes' identical-VIP-prefix
// advertisements coexist is buildEVPNPaths' RD derivation (paths.go's
// deriveRD): when DesiredAdvertisement.VRFID is nil (true for a
// VRFID/Function-less advertisement), the RD falls back to "routerID:0" —
// different per originating router. RFC 4364 §4.3.2 (and EVPN's identical
// convention) says PE routers never compare routes for the same prefix
// carrying different RDs — they're definitionally different routes, not
// best-path competitors. This test proves gobgp v4, as actually driven by
// this codebase's real buildEVPNPaths function (not a reimplementation),
// honors that: two paths for the identical prefix, originated with two
// different router IDs (simulating two gateway nodes), both survive as
// independent RIB entries rather than one silently replacing the other.
func TestAnycastSpike_TwoGatewayNodesSamePrefixSurviveIndependently(t *testing.T) {
	b := newTestBgpServer(t)

	const vipPrefix = "203.0.113.5/32"

	gw1 := model.DesiredAdvertisement{
		Name:          "gw1-selfaddr",
		AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes:      []string{vipPrefix},
		NextHop:       "2001:db8::1",
		// VRFID intentionally nil: this is the exact shape
		// NetworkGatewayReconciler.publishSelfAddress produces for a VIP/
		// self-address advertisement — no VRFID/Function, per its own doc
		// comment ("carries no VRFID/Function... not reached via a per-tenant
		// VRF decap at all").
	}
	gw2 := model.DesiredAdvertisement{
		Name:          "gw2-selfaddr",
		AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes:      []string{vipPrefix},
		NextHop:       "2001:db8::2",
	}

	// Two distinct router IDs, simulating two distinct gateway nodes each
	// applying their own advertisement locally — buildEVPNPaths is exactly
	// the function galactic-gateway's own applyEVPN call already uses.
	if err := buildEVPNPaths(b, gw1, "1.1.1.1", false); err != nil {
		t.Fatalf("buildEVPNPaths(gw1): %v", err)
	}
	if err := buildEVPNPaths(b, gw2, "1.1.1.2", false); err != nil {
		t.Fatalf("buildEVPNPaths(gw2): %v", err)
	}

	type observed struct {
		rd      string
		nextHop string
		best    bool
	}
	collect := func() []observed {
		var got []observed
		listErr := b.ListPath(apiutil.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL,
			Family:    bgp.RF_EVPN,
		}, func(_ bgp.NLRI, paths []*apiutil.Path) {
			for _, path := range paths {
				evpnNLRI, ok := path.Nlri.(*bgp.EVPNNLRI)
				if !ok {
					continue
				}
				ipPrefix, ok := evpnNLRI.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
				if !ok {
					continue
				}
				if ipPrefix.IPPrefixLength != 32 || ipPrefix.IPPrefix.String() != "203.0.113.5" {
					continue
				}
				got = append(got, observed{
					rd:      evpnNLRI.RD().String(),
					nextHop: evpnMpReachNexthop(path.Attrs),
					best:    path.Best,
				})
			}
		})
		if listErr != nil {
			t.Fatalf("ListPath: %v", listErr)
		}
		return got
	}

	got := collect()

	if len(got) != 2 {
		t.Fatalf("got %d paths for %s, want 2 (one per gateway node) — got %+v", len(got), vipPrefix, got)
	}

	rds := map[string]bool{}
	nextHops := map[string]bool{}
	for _, o := range got {
		rds[o.rd] = true
		nextHops[o.nextHop] = true
		if !o.best {
			t.Errorf("path %+v not marked Best — a non-competing (distinct-RD) route should never be "+
				"suppressed by best-path selection", o)
		}
	}
	if len(rds) != 2 {
		t.Errorf("expected 2 distinct route distinguishers (one per router ID), got %d: %+v", len(rds), got)
	}
	if len(nextHops) != 2 {
		t.Errorf("expected 2 distinct next-hops (one per gateway node), got %d: %+v", len(nextHops), got)
	}

	// Withdrawing one gateway node's path must not disturb the other's —
	// the property that matters for "a gateway node goes down, the other
	// keeps serving the VIP, unaffected."
	if err := buildEVPNPaths(b, gw1, "1.1.1.1", true); err != nil {
		t.Fatalf("withdraw gw1: %v", err)
	}

	got = collect()
	if len(got) != 1 {
		t.Fatalf("after withdrawing gw1, got %d paths, want 1 (gw2's own, untouched) — got %+v", len(got), got)
	}
	if got[0].nextHop != "2001:db8::2" {
		t.Errorf("surviving path next-hop = %q, want gw2's own (2001:db8::2) — gw1's withdrawal must not "+
			"have touched gw2's independent route", got[0].nextHop)
	}
}

// TestAnycastSpike_SameRouterIDCollapsesToOnePath is the negative control
// for the spike above: it proves the test methodology actually discriminates
// between "independent routes" and "one replaces the other," rather than
// the previous test passing by accident (e.g. a bug in the collection
// helper that always reports 2 regardless of what gobgp actually did). Two
// advertisements for the identical prefix under the identical router ID
// share the identical RD ("routerID:0" both times) — the identical NLRI —
// so the second AddPath call must update the existing route, not create a
// second one. If this test failed (saw 2 paths), the spike above would not
// be trustworthy evidence of anything.
func TestAnycastSpike_SameRouterIDCollapsesToOnePath(t *testing.T) {
	b := newTestBgpServer(t)
	const vipPrefix = "203.0.113.5/32"

	first := model.DesiredAdvertisement{
		Name: "adv", AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes: []string{vipPrefix}, NextHop: "2001:db8::1",
	}
	second := model.DesiredAdvertisement{
		Name: "adv", AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes: []string{vipPrefix}, NextHop: "2001:db8::9", // different next-hop, same RD
	}

	if err := buildEVPNPaths(b, first, "1.1.1.1", false); err != nil {
		t.Fatalf("buildEVPNPaths(first): %v", err)
	}
	if err := buildEVPNPaths(b, second, "1.1.1.1", false); err != nil { // same router ID as first
		t.Fatalf("buildEVPNPaths(second): %v", err)
	}

	var count int
	var lastNextHop string
	listErr := b.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_EVPN,
	}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, path := range paths {
			evpnNLRI, ok := path.Nlri.(*bgp.EVPNNLRI)
			if !ok {
				continue
			}
			ipPrefix, ok := evpnNLRI.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
			if !ok || ipPrefix.IPPrefixLength != 32 || ipPrefix.IPPrefix.String() != "203.0.113.5" {
				continue
			}
			count++
			lastNextHop = evpnMpReachNexthop(path.Attrs)
		}
	})
	if listErr != nil {
		t.Fatalf("ListPath: %v", listErr)
	}
	if count != 1 {
		t.Fatalf("got %d paths for the identical RD, want 1 (second must replace first, not coexist) — "+
			"if this fails, TestAnycastSpike_TwoGatewayNodesSamePrefixSurviveIndependently's "+
			"2-paths result is not meaningful evidence of anything", count)
	}
	if lastNextHop != "2001:db8::9" {
		t.Errorf("surviving path next-hop = %q, want %q (the second, more recent advertisement)",
			lastNextHop, "2001:db8::9")
	}
}
