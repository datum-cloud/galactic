// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"net"
	"slices"
	"testing"
)

func TestMergeRouteInventory(t *testing.T) {
	owned := mustPrefix(t, "fd00::1")
	lost := mustPrefix(t, "fd00::2")   // redirect route, map entry gone
	legacy := mustPrefix(t, "fd00::3") // pre-map seg6 route
	sid := net.ParseIP("fd00:99::1")
	mapPrefixes := map[string]struct{}{
		owned.String():  {},
		"fd00::9/128":   {}, // a sibling pod's, or one whose redirect was lost
		legacy.String(): {},
	}
	lookups := 0
	routes, unowned, err := mergeRouteInventory(
		[]*net.IPNet{owned, lost, owned},
		[]RouteInfo{{Prefix: legacy, SID: net.ParseIP("fd00:99::3")}, {Prefix: owned, SID: net.ParseIP("fd00:99::7")}},
		mapPrefixes,
		func(p *net.IPNet) (net.IP, bool, error) {
			lookups++
			if p.String() != owned.String() {
				t.Errorf("looked up %s, which has no redirect route or no map entry", p)
			}
			return sid, true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[r.Prefix.String()] = r.SID.String()
	}
	want := map[string]string{
		owned.String():  sid.String(),
		lost.String():   net.IP(nil).String(),
		legacy.String(): "fd00:99::3",
	}
	if len(routes) != len(want) {
		t.Errorf("routes %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("route %s SID %q, want %q", k, got[k], v)
		}
	}
	if !slices.Equal(unowned, []string{"fd00::9/128"}) {
		t.Errorf("unowned %v, want only the entry with no redirect route", unowned)
	}
	if lookups != 1 {
		t.Errorf("%d lookups, want 1", lookups)
	}
}

func TestMergeRouteInventoryLookupError(t *testing.T) {
	p := mustPrefix(t, "fd00::1")
	_, _, err := mergeRouteInventory([]*net.IPNet{p}, nil, map[string]struct{}{p.String(): {}},
		func(*net.IPNet) (net.IP, bool, error) { return nil, false, errTest })
	if err == nil {
		t.Error("a failed map read was not reported")
	}
}
