// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

const (
	testSharedPrefix = "fd00:10:ff01::/80"
	testOtherPrefix  = "fd00:10:ff02::/80"
)

func evpnAdv(name, sid string, prefixes ...string) model.DesiredAdvertisement {
	return model.DesiredAdvertisement{
		Name:          name,
		AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes:      prefixes,
		NextHop:       testNextHop,
		SRv6SID:       sid,
		VRFID:         ptrInt32Test(7),
		Communities:   []string{testRT100},
	}
}

// localEVPNPaths returns the SRv6 SID of every local EVPN path in b, keyed by
// prefix, failing the test if any prefix holds more than one path.
func localEVPNPaths(t *testing.T, b interface {
	ListPath(apiutil.ListPathRequest, func(bgp.NLRI, []*apiutil.Path)) error
}) map[string]string {
	t.Helper()
	got := make(map[string]string)
	err := b.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_EVPN,
	}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, path := range paths {
			evpn, ok := path.Nlri.(*bgp.EVPNNLRI)
			if !ok {
				continue
			}
			route, ok := evpn.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
			if !ok {
				continue
			}
			prefix := fmt.Sprintf("%s/%d", route.IPPrefix, route.IPPrefixLength)
			if _, dup := got[prefix]; dup {
				t.Errorf("prefix %s holds more than one local path", prefix)
			}
			sid, _ := evpnPrefixSID(path.Attrs)
			got[prefix] = sid.String()
		}
	})
	if err != nil {
		t.Fatalf("ListPath() error = %v", err)
	}
	return got
}

func TestApplyEVPNWithdrawsOnlyUnclaimedRoutes(t *testing.T) {
	oldAdv := evpnAdv("attachment-old", testSID1, testSharedPrefix)
	newAdv := evpnAdv("attachment-new", testSID1, testSharedPrefix)
	first := evpnAdv("a-first", testSID1, testSharedPrefix)
	second := evpnAdv("b-second", testSID2, testSharedPrefix)
	moved := evpnAdv("a-first", testSID1, testOtherPrefix)

	shared := map[string]string{testSharedPrefix: testSID1}
	none := map[string]string{}

	type step struct {
		advs []model.DesiredAdvertisement
		want map[string]string
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "RecreatedBeforeOldReaped",
			steps: []step{
				{[]model.DesiredAdvertisement{oldAdv}, shared},
				{[]model.DesiredAdvertisement{oldAdv, newAdv}, shared},
				{[]model.DesiredAdvertisement{newAdv}, shared},
			},
		},
		{
			name: "OldReapedBeforeRecreate",
			steps: []step{
				{[]model.DesiredAdvertisement{oldAdv}, shared},
				{nil, none},
				{[]model.DesiredAdvertisement{newAdv}, shared},
			},
		},
		{
			name: "ReplacedInOneApply",
			steps: []step{
				{[]model.DesiredAdvertisement{oldAdv}, shared},
				{[]model.DesiredAdvertisement{newAdv}, shared},
			},
		},
		{
			name: "PrefixMovesOffSharedRoute",
			steps: []step{
				{[]model.DesiredAdvertisement{first, second}, shared},
				{
					[]model.DesiredAdvertisement{moved, second},
					map[string]string{testSharedPrefix: testSID2, testOtherPrefix: testSID1},
				},
				{[]model.DesiredAdvertisement{moved}, map[string]string{testOtherPrefix: testSID1}},
			},
		},
		{
			name: "LastClaimantRemoved",
			steps: []step{
				{[]model.DesiredAdvertisement{oldAdv, newAdv}, shared},
				{[]model.DesiredAdvertisement{newAdv}, shared},
				{nil, none},
			},
		},
		{
			name: "ConflictingAttributesResolveByName",
			steps: []step{
				{[]model.DesiredAdvertisement{second, first}, shared},
				{[]model.DesiredAdvertisement{first, second}, shared},
				{[]model.DesiredAdvertisement{second}, map[string]string{testSharedPrefix: testSID2}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBgpServer(t)
			rr, err := NewRuntimeFactory(-1, false, "", nil)(types.NamespacedName{Name: "test"})
			if err != nil {
				t.Fatalf("new runtime: %v", err)
			}
			r, ok := rr.(*GoBGPRuntime)
			if !ok {
				t.Fatalf("runtime is %T, want *GoBGPRuntime", rr)
			}

			for i, s := range tt.steps {
				if err := r.applyEVPN(b, s.advs, testRouterID1); err != nil {
					t.Fatalf("step %d: applyEVPN() error = %v", i, err)
				}
				if got := localEVPNPaths(t, b); !maps.Equal(got, s.want) {
					t.Fatalf("step %d: local EVPN paths = %v, want %v", i, got, s.want)
				}
				if got, want := slices.Sorted(maps.Keys(r.appliedAdvertisements)), advNames(s.advs); !slices.Equal(got, want) {
					t.Errorf("step %d: applied advertisements = %v, want %v", i, got, want)
				}
			}
		})
	}
}

func advNames(advs []model.DesiredAdvertisement) []string {
	names := make([]string, 0, len(advs))
	for _, adv := range advs {
		names = append(names, adv.Name)
	}
	slices.Sort(names)
	return names
}
