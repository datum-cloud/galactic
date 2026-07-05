// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hash

import (
	"testing"

	"go.datum.net/galactic/internal/model"
)

// TestDesiredRouter_SRv6SIDChangeAltersHash guards against a regression where
// sortableAdvertisement dropped the SRv6SID field, causing two
// DesiredRouters that differ only in the advertised SID to hash identically.
// That made the BGPRouter reconciler's no-op check (comparing the persisted
// config-hash annotation against the freshly computed hash) skip re-applying
// to GoBGP whenever only the SID changed — e.g. after a pod restart picks up
// a new NAD srv6_sid — leaving stale seg6 encap / EVPN GWIPAddress routes in
// place until something else (like a full pod restart) forced a reapply.
func TestDesiredRouter_SRv6SIDChangeAltersHash(t *testing.T) {
	base := model.DesiredRouter{
		Namespace: "galactic-system",
		Name:      "dfw-worker-tenant",
		LocalASN:  65000,
		RouterID:  "10.0.1.1",
		Advertisements: []model.DesiredAdvertisement{
			{
				Name: "10-10",
				AddressFamily: model.AddressFamily{
					AFI:  "l2vpn",
					SAFI: "evpn",
				},
				Prefixes: []string{"fd00:10:ff01::/80"},
				NextHop:  "fc00:0:8::1",
				SRv6SID:  "2001:db8:ff01::1/128",
			},
		},
	}

	changed := base
	changed.Advertisements = []model.DesiredAdvertisement{base.Advertisements[0]}
	changed.Advertisements[0].SRv6SID = "2001:db8:ff01::99/128"

	baseHash, err := DesiredRouter(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}
	changedHash, err := DesiredRouter(changed)
	if err != nil {
		t.Fatalf("hash changed: %v", err)
	}

	if baseHash == changedHash {
		t.Fatalf("hash did not change when SRv6SID changed: both hashed to %s", baseHash)
	}
}

// TestDesiredRouter_Deterministic verifies that hashing the same value twice
// produces the same result.
func TestDesiredRouter_Deterministic(t *testing.T) {
	r := model.DesiredRouter{
		Namespace: "galactic-system",
		Name:      "dfw-worker-tenant",
		Advertisements: []model.DesiredAdvertisement{
			{Name: "10-10", Prefixes: []string{"fd00:10:ff01::/80"}, SRv6SID: "2001:db8:ff01::1/128"},
		},
	}

	first, err := DesiredRouter(r)
	if err != nil {
		t.Fatalf("hash first: %v", err)
	}
	second, err := DesiredRouter(r)
	if err != nil {
		t.Fatalf("hash second: %v", err)
	}
	if first != second {
		t.Fatalf("hash not deterministic: %s != %s", first, second)
	}
}
