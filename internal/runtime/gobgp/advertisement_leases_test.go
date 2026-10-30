// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"maps"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

func leaseTestRuntime(t *testing.T) *GoBGPRuntime {
	t.Helper()
	rt, err := NewRuntimeFactory(-1, false, "", nil, BMPConfig{})(types.NamespacedName{Name: "lease-test"})
	if err != nil {
		t.Fatal(err)
	}
	return rt.(*GoBGPRuntime)
}

func TestAdvertisementLeaseOwnerReplacementAndPartialApply(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "PathEqualReplacement", true: "FailedApply"}[partial], func(t *testing.T) {
			b := newTestBgpServer(t)
			r := leaseTestRuntime(t)
			legacy := evpnAdv("legacy", testSID1, testSharedPrefix)
			if err := r.applyEVPN(b, []model.DesiredAdvertisement{legacy}, testRouterID1); err != nil {
				t.Fatal(err)
			}
			leased := legacy
			leased.Name = "leased"
			leased.ExpiresAt = time.Now().Add(time.Minute)
			desired := []model.DesiredAdvertisement{leased}
			if partial {
				desired = append(desired, evpnAdv("invalid", "not-a-sid", testOtherPrefix))
			}
			err := r.applyEVPN(b, desired, testRouterID1)
			if (err != nil) != partial {
				t.Fatalf("apply error=%v partial=%t", err, partial)
			}
			if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if paths := localEVPNPaths(t, b); len(paths) != 0 {
				t.Fatalf("expired replacement retained paths: %v", paths)
			}
		})
	}
}

func TestAdvertisementLeasePreservesLegacySiblingAndDoesNotResurrect(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	leased := evpnAdv("a-leased", testSID1, testSharedPrefix, testOtherPrefix)
	leased.ExpiresAt = time.Now().Add(time.Minute)
	legacy := evpnAdv("b-legacy", testSID1, testSharedPrefix)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{leased, legacy}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if paths := localEVPNPaths(t, b); !maps.Equal(paths, map[string]string{testSharedPrefix: testSID1}) {
		t.Fatalf("legacy sibling changed: %v", paths)
	}
	leased.ExpiresAt = time.Now().Add(5 * time.Minute)
	r.RefreshAdvertisementLeases([]model.DesiredAdvertisement{leased})
	if _, exists := r.appliedAdvertisements[leased.Name]; exists {
		t.Fatal("refresh resurrected expired owner")
	}
	if paths := localEVPNPaths(t, b); len(paths) != 1 {
		t.Fatal("refresh added a route")
	}
}

func TestAdvertisementLeaseTimerIndependentOfRouterApply(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	r.server.bgp.Store(b)
	adv := evpnAdv("leased", testSID1, testSharedPrefix)
	adv.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{adv}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.runAdvertisementLeases(ctx) }()
	defer func() { cancel(); <-done }()
	r.mu.Lock()
	defer r.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(localEVPNPaths(t, b)) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("lease timer waited for full router reconciliation lock")
}

func TestAdvertisementLeaseArmsLegacyOwnerWithoutRouteChange(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	legacy := evpnAdv("same-owner", testSID1, testSharedPrefix)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{legacy}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	leased := legacy
	leased.ExpiresAt = time.Now().Add(time.Minute)
	r.RefreshAdvertisementLeases([]model.DesiredAdvertisement{leased})
	if len(localEVPNPaths(t, b)) != 1 {
		t.Fatal("lease attachment flapped route")
	}
	if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(localEVPNPaths(t, b)) != 0 {
		t.Fatal("lease attachment left immortal legacy route")
	}
}

func TestAdvertisementLeaseClearsOnlyLiveOwner(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	leased := evpnAdv("same-owner", testSID1, testSharedPrefix)
	leased.ExpiresAt = time.Now().Add(time.Minute)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{leased}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	legacy := leased
	legacy.ExpiresAt = time.Time{}
	r.RefreshAdvertisementLeases([]model.DesiredAdvertisement{legacy})
	if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(localEVPNPaths(t, b)) != 1 {
		t.Fatal("removed lease withdrew unleased owner")
	}
}

func TestAdvertisementStatusIncludesPartialInstalledOwner(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	adv := evpnAdv("partial", testSID1, testSharedPrefix)
	adv.ExpiresAt = time.Now().Add(time.Minute)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{adv}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	r.appliedAdvertisements = nil
	statuses := r.advertisementStatuses()
	if len(statuses) != 1 || statuses[0].Name != adv.Name || statuses[0].AdvertisedPrefixes != 1 {
		t.Fatalf("partial owner omitted: %+v", statuses)
	}
	if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(r.advertisementStatuses()) != 0 {
		t.Fatal("withdrawn partial owner retained")
	}
}

// Failed Apply can leave an unclaimed route even with no leases. The idle fast
// path must not suppress its retry once the routing error clears.
func TestAdvertisementLeaseRetriesUnleasedPartialWithdrawal(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	adv := evpnAdv("legacy", testSID1, testSharedPrefix)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{adv}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	var key evpnRouteKey
	var installed evpnRoute
	for key, installed = range r.appliedRoutes {
		break
	}
	broken := installed
	broken.adv.NextHop = "invalid-next-hop"
	r.appliedRoutes[key] = broken
	if err := r.applyEVPN(b, nil, testRouterID1); err == nil {
		t.Fatal("invalid withdrawal unexpectedly succeeded")
	}
	if err := r.expireAdvertisementLeases(b, time.Now()); err == nil {
		t.Fatal("failed withdrawal was not retried")
	}
	r.appliedRoutes[key] = installed
	if err := r.expireAdvertisementLeases(b, time.Now()); err != nil {
		t.Fatal(err)
	}
	if paths := localEVPNPaths(t, b); len(paths) != 0 {
		t.Fatalf("unclaimed legacy route retained: %v", paths)
	}
	if len(r.advertisementStatuses()) != 0 {
		t.Fatal("withdrawn owner retained in status")
	}
}

func TestAdvertisementLeaseFailedWithdrawalCannotBeRevived(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	adv := evpnAdv("leased", testSID1, testSharedPrefix)
	adv.ExpiresAt = time.Now().Add(time.Minute)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{adv}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	// Move this live owner's deadline into the past through the supported refresh
	// path, then inject a failure while withdrawing the installed route.
	adv.ExpiresAt = time.Now().Add(-time.Second)
	r.RefreshAdvertisementLeases([]model.DesiredAdvertisement{adv})
	var key evpnRouteKey
	var installed evpnRoute
	for key, installed = range r.appliedRoutes {
		break
	}
	broken := installed
	broken.adv.NextHop = "invalid-next-hop"
	r.appliedRoutes[key] = broken
	if err := r.expireAdvertisementLeases(b, time.Now()); err == nil {
		t.Fatal("invalid withdrawal unexpectedly succeeded")
	}
	adv.ExpiresAt = time.Now().Add(time.Hour)
	r.RefreshAdvertisementLeases([]model.DesiredAdvertisement{adv})
	if !advertisementExpired(r.advertisementOwners[adv.Name], time.Now()) {
		t.Fatal("refresh revived expired owner")
	}
	r.appliedRoutes[key] = installed
	if err := r.expireAdvertisementLeases(b, time.Now()); err != nil {
		t.Fatal(err)
	}
	if paths := localEVPNPaths(t, b); len(paths) != 0 {
		t.Fatalf("expired route retained after retry: %v", paths)
	}
}

func TestAdvertisementLeaseIndexKeepsDistinctVRFOwnership(t *testing.T) {
	b := newTestBgpServer(t)
	r := leaseTestRuntime(t)
	leased := evpnAdv("leased", testSID1, testSharedPrefix)
	leased.ExpiresAt = time.Now().Add(time.Minute)
	legacy := leased
	legacy.Name, legacy.ExpiresAt, legacy.VRFID = "legacy", time.Time{}, ptrInt32Test(8)
	if err := r.applyEVPN(b, []model.DesiredAdvertisement{leased, legacy}, testRouterID1); err != nil {
		t.Fatal(err)
	}
	if err := r.expireAdvertisementLeases(b, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(r.appliedRoutes) != 1 {
		t.Fatalf("routes=%d want only legacy VRF", len(r.appliedRoutes))
	}
	for key, route := range r.appliedRoutes {
		if key.rd != deriveRD(testRouterID1, legacy.VRFID) || route.adv.Name != legacy.Name {
			t.Fatalf("wrong survivor: %+v", route)
		}
	}
	if err := r.expireAdvertisementLeases(b, time.Now().Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(r.appliedRoutes) != 1 {
		t.Fatal("idle pass withdrew legacy survivor")
	}
}
