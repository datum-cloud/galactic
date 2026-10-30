// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
)

const advertisementLeaseInterval = time.Second

// RefreshAdvertisementLeases updates live owners without installing routes or reviving expired owners.
func (r *GoBGPRuntime) RefreshAdvertisementLeases(advertisements []model.DesiredAdvertisement) {
	r.advertisementMu.Lock()
	defer r.advertisementMu.Unlock()
	now := time.Now()
	refreshed := make(map[string]time.Time)
	for _, desired := range advertisements {
		current, ok := r.appliedAdvertisements[desired.Name]
		if !ok || (!current.ExpiresAt.IsZero() && !current.ExpiresAt.After(now)) {
			continue
		}
		oldRoute, newRoute := current, desired
		oldRoute.ExpiresAt, newRoute.ExpiresAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(oldRoute, newRoute) {
			continue
		}
		current.ExpiresAt = desired.ExpiresAt
		if !desired.ExpiresAt.IsZero() {
			current.ExpiresAt = now.Add(desired.ExpiresAt.Sub(now))
		}
		r.appliedAdvertisements[desired.Name] = current
		if owner, ok := r.advertisementOwners[desired.Name]; ok &&
			sameEVPNRoute(evpnRoute{adv: owner}, evpnRoute{adv: desired}) {
			r.advertisementOwners[desired.Name] = current
		}
		refreshed[desired.Name] = current.ExpiresAt
	}
	if len(refreshed) == 0 {
		return
	}
	for key, route := range r.appliedRoutes {
		if expiry, ok := refreshed[route.adv.Name]; ok {
			route.adv.ExpiresAt = expiry
			r.appliedRoutes[key] = route
		}
	}
	r.advertisementLeaseExpiry = nextAdvertisementExpiry(r.advertisementOwners)
}

func (r *GoBGPRuntime) runAdvertisementLeases(ctx context.Context) {
	ticker := time.NewTicker(advertisementLeaseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if b := r.server.bgp.Load(); b != nil {
				if err := r.expireAdvertisementLeases(b, now); err != nil {
					slog.Error("withdraw expired advertisement leases", "router", r.key.String(), "error", err)
				}
			}
		}
	}
}

func advertisementExpired(adv model.DesiredAdvertisement, now time.Time) bool {
	return !adv.ExpiresAt.IsZero() && !adv.ExpiresAt.After(now)
}

func nextAdvertisementExpiry(owners map[string]model.DesiredAdvertisement) time.Time {
	var earliest time.Time
	for _, owner := range owners {
		if !owner.ExpiresAt.IsZero() && (earliest.IsZero() || owner.ExpiresAt.Before(earliest)) {
			earliest = owner.ExpiresAt
		}
	}
	return earliest
}

// expireAdvertisementLeases only withdraws unclaimed routes, including partial Apply results.
func (r *GoBGPRuntime) expireAdvertisementLeases(b *gobgpserver.BgpServer, now time.Time) error {
	r.advertisementMu.Lock()
	defer r.advertisementMu.Unlock()
	if !r.advertisementCleanupPending &&
		(r.advertisementLeaseExpiry.IsZero() || r.advertisementLeaseExpiry.After(now)) {
		return nil
	}
	r.advertisementCleanupPending = true
	owners := r.advertisementOwners
	for key, route := range r.appliedRoutes {
		claimed := false
		for _, name := range r.advertisementRouteOwners[key] {
			owner, exists := owners[name]
			if exists && !advertisementExpired(owner, now) {
				route.adv.Name, route.adv.ExpiresAt = owner.Name, owner.ExpiresAt
				r.appliedRoutes[key] = route
				claimed = true
				break
			}
		}
		if claimed {
			continue
		}
		if err := buildEVPNPaths(b, route.adv, route.routerID, true); err != nil {
			return fmt.Errorf("withdraw expired route %s %s: %w", key.rd, key.prefix, err)
		}
		delete(r.appliedRoutes, key)
	}
	for name, adv := range r.appliedAdvertisements {
		owner, wanted := owners[name]
		if !wanted || advertisementExpired(adv, now) || advertisementExpired(owner, now) {
			delete(r.appliedAdvertisements, name)
		}
	}
	for name, adv := range r.advertisementOwners {
		if advertisementExpired(adv, now) {
			delete(r.advertisementOwners, name)
		}
	}
	r.advertisementLeaseExpiry = nextAdvertisementExpiry(owners)
	r.advertisementCleanupPending = false
	return nil
}

func (r *GoBGPRuntime) advertisementStatuses() []model.AdvertisementStatus {
	r.advertisementMu.Lock()
	defer r.advertisementMu.Unlock()
	counts := map[string]int32{}
	for name, adv := range r.appliedAdvertisements {
		counts[name] = int32(len(adv.Prefixes))
	}
	partial := map[string]int32{}
	for _, route := range r.appliedRoutes {
		partial[route.adv.Name]++
	}
	for name, count := range partial {
		counts[name] = max(counts[name], count)
	}
	statuses := make([]model.AdvertisementStatus, 0, len(counts))
	for name, count := range counts {
		statuses = append(statuses, model.AdvertisementStatus{Name: name, AdvertisedPrefixes: count})
	}
	return statuses
}
