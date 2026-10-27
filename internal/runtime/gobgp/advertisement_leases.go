// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
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
		for key, route := range r.appliedRoutes {
			if route.adv.Name == desired.Name {
				route.adv.ExpiresAt = current.ExpiresAt
				r.appliedRoutes[key] = route
			}
		}
	}
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

func advertisementClaimsRoute(adv model.DesiredAdvertisement, key evpnRouteKey, routerID string) bool {
	if adv.AddressFamily.AFI != afiL2VPN || deriveRD(routerID, adv.VRFID) != key.rd {
		return false
	}
	for _, value := range adv.Prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix == key.prefix {
			return true
		}
	}
	return false
}

// expireAdvertisementLeases only withdraws unclaimed routes, including partial Apply results.
func (r *GoBGPRuntime) expireAdvertisementLeases(b *gobgpserver.BgpServer, now time.Time) error {
	r.advertisementMu.Lock()
	defer r.advertisementMu.Unlock()
	owners := r.advertisementOwners
	if owners == nil {
		owners = r.appliedAdvertisements
	}
	for key, route := range r.appliedRoutes {
		claimed := false
		for _, owner := range owners {
			if !advertisementExpired(owner, now) && advertisementClaimsRoute(owner, key, route.routerID) {
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
