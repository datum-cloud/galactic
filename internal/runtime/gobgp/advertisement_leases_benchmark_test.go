// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"fmt"
	"testing"
	"time"

	"go.datum.net/galactic/internal/model"
)

// Benchmark both the common lease-free ticker and a due pass that visits every
// route. Shared live owners avoid BGP calls, isolating bookkeeping scaling.
func BenchmarkAdvertisementLeaseTick(b *testing.B) {
	for _, count := range []int{200, 1000, 3000} {
		for _, due := range []bool{false, true} {
			name := "NoLeases"
			if due {
				name = "DueSharedOwners"
			}
			b.Run(fmt.Sprintf("%s/%d", name, count), func(b *testing.B) {
				now := time.Now()
				advertisements := make([]model.DesiredAdvertisement, 0, count*2)
				for i := range count {
					adv := evpnAdv(fmt.Sprintf("legacy-%04d", i), testSID1, fmt.Sprintf("fd00:%x::/64", i))
					advertisements = append(advertisements, adv)
					if due {
						adv.Name = fmt.Sprintf("leased-%04d", i)
						adv.ExpiresAt = now.Add(-time.Second)
						advertisements = append(advertisements, adv)
					}
				}
				routes, owners, index, err := desiredEVPNRoutes(advertisements, testRouterID1)
				if err != nil {
					b.Fatal(err)
				}
				r := &GoBGPRuntime{appliedRoutes: routes, appliedAdvertisements: owners,
					advertisementOwners: owners, advertisementRouteOwners: index,
					advertisementLeaseExpiry: nextAdvertisementExpiry(owners)}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					// Keep exercising a due traversal after its expired sibling was removed.
					r.advertisementCleanupPending = due
					if err := r.expireAdvertisementLeases(nil, now); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
