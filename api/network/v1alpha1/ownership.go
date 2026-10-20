// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

// IsLegacyOwned reports whether router belongs to the Galactic EVPN
// implementation: galactic-router, the gateway, NAT, CNI, ingress sidecar,
// installer, garbage collection and the cell status projection. That is
// every router without a routerClassName. A router that names a class
// belongs to that class's controller, and these components ignore it
// entirely, including its deletion, whether or not the class exists.
func IsLegacyOwned(router *BGPRouter) bool {
	return router != nil && router.Spec.RouterClassName == nil
}

// LegacyOwnedRouters returns the routers in routers that IsLegacyOwned
// accepts, in their original order.
func LegacyOwnedRouters(routers []BGPRouter) []BGPRouter {
	out := make([]BGPRouter, 0, len(routers))
	for i := range routers {
		if IsLegacyOwned(&routers[i]) {
			out = append(out, routers[i])
		}
	}
	return out
}
