// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"sync"
	"time"
)

// uplinkIndexCacheTTL bounds how long UplinkIndexes serves an already-resolved
// set before resolving again. Callers hit it once per egress route write, and
// a node converging a full EVPN RIB writes thousands in a burst, so resolving
// per call would turn every burst into a storm of route and link dumps. The
// window is short enough that an interface appearing or moving is picked up
// well inside BGP's own convergence time.
//
// A var, not a const, so tests can shrink or disable it.
var uplinkIndexCacheTTL = 15 * time.Second

// uplinkIndexNow is time.Now, overridable so cache-expiry tests need no sleep.
var uplinkIndexNow = time.Now

var uplinkIndexCache struct {
	mu       sync.Mutex
	indexes  map[int]struct{}
	resolved time.Time
}

// UplinkIndexes returns the ifindexes of the interfaces the SRv6 datapath
// attaches to, the set ResolveInterfaces names.
//
// It exists so a caller resolving where to send an encapsulated packet can
// reject a route that leaves through some other interface. A node's management
// NIC almost always carries an IPv6 default route, so an ordinary route lookup
// for a SID the fabric has not advertised yet does not fail -- it silently
// resolves through management. Writing that result into the datapath produces
// a correctly encapsulated packet handed to a network that has never heard of
// the destination locator, which is indistinguishable from a blackhole at both
// ends.
//
// Names are resolved to indexes here rather than compared as strings because
// that is what both netlink route results and the datapath's own entries carry,
// and an index cannot go stale in the way a renamed interface's name can.
//
// An interface in the resolved set that no longer exists is skipped rather than
// failing the call: ResolveInterfaces may legitimately name an interface that
// has since gone away, and the remaining ones are still usable. An empty result
// is an error, since accepting every route is exactly the behavior this guards
// against.
func UplinkIndexes() (map[int]struct{}, error) {
	uplinkIndexCache.mu.Lock()
	defer uplinkIndexCache.mu.Unlock()

	if uplinkIndexCache.indexes != nil &&
		uplinkIndexNow().Sub(uplinkIndexCache.resolved) < uplinkIndexCacheTTL {
		return uplinkIndexCache.indexes, nil
	}

	names, err := ResolveInterfaces()
	if err != nil {
		return nil, fmt.Errorf("attach: resolve SRv6 uplink interfaces: %w", err)
	}

	indexes := make(map[int]struct{}, len(names))
	for _, name := range names {
		link, err := linkByNameFn(name)
		if err != nil {
			continue
		}
		indexes[link.Attrs().Index] = struct{}{}
	}
	if len(indexes) == 0 {
		return nil, fmt.Errorf("attach: none of the %d resolved SRv6 uplink interfaces exist on this host: %v",
			len(names), names)
	}

	uplinkIndexCache.indexes = indexes
	uplinkIndexCache.resolved = uplinkIndexNow()
	return indexes, nil
}

// InvalidateUplinkIndexes drops the cached uplink set so the next UplinkIndexes
// call resolves again. The watch loop calls it when the attachment set changes,
// so a newly attached interface is accepted as an egress link immediately
// rather than after the TTL.
func InvalidateUplinkIndexes() {
	uplinkIndexCache.mu.Lock()
	defer uplinkIndexCache.mu.Unlock()
	uplinkIndexCache.indexes = nil
}
