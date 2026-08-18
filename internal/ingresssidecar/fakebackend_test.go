// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"net"
	"sync"
)

// fakeBackend is an in-memory Backend for tests — no real kernel calls, so
// these tests exercise Store's own convergence/grace-period logic in
// isolation from internal/plumbing/vrf and internal/plumbing/srv6, which
// need CAP_NET_ADMIN and a real netlink socket (see §7 of the plan: the
// real-kernel verification pass those packages need is a separate,
// required pre-merge step, not something a unit test can stand in for).
type fakeBackend struct {
	mu sync.Mutex

	nextTableID uint32
	vrfs        map[string]uint32      // vpc -> tableID
	routes      map[string]routeRecord // "vpc/prefix" -> record
	calls       []string               // ordered call log, for assertions

	// failEnsureVRF/failEnsureRoute/failRemoveVRF/failRemoveRoute, if set,
	// make the matching method return this error instead of succeeding.
	failEnsureVRF   error
	failEnsureRoute error
	failRemoveVRF   error
	failRemoveRoute error
}

type routeRecord struct {
	prefix *net.IPNet
	sid    net.IP
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		nextTableID: 1,
		vrfs:        make(map[string]uint32),
		routes:      make(map[string]routeRecord),
	}
}

func (f *fakeBackend) EnsureVRF(vpc string) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "EnsureVRF:"+vpc)
	if f.failEnsureVRF != nil {
		return 0, f.failEnsureVRF
	}
	if id, ok := f.vrfs[vpc]; ok {
		return id, nil
	}
	id := f.nextTableID
	f.nextTableID++
	f.vrfs[vpc] = id
	return id, nil
}

func (f *fakeBackend) RemoveVRF(vpc string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "RemoveVRF:"+vpc)
	if f.failRemoveVRF != nil {
		return f.failRemoveVRF
	}
	delete(f.vrfs, vpc)
	return nil
}

func (f *fakeBackend) EnsureRoute(prefix *net.IPNet, sid net.IP, tableID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fmt.Sprintf("%d/%s", tableID, prefix)
	f.calls = append(f.calls, "EnsureRoute:"+key)
	if f.failEnsureRoute != nil {
		return f.failEnsureRoute
	}
	f.routes[key] = routeRecord{prefix: prefix, sid: sid}
	return nil
}

func (f *fakeBackend) RemoveRoute(prefix *net.IPNet, tableID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fmt.Sprintf("%d/%s", tableID, prefix)
	f.calls = append(f.calls, "RemoveRoute:"+key)
	if f.failRemoveRoute != nil {
		return f.failRemoveRoute
	}
	delete(f.routes, key)
	return nil
}

func (f *fakeBackend) ListVRFs() ([]VRFInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	infos := make([]VRFInfo, 0, len(f.vrfs))
	for vpc, id := range f.vrfs {
		infos = append(infos, VRFInfo{VPC: vpc, TableID: id})
	}
	return infos, nil
}

func (f *fakeBackend) ListRoutes(tableID uint32) ([]RouteInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var infos []RouteInfo
	prefixStr := fmt.Sprintf("%d/", tableID)
	for key, rec := range f.routes {
		if len(key) > len(prefixStr) && key[:len(prefixStr)] == prefixStr {
			infos = append(infos, RouteInfo{Prefix: rec.prefix, SID: rec.sid})
		}
	}
	return infos, nil
}

// routeCount/vrfCount let tests assert on the fake's installed state
// directly, independent of Store's own bookkeeping.
func (f *fakeBackend) routeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.routes)
}

func (f *fakeBackend) vrfCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.vrfs)
}

// seedRoute directly inserts a route into the fake's kernel-side state
// without going through Store — used to simulate pre-existing kernel state
// for Store.Inventory tests.
func (f *fakeBackend) seedRoute(vpc string, tableID uint32, prefix *net.IPNet, sid net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vrfs[vpc] = tableID
	if tableID >= f.nextTableID {
		f.nextTableID = tableID + 1
	}
	key := fmt.Sprintf("%d/%s", tableID, prefix)
	f.routes[key] = routeRecord{prefix: prefix, sid: sid}
}
