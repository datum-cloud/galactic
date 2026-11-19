// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"go.datum.net/galactic/internal/ownership"
)

// recordingSink records what the router hands Worker.
type recordingSink struct {
	mu          sync.Mutex
	upserts     []string
	withdrawals []string
	forgotten   []string
}

func (s *recordingSink) ForgetTable(vpc string, tableID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgotten = append(s.forgotten, fmt.Sprintf("%s %d", vpc, tableID))
}

func (s *recordingSink) Upsert(vpc string, tableID uint32, prefix netip.Prefix, sid net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts = append(s.upserts, fmt.Sprintf("%s %d %s %s", vpc, tableID, prefix, sid))
}

func (s *recordingSink) Withdraw(vpc string, prefix netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.withdrawals = append(s.withdrawals, vpc+" "+prefix.String())
}

const (
	workerVPC  = "vpcW"
	otherVPC   = "vpcX"
	otherRoute = 43
)

// fencedRoutes is a vrfRoutes over f whose table 42 belongs to a VPC Worker
// owns and table 43 to one it does not.
func fencedRoutes(f VPCFence, sink TenantRouteSink) (*vrfRoutes, *int) {
	failing := 0
	v := newVRFRoutes(func(n int) { failing = n })
	v.vpcOf = func(tableID uint32) string {
		switch tableID {
		case tenantRoute.tableID:
			return workerVPC
		case otherRoute:
			return otherVPC
		}
		return ""
	}
	v.fence, v.sink = f, sink
	return v, &failing
}

func TestVRFRoutes_WorkerOwnedVPCIsLeftToWorker(t *testing.T) {
	f := newFakeEgressTable(t)
	f.setUsable(tenantSID)
	var fenced []string
	fence := func(vpc string, mutate func() error) error {
		fenced = append(fenced, vpc)
		if vpc == workerVPC {
			return fmt.Errorf("write: %w", ownership.ErrWorkerOwned)
		}
		return mutate()
	}
	sink := &recordingSink{}
	v, failing := fencedRoutes(fence, sink)

	v.install(tenantRoute, tenantSID)
	if f.addCount() != 0 {
		t.Fatal("router wrote a route in a VPC Worker owns")
	}
	if *failing != 0 {
		t.Fatalf("a route Worker writes is counted failing: %d", *failing)
	}
	if err := v.withdraw(tenantRoute); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(v.pendingDel) != 0 {
		t.Fatal("a withdrawal Worker makes is pending")
	}

	other := vrfRouteKey{tableID: otherRoute, prefix: tenantRoute.prefix}
	v.install(other, tenantSID)
	if _, ok := f.entry(other); !ok {
		t.Fatal("route in a VPC Worker does not own was not written")
	}
	if want := []string{workerVPC, workerVPC, otherVPC}; fmt.Sprint(fenced) != fmt.Sprint(want) {
		t.Errorf("fenced writes = %v, want %v", fenced, want)
	}
	if len(sink.upserts) != 2 || len(sink.withdrawals) != 1 ||
		sink.upserts[0] != "vpcW 42 2001:db8:100::/64 fc00:0:a:42::" {
		t.Errorf("handed Worker upserts %v and withdrawals %v", sink.upserts, sink.withdrawals)
	}

	// A VRF removed or moved off its table withdraws what Worker was handed.
	v.forgetTable(workerVPC, tenantRoute.tableID)
	if fmt.Sprint(sink.forgotten) != "[vpcW 42]" {
		t.Errorf("forgotten tables = %v, want [vpcW 42]", sink.forgotten)
	}
}

func TestVRFRoutes_RetriesAFencedWithdrawal(t *testing.T) {
	f := newFakeEgressTable(t)
	f.setUsable(tenantSID)
	moving := true
	fence := func(_ string, mutate func() error) error {
		if moving {
			return ownership.ErrTransitioning
		}
		return mutate()
	}
	other := vrfRouteKey{tableID: otherRoute, prefix: tenantRoute.prefix}
	v, _ := fencedRoutes(fence, nil)
	moving = false
	v.install(other, tenantSID)
	moving = true
	if err := v.withdraw(other); !errors.Is(err, ownership.ErrTransitioning) {
		t.Fatalf("withdraw = %v, want ErrTransitioning", err)
	}
	if _, ok := f.entry(other); !ok {
		t.Fatal("entry removed while the fence refused")
	}
	moving = false
	v.retryPending()
	if _, ok := f.entry(other); ok {
		t.Fatal("refused withdrawal not retried")
	}
	if len(v.pendingDel) != 0 {
		t.Fatal("retried withdrawal still pending")
	}
}

func TestOwnershipFence_RefusesAWorkerOwnedScope(t *testing.T) {
	auth, err := ownership.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Claim(ownership.VPCScope(workerVPC), ownership.WorkerOwnerPrefix+"node-a:1"); err != nil {
		t.Fatal(err)
	}
	fence := OwnershipFence(auth)
	ran := false
	if err := fence(workerVPC, func() error { ran = true; return nil }); !errors.Is(err, ownership.ErrWorkerOwned) ||
		ran {
		t.Fatalf("fence(worker-owned) = %v, ran %t; want ErrWorkerOwned without running", err, ran)
	}
	if err := fence(otherVPC, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("fence(unowned) = %v, ran %t; want it run", err, ran)
	}
}
