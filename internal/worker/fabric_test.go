// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"

	"google.golang.org/grpc/codes"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/fabric"
	"go.datum.net/galactic/internal/worker/fabric/fabrictest"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/routes"
	"go.datum.net/galactic/internal/worker/sources"
)

const (
	tableA     = 100
	uidGuestA1 = "guest-a1"
	uidGuestA2 = "guest-a2"
)

var (
	guestA1Addr = netip.MustParseAddr("2001:db8:a::1")
	guestA2Addr = netip.MustParseAddr("2001:db8:a::2")
	sidA2       = netip.MustParseAddr("2001:db8:0:2:e000:1::")
)

// fabricEnv is an env running the real Fabric module over an in-memory
// datapath, with guest addresses on the attachments.
func fabricEnv(t *testing.T, withLocal bool) (*env, *fabrictest.Datapath) {
	t.Helper()
	e := newEnv(t)
	dp := fabrictest.New()
	dp.SetTable(vpcA, tableA)
	dp.Reach(locB, 7, "02:00:00:00:00:0b")
	e.routes = routes.New()
	e.src.SetAttachment(sources.Attachment{UID: uidGuestA1, Kind: sources.KindVPCAttachment, VPC: vpcA, Node: node,
		Admitted: true, Addresses: []netip.Addr{guestA1Addr}})
	e.src.SetAttachment(sources.Attachment{UID: uidGuestA2, Kind: sources.KindVPCAttachment, VPC: vpcA,
		Node: otherNode, Admitted: true, Addresses: []netip.Addr{guestA2Addr}})
	e.modules = func(h *fake.Host) []module.Module {
		fab, err := fabric.New(fabric.Config{Routes: e.routes, Datapath: dp,
			OwnLocator: func(ctx context.Context) (netip.Prefix, error) { return e.src.Locator(ctx, node) }})
		if err != nil {
			t.Fatal(err)
		}
		mods := []module.Module{fab}
		if withLocal {
			e.local = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
			mods = append(mods, e.local)
		}
		return mods
	}
	return e, dp
}

// syncRoutes sends one request on a new Routes.Sync stream as caller and
// returns the response.
func (e *env) syncRoutes(caller string, req *workerv1alpha1.RoutesSyncRequest) (
	*workerv1alpha1.RoutesSyncResponse, error) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(e.ctx(caller))
	e.t.Cleanup(cancel)
	stream, err := workerv1alpha1.NewRoutesClient(e.cc).Sync(ctx)
	if err != nil {
		return nil, err
	}
	// A stream the server already ended fails Send with io.EOF; Recv then
	// returns its status.
	if err := stream.Send(req); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return stream.Recv()
}

// upsert is a request upserting one route of VPC A in its table.
func upsert(seq uint64, prefix, sid string) *workerv1alpha1.RoutesSyncRequest {
	return &workerv1alpha1.RoutesSyncRequest{Sequence: seq, Upserts: []*workerv1alpha1.TenantRoute{
		{Vpc: vpcA, TableId: tableA, Prefix: prefix, Sid: sid},
	}}
}

func TestRoutesSyncRefusesACallerWithoutTheCapability(t *testing.T) {
	e, _ := fabricEnv(t, false)
	e.start()
	_, err := e.syncRoutes(natSA, upsert(1, "2001:db8:a::2/128", sidA2.String()))
	wantRefusal(t, err, codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
	if got := e.routes.Routes(vpcA); len(got) != 0 {
		t.Fatalf("refused stream recorded %v", got)
	}
}

func TestRoutesSyncWritesRoutesOfAScopeWithoutClaims(t *testing.T) {
	e, dp := fabricEnv(t, false)
	e.start()
	host := netip.PrefixFrom(guestA2Addr, 128)

	req := upsert(4, host.String(), sidA2.String())
	req.Upserts = append(req.Upserts, &workerv1alpha1.TenantRoute{Vpc: vpcA, TableId: tableA,
		Prefix: "not-a-prefix", Sid: sidA2.String()})
	resp, err := e.syncRoutes(routerSA, req)
	e.mustOK(err)
	if resp.GetSequence() != 4 || len(resp.GetRejected()) != 1 ||
		resp.GetRejected()[0].GetReason() != workerv1alpha1.ReasonMalformedRoute {
		t.Fatalf("response = %v, want sequence 4 with one MalformedRoute rejection", resp)
	}
	e.eventually("route written", func() bool { _, ok := dp.Entries(tableA)[host]; return ok })

	_, err = e.syncRoutes(routerSA, &workerv1alpha1.RoutesSyncRequest{Sequence: 5,
		Withdrawals: []*workerv1alpha1.TenantRouteKey{{Vpc: vpcA, Prefix: host.String()}}})
	e.mustOK(err)
	e.eventually("route removed", func() bool { _, ok := dp.Entries(tableA)[host]; return !ok })
}

func TestMixedLocalAndFabricDestinationsBecomeReady(t *testing.T) {
	e, _ := fabricEnv(t, true)
	e.start()
	_, err := e.syncRoutes(routerSA, upsert(1, netip.PrefixFrom(guestA2Addr, 128).String(),
		sidA2.String()))
	e.mustOK(err)
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth(uidGuestA1, uidGuestA2)))

	st := e.waitReady(mkey(vpcA, "svc-a"), 1)
	for _, d := range st.GetDestinations() {
		if !d.GetReady() || !d.GetForwardReady() || !d.GetReturnReady() {
			t.Errorf("destination %v = %+v, want ready both ways", d.GetDestination(), d)
		}
	}
	if got := st.GetDestinations()[1].GetMode(); got != workerv1alpha1.Mode_MODE_FABRIC {
		t.Errorf("guest-a2 resolved to %s, want MODE_FABRIC", got)
	}
}

func TestLocalDestinationNeverFallsBackToFabric(t *testing.T) {
	e, dp := fabricEnv(t, false)
	e.start()
	// A route covering the local guest's address exists, so Fabric could
	// deliver to it; it must not.
	_, err := e.syncRoutes(routerSA, upsert(1, "2001:db8:a::/120", sidA2.String()))
	e.mustOK(err)
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth(uidGuestA1, uidGuestA2)))

	st := e.waitObserved(mkey(vpcA, "svc-a"))
	e.eventually("fabric destination ready", func() bool {
		st = e.status(mkey(vpcA, "svc-a"))
		return len(st.GetDestinations()) == 2 && st.GetDestinations()[1].GetReady()
	})
	local := st.GetDestinations()[0]
	if local.GetMode() != workerv1alpha1.Mode_MODE_LOCAL || local.GetProgrammed() ||
		local.GetReason() != workerv1alpha1.ReasonModuleNotRunning {
		t.Fatalf("local destination = %+v, want MODE_LOCAL unprogrammed with ModuleNotRunning", local)
	}
	if isTrue(st, workerv1alpha1.ConditionReady) {
		t.Fatal("claim Ready with its Local destination unprogrammed")
	}
	if _, ok := dp.Entries(tableA)[netip.PrefixFrom(guestA1Addr, 128)]; ok {
		t.Fatal("Fabric wrote an entry for the local guest")
	}
}

// TestWithdrawalDuringRepairKeepsSharedTenantRoutes is the contract's
// withdrawal-during-repair transition for Fabric: a claim owns no tenant
// route, so the snapshot that releases it removes nothing of the VPC's
// routes, which other claims and the VPC's own traffic still use.
func TestWithdrawalDuringRepairKeepsSharedTenantRoutes(t *testing.T) {
	e, dp := fabricEnv(t, true)
	e.start()
	host := netip.PrefixFrom(guestA2Addr, 128)
	_, err := e.syncRoutes(routerSA, upsert(1, host.String(), sidA2.String()))
	e.mustOK(err)
	e.eventually("route written", func() bool { _, ok := dp.Entries(tableA)[host]; return ok })
	e.idle()

	e.local.FailApply(1, 0)
	k := mkey(vpcA, "svc-a")
	entered := e.local.PausePlan()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth(uidGuestA1, uidGuestA2)))
	<-entered
	entered = e.local.RepausePlan()
	<-entered
	if !e.isRepairing(vpcA) {
		t.Fatal("scope is not in repair after the failed commit")
	}
	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
	e.local.ResumePlan()

	e.waitGone(k)
	if _, ok := dp.Entries(tableA)[host]; !ok {
		t.Fatal("releasing a claim removed the VPC's tenant route")
	}
}
