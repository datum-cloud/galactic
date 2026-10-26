// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/testpki"
)

// nodeCaller is the identity the sidecar on n presents: its certs pod's.
func nodeCaller(ctx context.Context, n string) context.Context {
	return node.WithCaller(ctx, identity.Node(testSite, DefaultNamespace, "certs-"+n))
}

func newPermits(t *testing.T, objs []client.Object, l limit.Limits, slots int) *Permits {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	sel, _ := labels.Parse(DefaultPodSelector)
	certs, _ := labels.Parse(DefaultCertsSelector)
	adm := newTestAdmission(t, l)
	return &Permits{
		Admission: adm, Executor: NewExecutor(slots, 0, 0), Elected: elected,
		Discoverer: &Discoverer{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build(),
			Namespace: DefaultNamespace, Selector: sel, CertsSelector: certs},
	}
}

func pingPermitRequest(n, operator string, expires time.Time) *permitv1.RequestPermitRequest {
	return &permitv1.RequestPermitRequest{
		Node: n, Operator: operator, RequestId: "op-" + n,
		Query: &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: probeTarget4,
			AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4},
		ExpiresAt: timestamppb.New(expires),
	}
}

func TestPermitAuthorization(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	addr := serveGateway(t, gwCreds, &Debug{Elected: elected},
		&Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req := pingPermitRequest(routerA, "alice", time.Now().Add(10*time.Second))

	// A node reaches the permit service (which issues nothing without an
	// admission), and nothing else.
	nodeConn := dialAs(t, addr, loadCreds(t, ca, filepath.Join(dir, "node"),
		identity.Node(testSite, DefaultNamespace, "certs-"+routerA)))
	_, err := permitv1.NewPermitServiceClient(nodeConn).RequestPermit(ctx, req)
	if errcode.Of(err) != errcode.LimiterUnavailable {
		t.Errorf("node RequestPermit: %v", err)
	}
	_, err = fabricv1.NewFabricGatewayServiceClient(nodeConn).Query(ctx, &fabricv1.QueryRequest{})
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("node Query: %v", err)
	}
	_, err = servicev1.NewLookingGlassServiceClient(nodeConn).GetCapabilities(ctx,
		&servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor})
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("node GetCapabilities: %v", err)
	}

	// No other role may request a permit, and a node of another namespace
	// is refused by the handler.
	for _, id := range []identity.ID{
		identity.Operator(testSite, "alice"), identity.Service(testSite, testService),
		identity.Node(testSite, "elsewhere", "certs-"+routerA),
	} {
		conn := dialAs(t, addr, loadCreds(t, ca, filepath.Join(dir, string(id.Role)+id.Namespace), id))
		_, err := permitv1.NewPermitServiceClient(conn).RequestPermit(ctx, req)
		if errcode.Of(err) != errcode.Unauthorized {
			t.Errorf("%s RequestPermit: %v", id, err)
		}
	}
}

func TestPermitIssueHoldRelease(t *testing.T) {
	l := roomyLimits()
	l.QueueWait = 50 * time.Millisecond
	p := newPermits(t, routerPods(routerA, routerB), l, 1)
	ctxA, ctxB := nodeCaller(t.Context(), routerA), nodeCaller(t.Context(), routerB)
	expires := time.Now().Add(10 * time.Second)

	resp, err := p.RequestPermit(ctxA, pingPermitRequest(routerA, "alice", expires))
	if err != nil {
		t.Fatal(err)
	}
	pm := resp.GetPermit()
	if pm.GetNode() != routerA || pm.GetRequestId() != "op-"+routerA || pm.GetDestination() != probeTarget4 ||
		pm.GetPackets() != limit.PingPackets || pm.GetEpoch() != "lease-uid/"+testHolder ||
		pm.GetDeadline().AsTime().After(expires) {
		t.Errorf("permit = %v", pm)
	}
	// The permit holds the cell's only slot.
	_, err = p.RequestPermit(ctxB, pingPermitRequest(routerB, "bob", expires))
	if errcode.Of(err) != errcode.QueueTimeout {
		t.Errorf("second permit while the slot is held: %v", err)
	}
	// Only the node it was issued to may release it.
	_, err = p.ReleasePermit(ctxB, &permitv1.ReleasePermitRequest{Node: routerA, Id: pm.GetId()})
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("release by another node: %v", err)
	}
	if _, err := p.ReleasePermit(ctxB, &permitv1.ReleasePermitRequest{Node: routerB, Id: pm.GetId()}); err != nil {
		t.Errorf("release of an unknown permit: %v", err)
	}
	_, err = p.RequestPermit(ctxB, pingPermitRequest(routerB, "bob", expires))
	if errcode.Of(err) != errcode.QueueTimeout {
		t.Errorf("slot freed by another node's release: %v", err)
	}
	if _, err := p.ReleasePermit(ctxA, &permitv1.ReleasePermitRequest{Node: routerA, Id: pm.GetId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RequestPermit(ctxB, pingPermitRequest(routerB, "bob", expires)); err != nil {
		t.Errorf("after release: %v", err)
	}
}

func TestPermitRefusals(t *testing.T) {
	p := newPermits(t, routerPods(routerA, routerB), roomyLimits(), 8)
	ctxA := nodeCaller(t.Context(), routerA)
	expires := time.Now().Add(10 * time.Second)
	for name, tc := range map[string]struct {
		mod  func(*permitv1.RequestPermitRequest)
		code errcode.Code
	}{
		"another node": {func(r *permitv1.RequestPermitRequest) { r.Node = routerB }, errcode.Unauthorized},
		"no operator":  {func(r *permitv1.RequestPermitRequest) { r.Operator = "" }, errcode.InvalidQuery},
		"bad operator": {func(r *permitv1.RequestPermitRequest) { r.Operator = "a/b" }, errcode.InvalidQuery},
		"a read": {func(r *permitv1.RequestPermitRequest) {
			r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY,
				AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4}
		}, errcode.InvalidQuery},
		"not canonical": {func(r *permitv1.RequestPermitRequest) { r.Query.AddressFamily = 0 }, errcode.InvalidQuery},
		"past expiry": {func(r *permitv1.RequestPermitRequest) {
			r.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
		}, errcode.DeadlineExceeded},
	} {
		req := pingPermitRequest(routerA, "alice", expires)
		tc.mod(req)
		if _, err := p.RequestPermit(ctxA, req); errcode.Of(err) != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	// An unreleased permit's slot frees after its deadline plus the grace.
	p = newPermits(t, routerPods(routerA), roomyLimits(), 1)
	short := time.Now().Add(200 * time.Millisecond)
	if _, err := p.RequestPermit(ctxA, pingPermitRequest(routerA, "alice", short)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(short.Add(ReservationGrace + 100*time.Millisecond)))
	if rel, err := tryAcquire(p.Executor); err != nil {
		t.Errorf("slot still held past the permit's grace: %v", err)
	} else {
		rel()
	}
}

// leaderConn dials one leader address as the gateway.
type leaderConn struct{ conn *grpc.ClientConn }

func (l leaderConn) LeaderConn(context.Context) (*grpc.ClientConn, error) { return l.conn, nil }

func TestPermitForwarding(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	leader := newPermits(t, routerPods(routerA), roomyLimits(), 8)
	serve := func(p *Permits) string {
		srv := NewServer(gwCreds, testAllowlist, &Debug{Elected: p.Elected},
			&Service{Cell: testSite, Allowlist: testAllowlist, Elected: p.Elected}, p)
		var lc net.ListenConfig
		lis, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)
		return lis.Addr().String()
	}
	leaderAddr := serve(leader)
	follower := &Permits{
		Elected: func() bool { return false }, Discoverer: &Discoverer{Namespace: DefaultNamespace},
		Leader: leaderConn{conn: dialAs(t, leaderAddr, gwCreds)},
	}
	followerAddr := serve(follower)

	nodeConn := dialAs(t, followerAddr, loadCreds(t, ca, filepath.Join(dir, "node"),
		identity.Node(testSite, DefaultNamespace, "certs-"+routerA)))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	resp, err := permitv1.NewPermitServiceClient(nodeConn).RequestPermit(ctx,
		pingPermitRequest(routerA, "alice", time.Now().Add(10*time.Second)))
	if err != nil || resp.GetPermit().GetNode() != routerA {
		t.Fatalf("forwarded RequestPermit = %v, %v", resp, err)
	}
	// The leader sees the node's pod, not the follower's identity: another
	// node's pod cannot be claimed through the follower.
	_, err = permitv1.NewPermitServiceClient(nodeConn).RequestPermit(ctx,
		pingPermitRequest(routerB, "alice", time.Now().Add(10*time.Second)))
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("forwarded request for another node: %v", err)
	}
	if _, err := permitv1.NewPermitServiceClient(nodeConn).ReleasePermit(ctx,
		&permitv1.ReleasePermitRequest{Node: routerA, Id: resp.GetPermit().GetId()}); err != nil {
		t.Errorf("forwarded ReleasePermit: %v", err)
	}
}

func TestPermitForwardedToFollowerRefused(t *testing.T) {
	p := &Permits{
		Elected: func() bool { return false }, Discoverer: &Discoverer{Namespace: DefaultNamespace},
		Leader: leaderConn{},
	}
	ctx := node.WithCaller(t.Context(), identity.Gateway(testSite))
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(nodePodHeader, "certs-"+routerA))
	_, err := p.RequestPermit(ctx, pingPermitRequest(routerA, "alice", time.Now().Add(10*time.Second)))
	if errcode.Of(err) != errcode.OwnershipLost {
		t.Errorf("forwarded RequestPermit at a follower: %v", err)
	}
	_, err = p.ReleasePermit(ctx, &permitv1.ReleasePermitRequest{Node: routerA, Id: "x"})
	if errcode.Of(err) != errcode.OwnershipLost {
		t.Errorf("forwarded ReleasePermit at a follower: %v", err)
	}
}

func TestPrincipalFamiliesDoNotCollide(t *testing.T) {
	if fabricQueryPrincipal("operator", "bob") == operatorPrincipal("bob") {
		t.Error("a FabricQuery in namespace operator shares an operator's key")
	}
}
