// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
	"go.datum.net/galactic/internal/fabric/testpki"
)

const (
	testService   = "looking-glass"
	testRequestID = "b74e19ee-926f-43dc-b03d-c29550a827ab"
	otherCell     = "sjc"
)

var testAllowlist = Allowlist{testService: true}

type (
	fwdReq = forwardv1.ForwardDiagnosticRequest
	runReq = servicev1.RunDiagnosticRequest
)

func serveGateway(t *testing.T, creds *identity.Credentials, d *Debug, svc *Service, opts ...grpc.ServerOption) string {
	t.Helper()
	srv := NewServer(creds, svc.Allowlist, d, svc, noPermits(d.Elected), opts...)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

// noPermits is a permit service that issues no permits.
func noPermits(elected func() bool) *Permits {
	return &Permits{Elected: elected, Discoverer: &Discoverer{Namespace: DefaultNamespace}}
}

func dialTLS(t *testing.T, addr string, cfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func dialAs(t *testing.T, addr string, c *identity.Credentials) *grpc.ClientConn {
	t.Helper()
	return dialTLS(t, addr, c.ClientConfig(identity.Gateway(testSite)))
}

func validRequest(now time.Time) *servicev1.RunDiagnosticRequest {
	return &servicev1.RunDiagnosticRequest{
		ApiMajor:  ServiceAPIMajor,
		Cell:      testSite,
		ProjectId: "project-a",
		RequestId: testRequestID,
		ExpiresAt: timestamppb.New(now.Add(30 * time.Second)),
		Query: &fabricv1.Query{
			Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: "2606:4700:0000::1",
		},
	}
}

// runDiagnostic calls RunDiagnostic and returns the stream's final error.
func runDiagnostic(ctx context.Context, conn *grpc.ClientConn, req *servicev1.RunDiagnosticRequest) error {
	stream, err := servicev1.NewLookingGlassServiceClient(conn).RunDiagnostic(ctx, req)
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}

// forwardDiagnostic calls ForwardDiagnostic and returns the stream's final
// error.
func forwardDiagnostic(ctx context.Context, conn *grpc.ClientConn, env *forwardv1.ForwardDiagnosticRequest) error {
	stream, err := forwardv1.NewForwardServiceClient(conn).ForwardDiagnostic(ctx, env)
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}

func elected() bool { return true }

// serveFollower serves a gateway replica that does not lead and whose
// election lease names the replica at leaderAddr, and returns its address.
// dial is added to its leader connection's options.
func serveFollower(t *testing.T, creds *identity.Credentials, leaderAddr string, dial ...grpc.DialOption) string {
	t.Helper()
	f := followerService(t, creds, leaderAddr, dial...)
	return serveGateway(t, creds, f.Leader.(*Debug), f)
}

// followerService is the service of a replica that does not lead and whose
// election lease names the replica at leaderAddr.
func followerService(t *testing.T, creds *identity.Credentials, leaderAddr string, dial ...grpc.DialOption) *Service {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(leaderAddr)
	port, _ := strconv.Atoi(portStr)
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	holder := "gw-leader_1234"
	reader := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: testLeaseName, Namespace: DefaultNamespace},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gw-leader", Namespace: DefaultNamespace},
			Status: corev1.PodStatus{PodIP: host}},
	).Build()
	notElected := func() bool { return false }
	follower := &Debug{Elected: notElected, Reader: reader, Namespace: DefaultNamespace,
		LeaseName: testLeaseName, PodName: "gw-follower", Port: port, Credentials: creds, Cell: testSite,
		DialOptions: dial}
	return &Service{Cell: testSite, Allowlist: testAllowlist, Elected: notElected, Leader: follower}
}

func TestServiceAuthorization(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	rogue := testpki.NewCA(t, "rogue")
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	addr := serveGateway(t, gwCreds, &Debug{Elected: elected},
		&Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// A listed service of this cell reaches both service methods, unary and
	// streaming, repeatedly on one connection. Execution is not enabled.
	svc := dialAs(t, addr, loadCreds(t, ca, dir, identity.Service(testSite, testService)))
	for range 2 {
		caps, err := servicev1.NewLookingGlassServiceClient(svc).GetCapabilities(ctx,
			&servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor})
		if err != nil || caps.GetCell() != testSite || caps.GetEnabled() {
			t.Fatalf("GetCapabilities = %v, %v", caps, err)
		}
		if err := runDiagnostic(ctx, svc, validRequest(time.Now())); errcode.Of(err) != errcode.ServiceDisabled {
			t.Fatalf("RunDiagnostic: %v", err)
		}
	}

	// The service may call nothing else on the gateway.
	debug := fabricv1.NewFabricGatewayServiceClient(svc)
	if _, err := debug.Query(ctx, &fabricv1.QueryRequest{}); errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("service Query: %v", err)
	}
	if _, err := debug.ListNodes(ctx, &fabricv1.ListNodesRequest{}); errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("service ListNodes: %v", err)
	}
	if err := forwardDiagnostic(ctx, svc, &forwardv1.ForwardDiagnosticRequest{}); errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("service ForwardDiagnostic: %v", err)
	}

	// No other role gains a service method.
	for _, id := range []identity.ID{identity.Operator(testSite, "alice"), identity.Gateway(testSite)} {
		conn := dialAs(t, addr, loadCreds(t, ca, dir, id))
		_, err := servicev1.NewLookingGlassServiceClient(conn).GetCapabilities(ctx,
			&servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor})
		if errcode.Of(err) != errcode.Unauthorized {
			t.Errorf("%s GetCapabilities: %v", id, err)
		}
		if err := runDiagnostic(ctx, conn, validRequest(time.Now())); errcode.Of(err) != errcode.Unauthorized {
			t.Errorf("%s RunDiagnostic: %v", id, err)
		}
	}

	// Credentials that never authenticate as a listed service of this cell.
	issue := func(ca *testpki.CA, name string, opts testpki.Options) *tls.Config {
		f := ca.Issue(t, filepath.Join(dir, name), opts)
		pair, err := tls.LoadX509KeyPair(f.Cert, f.Key)
		if err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // client side of a server test
		return &tls.Config{Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true}
	}
	uris := func(id identity.ID) testpki.Options { return testpki.Options{URIs: []string{id.URI()}} }
	svcID := identity.Service(testSite, testService)
	expired := uris(svcID)
	expired.NotBefore, expired.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	for name, cfg := range map[string]*tls.Config{
		"unlisted service":   issue(ca, "unlisted", uris(identity.Service(testSite, "other"))),
		"cross-cell service": issue(ca, otherCell, uris(identity.Service(otherCell, testService))),
		"other CA":           issue(rogue, "rogue", uris(svcID)),
		"node role":          issue(ca, "node", uris(identity.Node(testSite, "ns", "pod"))),
		"expired":            issue(ca, "expired", expired),
		"no certificate":     {InsecureSkipVerify: true}, //nolint:gosec // client side of a server test
	} {
		conn := dialTLS(t, addr, cfg)
		_, err := servicev1.NewLookingGlassServiceClient(conn).GetCapabilities(ctx,
			&servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor})
		if err == nil {
			t.Errorf("%s: GetCapabilities succeeded", name)
		}
		err = runDiagnostic(ctx, conn, validRequest(time.Now()))
		if err == nil || errcode.Of(err) == errcode.ServiceDisabled {
			t.Errorf("%s: RunDiagnostic reached the handler: %v", name, err)
		}
	}
}

func TestServiceCertificateLifecycle(t *testing.T) {
	dir := t.TempDir()
	oldCA := testpki.NewCA(t, "old")
	newCA := testpki.NewCA(t, "new")
	gwID := identity.Gateway(testSite)
	svcID := identity.Service(testSite, testService)
	serverDir := filepath.Join(dir, "server")
	f := oldCA.Issue(t, serverDir, testpki.Options{URIs: []string{gwID.URI()}})
	now := time.Now()
	var mu sync.Mutex
	server := &identity.Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: gwID, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	addr := serveGateway(t, server, &Debug{Elected: elected},
		&Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	caps := func(conn *grpc.ClientConn) error {
		_, err := servicev1.NewLookingGlassServiceClient(conn).GetCapabilities(ctx,
			&servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor})
		return err
	}
	both := append(append([]byte{}, oldCA.PEM...), newCA.PEM...)
	client := func(ca *testpki.CA, name string, notAfter time.Time) *grpc.ClientConn {
		cf := ca.Issue(t, filepath.Join(dir, name), testpki.Options{URIs: []string{svcID.URI()}, NotAfter: notAfter}, both)
		c := &identity.Credentials{CertFile: cf.Cert, KeyFile: cf.Key, CAFile: cf.CA, Self: svcID}
		if err := c.Reload(); err != nil {
			t.Fatal(err)
		}
		return dialAs(t, addr, c)
	}

	// Rotation: the server moves to a bundle holding both CAs and a leaf
	// from the new one. The old client keeps working on its connection and a
	// new-CA client is accepted.
	oldClient := client(oldCA, "old-client", time.Time{})
	if err := caps(oldClient); err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	newCA.Issue(t, serverDir, testpki.Options{URIs: []string{gwID.URI()}}, both)
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	newClient := client(newCA, "new-client", time.Time{})
	if err := caps(oldClient); err != nil {
		t.Errorf("old CA during overlap: %v", err)
	}
	if err := caps(newClient); err != nil {
		t.Errorf("new CA during overlap: %v", err)
	}

	// The old CA leaves the bundle: its client is refused on the connection
	// it already holds.
	newCA.Issue(t, serverDir, testpki.Options{URIs: []string{gwID.URI()}})
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := caps(oldClient); status.Code(err) != codes.Unauthenticated {
		t.Errorf("old CA after rotation: %v", err)
	}
	if err := caps(newClient); err != nil {
		t.Errorf("new CA after rotation: %v", err)
	}

	// Expiry: once the server's clock passes the client's certificate, the
	// open connection authorizes nothing more.
	shortClient := client(newCA, "short", now.Add(time.Hour))
	if err := caps(shortClient); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if err := caps(shortClient); status.Code(err) != codes.Unauthenticated {
		t.Errorf("after expiry: %v", err)
	}
	if err := runDiagnostic(ctx, shortClient, validRequest(time.Now())); status.Code(err) != codes.Unauthenticated {
		t.Errorf("stream after expiry: %v", err)
	}
}

// envelopeRecorder records every ForwardDiagnosticRequest a server receives.
type envelopeRecorder struct {
	mu   sync.Mutex
	envs []*forwardv1.ForwardDiagnosticRequest
}

type recordingStream struct {
	grpc.ServerStream
	r *envelopeRecorder
}

func (s *recordingStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if env, ok := m.(*forwardv1.ForwardDiagnosticRequest); ok && err == nil {
		s.r.mu.Lock()
		s.r.envs = append(s.r.envs, proto.CloneOf(env))
		s.r.mu.Unlock()
	}
	return err
}

func (r *envelopeRecorder) interceptor(
	srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	return handler(srv, &recordingStream{ServerStream: ss, r: r})
}

func (r *envelopeRecorder) last() *forwardv1.ForwardDiagnosticRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.envs) == 0 {
		return nil
	}
	return r.envs[len(r.envs)-1]
}

func TestServiceForwarding(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	svcID := identity.Service(testSite, testService)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	rec := &envelopeRecorder{}
	leaderAddr := serveGateway(t, gwCreds, &Debug{Elected: elected},
		&Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected},
		grpc.ChainStreamInterceptor(rec.interceptor))
	followerAddr := serveFollower(t, gwCreds, leaderAddr)
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	notElected := func() bool { return false }

	// A follower authenticates the service, forwards the validated request
	// once in a typed envelope, and relays the leader's answer.
	svc := dialAs(t, followerAddr, loadCreds(t, ca, dir, svcID))
	sent := time.Now()
	req := validRequest(sent)
	callCtx, callCancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx,
		"x-fabric-api-operator", "mallory", "x-fabric-api-service", "forged"), 5*time.Second)
	defer callCancel()
	if err := runDiagnostic(callCtx, svc, req); errcode.Of(err) != errcode.ServiceDisabled {
		t.Fatalf("forwarded RunDiagnostic: %v", err)
	}
	env := rec.last()
	if env == nil {
		t.Fatal("the leader received no envelope")
	}
	got := env.GetRequest()
	if env.GetService() != svcID.URI() || got.GetProjectId() != "project-a" || got.GetRequestId() != testRequestID ||
		got.GetCell() != testSite {
		t.Errorf("envelope attribution = %v", env)
	}
	if got.GetQuery().GetTarget() != "2606:4700::1" ||
		got.GetQuery().GetAddressFamily() != fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6 {
		t.Errorf("envelope query is not canonical: %v", got.GetQuery())
	}
	// The transport carries the caller's deadline as a relative timeout, so
	// the follower's copy may trail it by the call's latency.
	callDeadline, _ := callCtx.Deadline()
	if d := env.GetDeadline().AsTime(); d.After(req.GetExpiresAt().AsTime()) || d.After(callDeadline.Add(time.Second)) {
		t.Errorf("envelope deadline %v exceeds the request's", d)
	}
	if r := env.GetReceivedAt().AsTime(); r.Before(sent.Add(-time.Second)) || r.After(time.Now()) {
		t.Errorf("envelope receipt time %v", r)
	}

	// A follower never forwards a forwarded request again.
	gw := dialAs(t, followerAddr, gwCreds)
	if err := forwardDiagnostic(ctx, gw, env); errcode.Of(err) != errcode.OwnershipLost {
		t.Errorf("second hop: %v", err)
	}

	// With no leader, a follower refuses rather than executing.
	lost := &Service{Cell: testSite, Allowlist: testAllowlist, Elected: notElected, Leader: &Debug{
		Reader: fake.NewClientBuilder().WithScheme(s).Build(), Namespace: DefaultNamespace, LeaseName: testLeaseName,
	}}
	lostAddr := serveGateway(t, gwCreds, &Debug{Elected: notElected}, lost)
	lostConn := dialAs(t, lostAddr, loadCreds(t, ca, dir, svcID))
	if err := runDiagnostic(ctx, lostConn, validRequest(time.Now())); errcode.Of(err) != errcode.OwnershipLost {
		t.Errorf("no leader: %v", err)
	}

	// The leader validates every envelope again.
	leader := dialAs(t, leaderAddr, gwCreds)
	now := time.Now()
	envelope := func(edit func(*forwardv1.ForwardDiagnosticRequest)) *forwardv1.ForwardDiagnosticRequest {
		e := &forwardv1.ForwardDiagnosticRequest{
			Service:    svcID.URI(),
			Request:    validRequest(now),
			ReceivedAt: timestamppb.New(now),
			Deadline:   timestamppb.New(now.Add(20 * time.Second)),
		}
		if edit != nil {
			edit(e)
		}
		return e
	}
	for name, tc := range map[string]struct {
		edit func(*fwdReq)
		want errcode.Code
	}{
		"valid":            {nil, errcode.ServiceDisabled},
		"unlisted service": {func(e *fwdReq) { e.Service = identity.Service(testSite, "other").URI() }, errcode.Unauthorized},
		"cross-cell envelope": {func(e *fwdReq) {
			e.Service = identity.Service(otherCell, testService).URI()
		}, errcode.Unauthorized},
		"operator": {func(e *fwdReq) {
			e.Service = identity.Operator(testSite, "alice").URI()
		}, errcode.Unauthorized},
		"no service":   {func(e *fwdReq) { e.Service = "" }, errcode.Unauthorized},
		"request cell": {func(e *fwdReq) { e.Request.Cell = otherCell }, errcode.Unauthorized},
		"bad project":  {func(e *fwdReq) { e.Request.ProjectId = "a b" }, errcode.InvalidQuery},
		"no deadline":  {func(e *fwdReq) { e.Deadline = nil }, errcode.InvalidQuery},
		"past deadline": {func(e *fwdReq) {
			e.Deadline = timestamppb.New(now.Add(-time.Second))
		}, errcode.DeadlineExceeded},
		"no receipt":     {func(e *fwdReq) { e.ReceivedAt = nil }, errcode.InvalidQuery},
		"future receipt": {func(e *fwdReq) { e.ReceivedAt = timestamppb.New(now.Add(time.Minute)) }, errcode.InvalidQuery},
		"lifetime from receipt": {func(e *fwdReq) {
			e.ReceivedAt = timestamppb.New(now.Add(-100 * time.Second))
		}, errcode.InvalidQuery},
	} {
		if err := forwardDiagnostic(ctx, leader, envelope(tc.edit)); errcode.Of(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

// fakeEventStream is a RunDiagnostic server stream that records events.
type fakeEventStream struct {
	grpc.ServerStream
	ctx    context.Context
	events []*servicev1.DiagnosticEvent
}

func (s *fakeEventStream) Context() context.Context { return s.ctx }

func (s *fakeEventStream) Send(ev *servicev1.DiagnosticEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func TestServiceValidation(t *testing.T) {
	now := time.Now()
	svc := &Service{
		Cell: testSite, Allowlist: testAllowlist, Elected: elected, Now: func() time.Time { return now },
		Destinations: query.DestinationPolicy{Deny: []netip.Prefix{netip.MustParsePrefix("2606:4700:ff::/48")}},
	}
	ctx := node.WithCaller(t.Context(), identity.Service(testSite, testService))
	for name, tc := range map[string]struct {
		edit func(*runReq)
		want errcode.Code
	}{
		"valid": {nil, errcode.ServiceDisabled},
		"route lookup": {func(r *runReq) {
			r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP, Target: "192.0.2.0/24"}
		}, errcode.ServiceDisabled},
		"bgp summary": {func(r *runReq) {
			r.Query = &fabricv1.Query{
				Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY, AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6,
			}
		}, errcode.ServiceDisabled},
		"api major":       {func(r *runReq) { r.ApiMajor = 2 }, errcode.VersionUnsupported},
		"other cell":      {func(r *runReq) { r.Cell = otherCell }, errcode.Unauthorized},
		"no project":      {func(r *runReq) { r.ProjectId = "" }, errcode.InvalidQuery},
		"long project":    {func(r *runReq) { r.ProjectId = strings.Repeat("a", 129) }, errcode.InvalidQuery},
		"project control": {func(r *runReq) { r.ProjectId = "project\n" }, errcode.InvalidQuery},
		"no request ID":   {func(r *runReq) { r.RequestId = "" }, errcode.InvalidQuery},
		"uppercase UUID":  {func(r *runReq) { r.RequestId = strings.ToUpper(testRequestID) }, errcode.InvalidQuery},
		"not a UUID":      {func(r *runReq) { r.RequestId = "request-1" }, errcode.InvalidQuery},
		"no expiration":   {func(r *runReq) { r.ExpiresAt = nil }, errcode.InvalidQuery},
		"expired":         {func(r *runReq) { r.ExpiresAt = timestamppb.New(now) }, errcode.DeadlineExceeded},
		"too far": {func(r *runReq) {
			r.ExpiresAt = timestamppb.New(now.Add(121 * time.Second))
		}, errcode.InvalidQuery},
		"no query": {func(r *runReq) { r.Query = nil }, errcode.InvalidQuery},
		"as-path": {func(r *runReq) {
			r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_AS_PATH, Target: "_64512_"}
		}, errcode.InvalidQuery},
		"hostname probe": {func(r *runReq) { r.Query.Target = "example.com" }, errcode.InvalidQuery},
		// The public destination policy refuses before the snapshot, so a
		// forbidden probe costs no tokens, slots or packets.
		"documentation probe": {func(r *runReq) { r.Query.Target = "2001:db8::1" }, errcode.DestinationNotAllowed},
		"unique local probe":  {func(r *runReq) { r.Query.Target = "fc00::1" }, errcode.DestinationNotAllowed},
		"private probe": {func(r *runReq) {
			r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_TRACEROUTE, Target: "10.0.0.1"}
		}, errcode.DestinationNotAllowed},
		"multicast probe": {func(r *runReq) {
			r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: "224.0.0.1"}
		}, errcode.DestinationNotAllowed},
		"denied probe":    {func(r *runReq) { r.Query.Target = "2606:4700:ff::1" }, errcode.DestinationNotAllowed},
		"too many nodes":  {func(r *runReq) { r.Nodes = make([]string, MaxServiceNodes+1) }, errcode.InvalidQuery},
		"duplicate nodes": {func(r *runReq) { r.Nodes = []string{"a", "a"} }, errcode.InvalidQuery},
		"empty node name": {func(r *runReq) { r.Nodes = []string{""} }, errcode.InvalidQuery},
		"selected nodes":  {func(r *runReq) { r.Nodes = []string{"a", "b"} }, errcode.ServiceDisabled},
		"maximum lifetime": {func(r *runReq) {
			r.ExpiresAt = timestamppb.New(now.Add(MaxServiceRequestLifetime))
		}, errcode.ServiceDisabled},
	} {
		req := validRequest(now)
		if tc.edit != nil {
			tc.edit(req)
		}
		stream := &fakeEventStream{ctx: ctx}
		if err := svc.RunDiagnostic(req, stream); errcode.Of(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
		if len(stream.events) != 0 {
			t.Errorf("%s: sent events %v", name, stream.events)
		}
	}

	// With no deployment ranges configured, the public policy still
	// refuses special-use targets.
	open := &Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected, Now: func() time.Time { return now }}
	req := validRequest(now)
	req.Query.Target = "fc00::1"
	if err := open.RunDiagnostic(req, &fakeEventStream{ctx: ctx}); errcode.Of(err) != errcode.DestinationNotAllowed {
		t.Errorf("unique local probe without --deny-prefixes: %v, want %s", err, errcode.DestinationNotAllowed)
	}

	// GetCapabilities checks the version and cell too.
	_, err := svc.GetCapabilities(ctx, &servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: 2})
	if errcode.Of(err) != errcode.VersionUnsupported {
		t.Errorf("capabilities major: %v", err)
	}
	_, err = svc.GetCapabilities(ctx, &servicev1.GetCapabilitiesRequest{Cell: otherCell, ApiMajor: 1})
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("capabilities cell: %v", err)
	}
}

func TestStripForwarding(t *testing.T) {
	md := metadata.Pairs("x-fabric-api-operator", "mallory", "x-fabric-api-service", "forged", "x-other", "kept")
	for _, tc := range []struct {
		caller identity.ID
		kept   bool
	}{
		{identity.Service(testSite, testService), false},
		{identity.Operator(testSite, "alice"), false},
		{identity.Gateway(testSite), true},
	} {
		ctx := node.WithCaller(metadata.NewIncomingContext(t.Context(), md), tc.caller)
		got, _ := metadata.FromIncomingContext(stripForwarding(ctx))
		if (len(got.Get("x-fabric-api-operator")) > 0) != tc.kept || len(got.Get("x-fabric-api-service")) > 0 != tc.kept {
			t.Errorf("%s: metadata %v", tc.caller, got)
		}
		if got.Get("x-other")[0] != "kept" {
			t.Errorf("%s: dropped unrelated metadata", tc.caller)
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	a, err := ParseAllowlist([]string{testService, "lg-2"})
	if err != nil || !a[testService] || !a["lg-2"] {
		t.Fatalf("ParseAllowlist = %v, %v", a, err)
	}
	for _, bad := range []string{"", "Looking-Glass", "a/b", "-x"} {
		if _, err := ParseAllowlist([]string{bad}); err == nil {
			t.Errorf("ParseAllowlist(%q) succeeded", bad)
		}
	}
	if err := (Allowlist{}).Handshake(identity.Service(testSite, testService)); err == nil {
		t.Error("an empty allowlist accepted a service")
	}
	// A node connects for the permit service alone; GatewayMethods keeps
	// it from every other method (TestPermitAuthorization).
	if err := (Allowlist{}).Handshake(identity.Node(testSite, "ns", "pod")); err != nil {
		t.Errorf("the gateway refused a node identity: %v", err)
	}
}
