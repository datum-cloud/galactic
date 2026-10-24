// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// Looking Glass service request bounds.
const (
	// ServiceAPIMajor is the only API major version the service serves.
	ServiceAPIMajor = 1
	// MaxServiceRequestLifetime bounds a request's expiration, measured from
	// the gateway's first receipt.
	MaxServiceRequestLifetime = 120 * time.Second
	// MaxServiceNodes bounds a request's explicit router selection.
	MaxServiceNodes = 32
	// maxForwardSkew is how far a forwarded receipt time may lead this
	// replica's clock.
	maxForwardSkew = time.Second
)

var (
	projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	requestIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// serviceQueryTypes are the diagnostics the service may request.
var serviceQueryTypes = map[query.Type]bool{
	query.TypeRouteLookup: true,
	query.TypeBGPSummary:  true,
	query.TypePing:        true,
	query.TypeTraceroute:  true,
}

// Allowlist names the Looking Glass service identities a cell's gateway
// accepts. A service identity of the gateway's cell is authorized only when
// its name is listed; an empty allowlist accepts none.
type Allowlist map[string]bool

// ParseAllowlist builds an Allowlist from service names, each a valid
// identity path segment.
func ParseAllowlist(names []string) (Allowlist, error) {
	a := Allowlist{}
	for _, n := range names {
		if _, err := identity.Parse(identity.Service("cell", n).URI()); err != nil {
			return nil, fmt.Errorf("service identity name %q: %w", n, err)
		}
		a[n] = true
	}
	return a, nil
}

// Check refuses a service identity that is not listed. Other roles pass; the
// method table governs them.
func (a Allowlist) Check(id identity.ID) error {
	if id.Role == identity.RoleService && !a[id.Name] {
		return errcode.Status(errcode.Unauthorized, "service identity "+id.URI()+" is not allowed in this cell")
	}
	return nil
}

// Handshake is the gateway server's handshake check: operators, the gateway
// and listed service identities may connect.
func (a Allowlist) Handshake(id identity.ID) error {
	switch id.Role {
	case identity.RoleOperator, identity.RoleGateway:
		return nil
	case identity.RoleService:
		return a.Check(id)
	}
	return errcode.Status(errcode.Unauthorized, "identity "+id.URI()+" may not call the fabric-api gateway")
}

// forwardingPrefix prefixes every metadata key a gateway replica sets when
// it forwards a call to the leader.
const forwardingPrefix = "x-fabric-api-"

// stripForwarding removes forwarding metadata from a call whose caller is
// not the gateway identity, so no other caller can pose as a forwarded one.
func stripForwarding(ctx context.Context) context.Context {
	if id, ok := node.CallerFrom(ctx); ok && id.Role == identity.RoleGateway {
		return ctx
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	clean := metadata.MD{}
	for k, v := range md {
		if !strings.HasPrefix(k, forwardingPrefix) {
			clean[k] = v
		}
	}
	return metadata.NewIncomingContext(ctx, clean)
}

// StripForwardingUnary is a unary interceptor, chained after
// authorization, that removes forwarding metadata a non-gateway caller sent.
func StripForwardingUnary(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	return handler(stripForwarding(ctx), req)
}

// StripForwardingStream is StripForwardingUnary for streams.
func StripForwardingStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &contextStream{ServerStream: ss, ctx: stripForwarding(ss.Context())})
}

type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextStream) Context() context.Context { return s.ctx }

// NewServer returns the gateway's gRPC server: the operator debug service,
// the Looking Glass service and the gateway-only forwarding service on one
// mTLS listener. Every call, unary or streaming, is authorized per role from
// GatewayMethods against a peer certificate re-verified on that call, bounded
// by the certificate's expiry, and stripped of forwarding metadata unless
// the gateway identity sent it. opts are appended.
func NewServer(
	creds *identity.Credentials, allowlist Allowlist, debug *Debug, service *Service, opts ...grpc.ServerOption,
) *grpc.Server {
	auth := &node.Authorizer{Methods: GatewayMethods, Credentials: creds, Allow: allowlist.Check}
	gs := grpc.NewServer(append([]grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(creds.ServerConfig(allowlist.Handshake))),
		grpc.ChainUnaryInterceptor(auth.Unary(), StripForwardingUnary),
		grpc.ChainStreamInterceptor(auth.Stream(), StripForwardingStream),
	}, opts...)...)
	fabricv1.RegisterFabricGatewayServiceServer(gs, debug)
	servicev1.RegisterLookingGlassServiceServer(gs, service)
	forwardv1.RegisterForwardServiceServer(gs, service.Forwarder())
	return gs
}

// LeaderDialer connects to the cell's elected gateway leader.
type LeaderDialer interface {
	LeaderConn(ctx context.Context) (*grpc.ClientConn, error)
}

// Service implements the Looking Glass service. Any replica authenticates
// and validates a request; a follower forwards it once to the leader, which
// validates it again before executing. Customer execution is not enabled:
// a valid request is refused with ServiceDisabled.
type Service struct {
	servicev1.UnimplementedLookingGlassServiceServer

	// Cell is the cell this gateway serves.
	Cell string
	// Allowlist names the accepted service identities.
	Allowlist Allowlist
	// Elected reports whether this replica leads.
	Elected func() bool
	// Leader connects a follower to the leader.
	Leader LeaderDialer
	// Now, when set, replaces the wall clock.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// GetCapabilities reports the cell's service policy.
func (s *Service) GetCapabilities(
	ctx context.Context, req *servicev1.GetCapabilitiesRequest,
) (*servicev1.GetCapabilitiesResponse, error) {
	if _, err := serviceCaller(ctx); err != nil {
		return nil, err
	}
	if req.GetApiMajor() != ServiceAPIMajor {
		return nil, errcode.Status(errcode.VersionUnsupported, fmt.Sprintf("API major %d is not served", req.GetApiMajor()))
	}
	if req.GetCell() != s.Cell {
		return nil, errcode.Status(errcode.Unauthorized, "request names another cell")
	}
	return &servicev1.GetCapabilitiesResponse{Cell: s.Cell, ApiMajor: ServiceAPIMajor}, nil
}

// RunDiagnostic validates a request and runs it on the leader.
func (s *Service) RunDiagnostic(
	req *servicev1.RunDiagnosticRequest, stream grpc.ServerStreamingServer[servicev1.DiagnosticEvent],
) error {
	ctx := stream.Context()
	caller, err := serviceCaller(ctx)
	if err != nil {
		return err
	}
	received := s.now()
	canonical, deadline, err := s.validate(ctx, req, received, received)
	if err != nil {
		return err
	}
	if !s.Elected() {
		return s.forward(ctx, caller, canonical, received, deadline, stream)
	}
	return s.execute(canonical, deadline)
}

// Forwarder returns the gateway-only service a follower forwards to.
func (s *Service) Forwarder() forwardv1.ForwardServiceServer { return &forwarder{s: s} }

type forwarder struct {
	forwardv1.UnimplementedForwardServiceServer
	s *Service
}

// ForwardDiagnostic runs a request a follower forwarded. It trusts the
// envelope only from the gateway identity and validates its service, cell,
// allowlist entry, request and deadline again; a replica that does not lead
// refuses it, so a request never takes a second hop.
func (f *forwarder) ForwardDiagnostic(
	env *forwardv1.ForwardDiagnosticRequest, stream grpc.ServerStreamingServer[servicev1.DiagnosticEvent],
) error {
	s := f.s
	ctx := stream.Context()
	if id, ok := node.CallerFrom(ctx); !ok || id.Role != identity.RoleGateway {
		return errcode.Status(errcode.Unauthorized, "only the gateway may forward diagnostics")
	}
	if !s.Elected() {
		return errcode.Status(errcode.OwnershipLost, "this replica does not lead; forwarded requests are not forwarded again")
	}
	svc, err := identity.Parse(env.GetService())
	if err != nil || svc.Role != identity.RoleService || svc.Cell != s.Cell {
		return errcode.Status(errcode.Unauthorized, "forwarded request names no service identity of this cell")
	}
	if err := s.Allowlist.Check(svc); err != nil {
		return err
	}
	now := s.now()
	if !env.GetReceivedAt().IsValid() || env.GetReceivedAt().AsTime().After(now.Add(maxForwardSkew)) {
		return errcode.Status(errcode.InvalidQuery, "forwarded request has no valid receipt time")
	}
	if !env.GetDeadline().IsValid() {
		return errcode.Status(errcode.InvalidQuery, "forwarded request has no deadline")
	}
	canonical, deadline, err := s.validate(ctx, env.GetRequest(), env.GetReceivedAt().AsTime(), now)
	if err != nil {
		return err
	}
	if d := env.GetDeadline().AsTime(); d.Before(deadline) {
		deadline = d
	}
	if !now.Before(deadline) {
		return errcode.Status(errcode.DeadlineExceeded, "forwarded request's deadline has passed")
	}
	return s.execute(canonical, deadline)
}

// serviceCaller returns the authenticated service identity of a call.
func serviceCaller(ctx context.Context) (identity.ID, error) {
	id, ok := node.CallerFrom(ctx)
	if !ok || id.Role != identity.RoleService {
		return identity.ID{}, errcode.Status(errcode.Unauthorized,
			"only service identities may call the Looking Glass service")
	}
	return id, nil
}

// validate checks a request's version, cell, attribution, expiration, query
// and node selection before any work, and returns it with its query in
// canonical form and its effective deadline: the earliest of its expiration
// and ctx's deadline. received is the gateway's first receipt, from which
// the expiration bound is measured; now is this replica's current time.
func (s *Service) validate(
	ctx context.Context, req *servicev1.RunDiagnosticRequest, received, now time.Time,
) (*servicev1.RunDiagnosticRequest, time.Time, error) {
	if req.GetApiMajor() != ServiceAPIMajor {
		return nil, time.Time{}, errcode.Status(errcode.VersionUnsupported,
			fmt.Sprintf("API major %d is not served", req.GetApiMajor()))
	}
	if req.GetCell() != s.Cell {
		return nil, time.Time{}, errcode.Status(errcode.Unauthorized, "request names another cell")
	}
	if !projectIDPattern.MatchString(req.GetProjectId()) {
		return nil, time.Time{}, errcode.Status(errcode.InvalidQuery, "project_id must be 1 to 128 bytes of [A-Za-z0-9._:-]")
	}
	if !requestIDPattern.MatchString(req.GetRequestId()) {
		return nil, time.Time{}, errcode.Status(errcode.InvalidQuery, "request_id must be a lowercase UUID")
	}
	if !req.GetExpiresAt().IsValid() {
		return nil, time.Time{}, errcode.Status(errcode.InvalidQuery, "expires_at is required")
	}
	expires := req.GetExpiresAt().AsTime()
	if !expires.After(now) {
		return nil, time.Time{}, errcode.Status(errcode.DeadlineExceeded, "request has expired")
	}
	if expires.After(received.Add(MaxServiceRequestLifetime)) {
		return nil, time.Time{}, errcode.Status(errcode.InvalidQuery,
			fmt.Sprintf("expires_at is more than %s after receipt", MaxServiceRequestLifetime))
	}
	q, err := serviceQuery(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := checkNodes(req.GetNodes()); err != nil {
		return nil, time.Time{}, err
	}
	out := proto.CloneOf(req)
	out.Query = node.QueryToProto(q)
	deadline := expires
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return out, deadline, nil
}

// serviceQuery canonicalizes a request's query and refuses any type the
// service may not request, and any probe target that is not a numeric
// address.
func serviceQuery(req *servicev1.RunDiagnosticRequest) (query.Query, error) {
	if req.GetQuery() == nil {
		return query.Query{}, errcode.Status(errcode.InvalidQuery, "query is required")
	}
	q := node.QueryFromProto(req.GetQuery())
	if !serviceQueryTypes[q.Type] {
		return query.Query{}, errcode.Status(errcode.InvalidQuery, "query type is not available to the service")
	}
	q, err := query.Canonicalize(q)
	if err != nil {
		return query.Query{}, errcode.FromError(err)
	}
	if q.Type.Probe() {
		if _, err := query.ResolvedProbe(q); err != nil {
			return query.Query{}, errcode.FromError(err)
		}
	}
	return q, nil
}

func checkNodes(nodes []string) error {
	if len(nodes) > MaxServiceNodes {
		return errcode.Status(errcode.InvalidQuery, fmt.Sprintf("at most %d nodes may be selected", MaxServiceNodes))
	}
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if n == "" || len(n) > 253 || seen[n] {
			return errcode.Status(errcode.InvalidQuery, "node names must be unique and non-empty")
		}
		seen[n] = true
	}
	return nil
}

// forward hands a validated request to the leader once, with this replica's
// gateway identity, and relays its events.
func (s *Service) forward(
	ctx context.Context, caller identity.ID, req *servicev1.RunDiagnosticRequest, received, deadline time.Time,
	stream grpc.ServerStreamingServer[servicev1.DiagnosticEvent],
) error {
	if s.Leader == nil {
		return errcode.Status(errcode.OwnershipLost, "this replica does not lead and cannot forward")
	}
	conn, err := s.Leader.LeaderConn(ctx)
	if err != nil {
		return errcode.Status(errcode.OwnershipLost, err.Error())
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	events, err := forwardv1.NewForwardServiceClient(conn).ForwardDiagnostic(ctx, &forwardv1.ForwardDiagnosticRequest{
		Service:    caller.URI(),
		Request:    req,
		ReceivedAt: timestamppb.New(received),
		Deadline:   timestamppb.New(deadline),
	})
	if err != nil {
		return err
	}
	for {
		ev, err := events.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
}

// execute runs a validated request on the leader. Customer execution is not
// enabled in any cell yet.
func (s *Service) execute(_ *servicev1.RunDiagnosticRequest, deadline time.Time) error {
	if !s.now().Before(deadline) {
		return errcode.Status(errcode.DeadlineExceeded, "request's deadline has passed")
	}
	return errcode.Status(errcode.ServiceDisabled, "this cell does not execute Looking Glass service diagnostics")
}
