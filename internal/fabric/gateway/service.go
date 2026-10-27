// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
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
	// maxSnapshotBytes bounds one serialized snapshot event.
	maxSnapshotBytes = 64 << 10
	// outcomeBuffer is how many finished router outcomes may wait for the
	// stream's writer.
	outcomeBuffer = 2
	// maxOutcomeBytes bounds one serialized outcome event; a larger result
	// is delivered as a ResponseTooLarge failure.
	maxOutcomeBytes = 144 << 10
	// maxCompleteBytes is the output reserved for the terminal event.
	maxCompleteBytes = 64 << 10
	// failureReserve is the output reserved for each router still to
	// report, enough for its failure outcome.
	failureReserve = 1 << 10
	// MaxStreamBytes bounds the serialized events of one stream.
	MaxStreamBytes = 5 << 20
)

// Service feature names, as GetCapabilities advertises and a request's
// required_features names them.
const (
	FeatureRouterOutcomes        = "router-outcomes"
	FeatureTerminalCoverage      = "terminal-coverage"
	FeatureAggregateProbeBudgets = "aggregate-probe-budgets"
)

// features lists the features this gateway serves: aggregate probe budgets
// only while it executes requests under an Admission. Enabling execution
// asserts that every node also requires probe permits, so direct operator
// probes are charged too.
func (s *Service) features() []string {
	f := []string{FeatureRouterOutcomes, FeatureTerminalCoverage}
	if s.enabled() {
		f = append(f, FeatureAggregateProbeBudgets)
	}
	return f
}

// Terminal reasons of a stream's complete event.
const (
	CompleteSucceeded        = "Succeeded"
	CompletePartialResults   = "PartialResults"
	CompleteExecutionFailed  = "ExecutionFailed"
	CompleteNoNodesAvailable = "NoNodesAvailable"
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

// Handshake is the gateway server's handshake check: operators, the
// gateway, nodes and listed service identities may connect.
func (a Allowlist) Handshake(id identity.ID) error {
	switch id.Role {
	case identity.RoleOperator, identity.RoleGateway, identity.RoleNode:
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
// the Looking Glass service, the node-only permit service and the
// gateway-only forwarding service on one mTLS listener. Every call, unary or streaming, is authorized per role from
// GatewayMethods against a peer certificate re-verified on that call, bounded
// by the certificate's expiry, and stripped of forwarding metadata unless
// the gateway identity sent it. Connections, windows and concurrent
// diagnostic calls are bounded per replica (see transportOptions and
// rpcCaps). opts are appended.
func NewServer(
	creds *identity.Credentials, allowlist Allowlist, debug *Debug, service *Service, permits *Permits,
	opts ...grpc.ServerOption,
) *grpc.Server {
	auth := &node.Authorizer{Methods: GatewayMethods, Credentials: creds, Allow: allowlist.Check}
	gs := grpc.NewServer(append(append(transportOptions(credentials.NewTLS(creds.ServerConfig(allowlist.Handshake))),
		grpc.ChainUnaryInterceptor(auth.Unary(), StripForwardingUnary),
		grpc.ChainStreamInterceptor(auth.Stream(), StripForwardingStream, newRPCCaps().stream),
	), opts...)...)
	fabricv1.RegisterFabricGatewayServiceServer(gs, debug)
	servicev1.RegisterLookingGlassServiceServer(gs, service)
	forwardv1.RegisterForwardServiceServer(gs, service.Forwarder())
	permitv1.RegisterPermitServiceServer(gs, permits)
	return gs
}

// LeaderDialer connects to the cell's elected gateway leader.
type LeaderDialer interface {
	LeaderConn(ctx context.Context) (*grpc.ClientConn, error)
}

// Service implements the Looking Glass service. Any replica authenticates
// and validates a request; a follower forwards it once to the leader, which
// validates it again before executing. Unless its Switch is on and it has an
// Admission, the leader refuses a valid request with ServiceDisabled.
type Service struct {
	servicev1.UnimplementedLookingGlassServiceServer

	// Cell is the cell this gateway serves.
	Cell string
	// Switch, while on, makes the leader execute valid requests; turning it
	// off cancels those running. A nil Switch is off.
	Switch *ServiceSwitch
	// Admission enforces the cell's aggregate admission and probe budgets.
	// It must be the Runner's; without it nothing executes.
	Admission *Admission
	// Discoverer takes each request's router inventory; it should read
	// uncached, so the snapshot carries the pod list's resourceVersion.
	Discoverer *Discoverer
	// Runner executes a request on its selected routers.
	Runner *Runner
	// Revision is the commit the gateway was built from.
	Revision string
	// Allowlist names the accepted service identities.
	Allowlist Allowlist
	// Destinations is the public destination policy a probe target must
	// pass before its snapshot. Its Deny should match every node's
	// --deny-prefixes; its Allow must be empty.
	Destinations query.DestinationPolicy
	// Elected reports whether this replica leads.
	Elected func() bool
	// Leader connects a follower to the leader.
	Leader LeaderDialer
	// Metrics, when set, counts requests and their routers' outcomes.
	Metrics *Metrics
	// Now, when set, replaces the wall clock.
	Now func() time.Time

	// outputLimit, when positive, replaces MaxStreamBytes.
	outputLimit int
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// enabled reports whether the service executes requests: its Switch is on
// and it has an Admission.
func (s *Service) enabled() bool {
	on, _ := s.Switch.State()
	return on && s.Admission != nil
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
	return s.capabilities(), nil
}

// capabilities builds the cell's service policy. Its policy revision digests
// every field but the revisions and the generation time.
func (s *Service) capabilities() *servicev1.GetCapabilitiesResponse {
	families := []fabricv1.AddressFamily{
		fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4, fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6,
	}
	resp := &servicev1.GetCapabilitiesResponse{
		Cell:     s.Cell,
		ApiMajor: ServiceAPIMajor,
		Enabled:  s.enabled(),
		Operations: []*servicev1.Operation{
			{Type: fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP, AddressFamilies: families},
			{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY, AddressFamilies: families},
			{Type: fabricv1.QueryType_QUERY_TYPE_PING, AddressFamilies: families},
			{Type: fabricv1.QueryType_QUERY_TYPE_TRACEROUTE, AddressFamilies: families},
		},
		Features: s.features(),
		Limits: &servicev1.Limits{
			MaxRequestLifetime:  durationpb.New(MaxServiceRequestLifetime),
			MaxNodeExecution:    durationpb.New(query.MaxNodeExecution),
			MaxSelectedRouters:  MaxServiceNodes,
			MaxInventoryRouters: MaxInventoryRouters,
			MaxBudgets:          maxServiceBudgets(),
		},
	}
	if slices.Contains(resp.Features, FeatureAggregateProbeBudgets) {
		resp.Limits.Admission = admissionLimits(s.Admission.Limits)
	}
	policy, err := proto.MarshalOptions{Deterministic: true}.Marshal(resp)
	if err == nil {
		sum := sha256.Sum256(policy)
		resp.PolicyRevision = "sha256:" + hex.EncodeToString(sum[:])
	}
	resp.ContractRevision = s.Revision
	resp.GeneratedAt = timestamppb.New(s.now())
	return resp
}

// admissionLimits reports a cell's aggregate limits.
func admissionLimits(l limit.Limits) *servicev1.AdmissionLimits {
	r := func(r limit.Rate) *servicev1.TokenRate {
		return &servicev1.TokenRate{PerSecond: r.PerSecond, Burst: r.Burst}
	}
	return &servicev1.AdmissionLimits{
		RequestCell:             r(l.RequestCell),
		RequestProject:          r(l.RequestProject),
		PacketCell:              r(l.PacketCell),
		PacketProject:           r(l.PacketPrincipal),
		PacketDestinationHost:   r(l.PacketHost),
		PacketDestinationPrefix: r(l.PacketPrefix),
		ActiveJobs:              uint32(l.Slots),
		ProjectActiveJobs:       uint32(l.PrincipalSlots),
		QueuedJobs:              uint32(l.Queue),
		ProjectQueuedJobs:       uint32(l.PrincipalQueue),
		Streams:                 uint32(l.Streams),
		ProjectStreams:          uint32(l.ProjectStreams),
		QueueWait:               durationpb.New(l.QueueWait),
		PingPackets:             limit.PingPackets,
		TraceroutePackets:       limit.TraceroutePackets,
	}
}

// maxServiceBudgets are the largest result budgets a service request may
// ask for: the node ceilings.
func maxServiceBudgets() *fabricv1.Budgets {
	c := query.Ceilings
	return &fabricv1.Budgets{
		MaxResponseBytes:      uint32(c.MaxNodeResponseBytes),
		MaxPrefixes:           uint32(c.MaxPrefixes),
		MaxPathsPerPrefix:     uint32(c.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: uint32(c.MaxCommunitiesPerPath),
	}
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
		s.Metrics.serviceRequest(req, errcode.Of(err))
		return err
	}
	if !s.Elected() {
		return s.forward(ctx, caller, canonical, received, deadline, stream)
	}
	return s.execute(ctx, caller, canonical, deadline, stream.Send)
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
	ctx := stream.Context()
	svc, canonical, deadline, err := f.accept(ctx, env)
	if err != nil {
		// A follower counts only what it refused itself, so the leader
		// counts the forwarded requests it refuses before executing them.
		f.s.Metrics.serviceRequest(env.GetRequest(), errcode.Of(err))
		return err
	}
	return f.s.execute(ctx, svc, canonical, deadline, stream.Send)
}

// accept checks a forwarded request's caller, election, envelope and
// request, and returns its service identity, canonical request and
// effective deadline.
func (f *forwarder) accept(ctx context.Context, env *forwardv1.ForwardDiagnosticRequest,
) (identity.ID, *servicev1.RunDiagnosticRequest, time.Time, error) {
	s := f.s
	fail := func(err error) (identity.ID, *servicev1.RunDiagnosticRequest, time.Time, error) {
		return identity.ID{}, nil, time.Time{}, err
	}
	if id, ok := node.CallerFrom(ctx); !ok || id.Role != identity.RoleGateway {
		return fail(errcode.Status(errcode.Unauthorized, "only the gateway may forward diagnostics"))
	}
	if !s.Elected() {
		return fail(errcode.Status(errcode.OwnershipLost,
			"this replica does not lead; forwarded requests are not forwarded again"))
	}
	svc, err := identity.Parse(env.GetService())
	if err != nil || svc.Role != identity.RoleService || svc.Cell != s.Cell {
		return fail(errcode.Status(errcode.Unauthorized, "forwarded request names no service identity of this cell"))
	}
	if err := s.Allowlist.Check(svc); err != nil {
		return fail(err)
	}
	now := s.now()
	if !env.GetReceivedAt().IsValid() || env.GetReceivedAt().AsTime().After(now.Add(maxForwardSkew)) {
		return fail(errcode.Status(errcode.InvalidQuery, "forwarded request has no valid receipt time"))
	}
	if !env.GetDeadline().IsValid() {
		return fail(errcode.Status(errcode.InvalidQuery, "forwarded request has no deadline"))
	}
	canonical, deadline, err := s.validate(ctx, env.GetRequest(), env.GetReceivedAt().AsTime(), now)
	if err != nil {
		return fail(err)
	}
	if d := env.GetDeadline().AsTime(); d.Before(deadline) {
		deadline = d
	}
	if !now.Before(deadline) {
		return fail(errcode.Status(errcode.DeadlineExceeded, "forwarded request's deadline has passed"))
	}
	return svc, canonical, deadline, nil
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
	q, err := serviceQuery(req, s.Destinations)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := checkNodes(req.GetNodes()); err != nil {
		return nil, time.Time{}, err
	}
	if err := checkBudgets(req.GetBudgets()); err != nil {
		return nil, time.Time{}, err
	}
	if err := checkFeatures(req.GetRequiredFeatures(), s.features()); err != nil {
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
// address or that destinations refuses.
func serviceQuery(req *servicev1.RunDiagnosticRequest, destinations query.DestinationPolicy) (query.Query, error) {
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
		dst, err := query.ResolvedProbe(q)
		if err != nil {
			return query.Query{}, errcode.FromError(err)
		}
		if err := destinations.Check(dst); err != nil {
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

// checkBudgets refuses a budget above its advertised maximum.
func checkBudgets(b *fabricv1.Budgets) error {
	ceiling := maxServiceBudgets()
	if b.GetMaxResponseBytes() > ceiling.GetMaxResponseBytes() || b.GetMaxPrefixes() > ceiling.GetMaxPrefixes() ||
		b.GetMaxPathsPerPrefix() > ceiling.GetMaxPathsPerPrefix() ||
		b.GetMaxCommunitiesPerPath() > ceiling.GetMaxCommunitiesPerPath() {
		return errcode.Status(errcode.InvalidQuery, "a budget exceeds its advertised maximum")
	}
	return nil
}

// checkFeatures refuses a required feature this gateway does not serve,
// known or not.
func checkFeatures(required, served []string) error {
	for _, f := range required {
		if !slices.Contains(served, f) {
			return errcode.Status(errcode.VersionUnsupported, "a required feature is not available")
		}
	}
	return nil
}

// forward hands a validated request to the leader once, with this replica's
// gateway identity, and relays its events under the same write bound as the
// leader's. A forwarded call that fails is never forwarded again. The
// leader counts the request; this replica counts it only when no leader
// could be reached.
func (s *Service) forward(
	ctx context.Context, caller identity.ID, req *servicev1.RunDiagnosticRequest, received, deadline time.Time,
	stream grpc.ServerStreamingServer[servicev1.DiagnosticEvent],
) error {
	if s.Leader == nil {
		s.Metrics.serviceRequest(req, errcode.OwnershipLost)
		return errcode.Status(errcode.OwnershipLost, "this replica does not lead and cannot forward")
	}
	conn, err := s.Leader.LeaderConn(ctx)
	if err != nil {
		s.Metrics.serviceRequest(req, errcode.OwnershipLost)
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
	w := newEventWriter(stream.Send)
	defer w.close()
	if err := relay(events.Recv, w); !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// execute runs a validated request on the leader and sends its events: one
// snapshot of the cell's routers before any router executes, each selected
// router's outcome as it finishes, and the terminal coverage. Before
// discovery it confirms the election, charges the cell's and the project's
// request tokens, registers the attempt key and opens a live stream; after
// discovery it reserves queue capacity for every selected router at once,
// before the snapshot is sent. Events are written by one writer; finished
// outcomes wait for it in a buffer of outcomeBuffer. A failed write, or a
// write or a hand-off to the buffer blocked for SendBound, cancels every
// router still running and ends the stream without complete; the deadline,
// the loss of the election and the output budget cancel them too, but the
// stream still ends with complete, as it does when the Switch is turned off.
// An outcome larger than
// maxOutcomeBytes is delivered as a ResponseTooLarge failure, and once the
// stream's output budget cannot hold an outcome, that router and every
// router still running fail with OutputLimitExceeded. A failure before the
// snapshot is returned as the call's status; once the snapshot is sent the
// stream ends with complete and status OK, whatever the diagnostic's own
// result.
func (s *Service) execute(
	ctx context.Context, caller identity.ID, req *servicev1.RunDiagnosticRequest, deadline time.Time,
	send func(*servicev1.DiagnosticEvent) error,
) (err error) {
	rec := serviceRecord{started: s.now()}
	defer func() { s.finish(caller, req, &rec, err) }()
	if !s.now().Before(deadline) {
		return errcode.Status(errcode.DeadlineExceeded, "request's deadline has passed")
	}
	adm := s.Admission
	on, offCtx := s.Switch.State()
	if !on || adm == nil || s.Discoverer == nil || s.Runner == nil {
		return errcode.Status(errcode.ServiceDisabled, "this cell does not execute Looking Glass service diagnostics")
	}
	project := req.GetProjectId()
	epochCtx, closeStream, err := adm.admit(ctx, caller, req)
	if err != nil {
		return err
	}
	defer closeStream()

	// sendCtx ends when the stream does, a write fails or the consumer
	// stalls; runCtx also ends at the deadline, when the election is lost,
	// when the service is turned off or when the output budget runs out.
	// Outcomes those cut short still reach the writer, so the consumer can
	// see them while the stream lasts.
	sendCtx, abort := context.WithCancelCause(ctx)
	defer abort(nil)
	ownedCtx, lose := context.WithCancelCause(sendCtx)
	defer lose(nil)
	defer context.AfterFunc(epochCtx, func() { lose(errOwnershipLost) })()
	defer context.AfterFunc(offCtx, func() { lose(errServiceDisabled) })()
	runCtx, cancel := context.WithDeadline(ownedCtx, deadline)
	defer cancel()

	inv, err := s.Discoverer.Inventory(runCtx, req.GetNodes(), MaxServiceNodes, s.now())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		switch {
		case errors.Is(context.Cause(runCtx), errOwnershipLost):
			return errcode.Status(errcode.OwnershipLost, "the election was lost during router discovery")
		case errors.Is(context.Cause(runCtx), errServiceDisabled):
			return errcode.Status(errcode.ServiceDisabled, "the service was disabled during router discovery")
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			return errcode.Status(errcode.DeadlineExceeded, "request's deadline passed during router discovery")
		case runCtx.Err() != nil:
			return errcode.Status(errcode.Cancelled, "request was cancelled during router discovery")
		}
		return errcode.Status(errcode.Internal, "router discovery failed")
	}
	snapshot := snapshotEvent(inv)
	if proto.Size(snapshot) > maxSnapshotBytes {
		return errcode.Status(errcode.InventoryTooLarge, "the cell's router snapshot exceeds its size bound")
	}
	res, err := s.Runner.Executor.Reserve(project, selectedCount(inv.Routers))
	if err != nil {
		err := errcode.Retry(errcode.QueueFull, "the cell's execution queue cannot take this request",
			string(limit.ScopeQueue), time.Second)
		adm.Metrics.refused(project, err)
		return err
	}
	defer res.Release()
	w := newEventWriter(send)
	defer w.close()
	var seq uint64
	out := streamOutput{limit: s.streamLimit(), pending: selectedCount(inv.Routers)}
	next := func(ev *servicev1.DiagnosticEvent) error {
		seq++
		ev.RequestId, ev.Sequence = req.GetRequestId(), seq
		out.used += proto.Size(ev)
		return w.write(ev)
	}
	err = next(&servicev1.DiagnosticEvent{Event: &servicev1.DiagnosticEvent_Snapshot{Snapshot: snapshot}})
	if err != nil {
		return err
	}
	rec.inventory = &inv
	op := serviceOperation(req)
	s.Metrics.serviceOmitted(op, inv.Routers)

	q := node.QueryFromProto(req.GetQuery())
	budgets := req.GetBudgets()
	if budgets == nil {
		budgets = &fabricv1.Budgets{}
	}
	outcomes := make(chan Outcome, outcomeBuffer)
	go func() {
		defer close(outcomes)
		s.Runner.Stream(runCtx, project, req.GetRequestId(), q, inv.Routers, budgets, deadline, res,
			func(o Outcome) {
				t := time.NewTimer(SendBound)
				defer t.Stop()
				select {
				case outcomes <- o:
				case <-sendCtx.Done():
				case <-t.C:
					abort(errConsumerStalled)
				}
			})
	}()
	stop := func(err error) error {
		abort(err)
		for range outcomes {
		}
		return err
	}
	// ended ends the stream once sendCtx has: its consumer is gone or
	// stalled, so no further event is written.
	ended := func() error {
		if errors.Is(context.Cause(sendCtx), errConsumerStalled) {
			return stop(stalledStatus())
		}
		return stop(errcode.Status(errcode.Cancelled, "the stream ended before the request finished"))
	}
	var tally streamCoverage
	for {
		if sendCtx.Err() != nil {
			return ended()
		}
		var o Outcome
		var ok bool
		select {
		case o, ok = <-outcomes:
		case <-sendCtx.Done():
			return ended()
		}
		if !ok {
			break
		}
		ev := out.fit(o, func() { lose(errOutputLimit) })
		tally.add(ev)
		s.Metrics.serviceOutcome(op, ev.Err)
		if err := next(outcomeEvent(ev)); err != nil {
			return stop(err)
		}
	}
	rec.complete = tally.complete(inv, s.now())
	return next(&servicev1.DiagnosticEvent{Event: &servicev1.DiagnosticEvent_Complete{Complete: rec.complete}})
}

// serviceRecord is what finish reports about a request the leader ran.
type serviceRecord struct {
	started time.Time
	// inventory is set once the snapshot is delivered.
	inventory *Inventory
	// complete is the terminal coverage, set before it is sent.
	complete *servicev1.Complete
}

// reasonDeliveryFailed is the reason a request whose stream broke is
// counted and logged with.
const reasonDeliveryFailed = "DeliveryFailed"

// finish counts a request the leader ran and, once its snapshot was
// delivered, logs it: who asked, for which project, its operation, reason
// and coverage counts and how long it took. The log carries no target,
// observation or node error text. A request refused before its snapshot is
// logged only at debug level.
func (s *Service) finish(caller identity.ID, req *servicev1.RunDiagnosticRequest, rec *serviceRecord, err error) {
	reason := reasonDeliveryFailed
	switch {
	case err == nil && rec.complete != nil:
		reason = rec.complete.GetReason()
	case errcode.Typed(err):
		reason = string(errcode.Of(err))
	}
	op := serviceOperation(req)
	elapsed := s.now().Sub(rec.started)
	s.Metrics.serviceRequest(req, errcode.Code(reason))
	if rec.inventory == nil {
		slog.Debug("Looking Glass request refused", "service", caller.Name, "project", req.GetProjectId(),
			"requestID", req.GetRequestId(), labelOperation, op, labelReason, reason)
		return
	}
	if s.Metrics != nil {
		s.Metrics.serviceDuration.WithLabelValues(op).Observe(elapsed.Seconds())
	}
	attrs := []any{
		"service", caller.Name, "project", req.GetProjectId(), "requestID", req.GetRequestId(),
		labelOperation, op, labelReason, reason, "routers", len(rec.inventory.Routers),
		"selected", selectedCount(rec.inventory.Routers), "duration", elapsed,
	}
	if c := rec.complete; c != nil {
		attrs = append(attrs, "successful", c.GetSuccessful(), "failed", c.GetFailed(), "omitted", c.GetOmitted(),
			"truncated", c.GetTruncatedRouters())
	}
	slog.Info("Looking Glass request finished", attrs...)
}

// serviceOperation is a request's operation as a metric label: its query
// type, or Unsupported for one the service does not serve.
func serviceOperation(req *servicev1.RunDiagnosticRequest) string {
	t := node.QueryFromProto(req.GetQuery()).Type
	if !serviceQueryTypes[t] {
		return "Unsupported"
	}
	return string(t)
}

func (s *Service) streamLimit() int {
	if s.outputLimit > 0 {
		return s.outputLimit
	}
	return MaxStreamBytes
}

// streamOutput is a stream's output budget: bytes written so far, and the
// routers still to report, each of which keeps failureReserve of the budget,
// like the terminal event keeps maxCompleteBytes.
type streamOutput struct {
	limit, used, pending int
}

// fit returns o as it can be delivered: a result over maxOutcomeBytes as
// ResponseTooLarge, and a result the remaining budget cannot hold as
// OutputLimitExceeded, calling exhausted so the routers still running stop.
func (b *streamOutput) fit(o Outcome, exhausted func()) Outcome {
	b.pending--
	size := proto.Size(outcomeEvent(o))
	if size > maxOutcomeBytes {
		o.Observation, o.Err = nil, errcode.Status(errcode.ResponseTooLarge, "router's result exceeds its size bound")
		size = proto.Size(outcomeEvent(o))
	}
	if b.used+size+b.pending*failureReserve+maxCompleteBytes > b.limit {
		exhausted()
		o.Observation, o.Err = nil, errcode.Status(errcode.OutputLimitExceeded, "the stream's output budget is exhausted")
	}
	return o
}

func selectedCount(routers []Node) int {
	n := 0
	for _, r := range routers {
		if r.Selected {
			n++
		}
	}
	return n
}

// attemptKey identifies an attempt within its service identity, project
// and cell.
func attemptKey(caller identity.ID, req *servicev1.RunDiagnosticRequest) string {
	return caller.URI() + "|" + req.GetProjectId() + "|" + req.GetRequestId()
}

// requestDigest digests a canonical request's execution arguments: every
// field but its expiration.
func requestDigest(req *servicev1.RunDiagnosticRequest) string {
	args := proto.CloneOf(req)
	args.ExpiresAt = nil
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(args)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func snapshotEvent(inv Inventory) *servicev1.Snapshot {
	out := &servicev1.Snapshot{
		SnapshotId:          inv.ID,
		CapturedAt:          timestamppb.New(inv.CapturedAt),
		ResourceVersion:     inv.ResourceVersion,
		UnscheduledPodCount: uint32(inv.Unscheduled),
	}
	for _, r := range inv.Routers {
		sr := &servicev1.SnapshotRouter{Node: r.Name, Selected: r.Selected, OmittedReason: r.OmittedReason}
		if r.Selected {
			sr.PodUid = r.PodUID
		}
		out.Routers = append(out.Routers, sr)
	}
	return out
}

func outcomeEvent(o Outcome) *servicev1.DiagnosticEvent {
	out := &servicev1.RouterOutcome{Node: o.Node.Name, PodUid: o.Node.PodUID, CompletedAt: timestamppb.New(o.Completed)}
	if o.Err != nil {
		code := errcode.Of(o.Err)
		f := &servicev1.Failure{
			Reason: string(code), Message: failureMessage(code), Scope: errcode.Metadata(o.Err)[errcode.MetadataScope],
		}
		if d, ok := errcode.RetryDelay(o.Err); ok {
			f.RetryDelay = durationpb.New(d)
		}
		out.Result = &servicev1.RouterOutcome_Failure{Failure: f}
	} else {
		out.Result = &servicev1.RouterOutcome_Observation{Observation: o.Observation}
	}
	return &servicev1.DiagnosticEvent{Event: &servicev1.DiagnosticEvent_Outcome{Outcome: out}}
}

// failureMessage is the fixed description of a router failure. Node error
// messages can carry targets or FRR text, so none reaches the service.
func failureMessage(code errcode.Code) string {
	switch code {
	case errcode.NodeUnreachable:
		return "router did not answer"
	case errcode.Timeout:
		return "router did not finish within its execution bound"
	case errcode.QueueTimeout:
		return "router job waited too long for an execution slot"
	case errcode.NodeBusy:
		return "cell execution capacity is full"
	case errcode.DeadlineExceeded:
		return "request deadline passed before the router finished"
	case errcode.Cancelled:
		return "request was cancelled before the router finished"
	case errcode.FRRUnavailable:
		return "router's routing daemon is unavailable"
	case errcode.Throttled:
		return "a probe packet budget is exhausted"
	case errcode.QueueFull:
		return "the cell's execution queue is full"
	case errcode.OwnershipLost:
		return "the gateway lost execution ownership"
	case errcode.LimiterUnavailable:
		return "the cell's limiter is unavailable"
	case errcode.ResponseTooLarge:
		return "router's result exceeds its size bound"
	case errcode.OutputLimitExceeded:
		return "the stream's output budget is exhausted"
	}
	return "router diagnostic failed"
}

// streamCoverage counts a stream's outcomes.
type streamCoverage struct {
	successful, failed, truncated int
	// stopped is the request-level reason, DeadlineExceeded, Cancelled,
	// OwnershipLost or OutputLimitExceeded, that cut a router short, if any.
	stopped errcode.Code
}

func (c *streamCoverage) add(o Outcome) {
	if o.Err == nil {
		c.successful++
		if o.Observation.GetTruncated() {
			c.truncated++
		}
		return
	}
	c.failed++
	switch code := errcode.Of(o.Err); code {
	case errcode.DeadlineExceeded, errcode.Cancelled, errcode.OwnershipLost, errcode.OutputLimitExceeded:
		if c.stopped == "" {
			c.stopped = code
		}
	}
}

// complete returns the terminal coverage. A request cut short by its
// deadline, cancellation, the loss of the election or its output budget
// reports that first; otherwise no selected router
// is NoNodesAvailable, no success ExecutionFailed, and any failure,
// truncation or omission other than NotRequested PartialResults.
func (c *streamCoverage) complete(inv Inventory, now time.Time) *servicev1.Complete {
	out := &servicev1.Complete{
		SnapshotId:       inv.ID,
		FinishedAt:       timestamppb.New(now),
		Expected:         uint32(len(inv.Routers)),
		Successful:       uint32(c.successful),
		Failed:           uint32(c.failed),
		TruncatedRouters: uint32(c.truncated),
	}
	partial := c.failed > 0 || c.truncated > 0
	for _, r := range inv.Routers {
		if !r.Selected {
			out.Omitted++
			partial = partial || r.OmittedReason != OmitNotRequested
		}
	}
	switch {
	case c.stopped != "":
		out.Reason = string(c.stopped)
	case c.successful+c.failed == 0:
		out.Reason = CompleteNoNodesAvailable
	case c.successful == 0:
		out.Reason = CompleteExecutionFailed
	case partial:
		out.Reason = CompletePartialResults
	default:
		out.Reason = CompleteSucceeded
	}
	return out
}
