// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package node is the fabric-api node sidecar: the FabricService that runs
// beside FRR in each fabric-router pod, reads FRR over its vty sockets, and
// sends ICMP probes from the node's fabric loopback.
//
// Every call, federated or operator, passes the same checks in order: the
// caller's identity, the request's shape and canonical query, the node name,
// the absolute expiration, the enabled query types, duplicate suppression,
// then the node's execution budgets. One deadline, fixed before any queueing,
// bounds the whole call.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/index"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
)

// FRR runs a command against an FRR daemon. *frr.VTY implements it.
type FRR interface {
	Run(ctx context.Context, cmd frr.Command) (frr.Response, error)
}

// Prober runs ICMP probes. *probe.Prober implements it.
type Prober interface {
	Ping(ctx context.Context, src, dst netip.Addr, opts probe.Options) (*fabricv1.PingResult, error)
	Traceroute(ctx context.Context, src, dst netip.Addr, opts probe.Options) (*fabricv1.TracerouteResult, error)
}

// Defaults for Config's zero fields.
const (
	DefaultMaxConcurrent    = 4
	DefaultMaxExpensive     = 1
	DefaultMaxActiveProbes  = 2
	DefaultPacketRate       = 20
	DefaultPacketBurst      = 5
	DefaultBreakerCooldown  = 10 * time.Minute
	DefaultDedupEntries     = 1024
	DefaultDedupBytes       = 32 << 20
	DefaultIdentityInterval = 60 * time.Second
)

// Config configures a Server.
type Config struct {
	// NodeName is this node; requests naming another node are refused.
	NodeName string
	// Site is reported by Info.
	Site string
	// FRR reads FRR state.
	FRR FRR
	// Prober sends probes.
	Prober Prober
	// ProbeSources are the per-family probe source addresses, at most one
	// per family. A family with none reports ProbeSourceUnavailable.
	ProbeSources []netip.Addr
	// PublicPolicy applies to the gateway identity, OperatorPolicy to
	// operator identities. Only OperatorPolicy may carry Allow exceptions.
	PublicPolicy   query.DestinationPolicy
	OperatorPolicy query.DestinationPolicy
	// ExpensiveEnabled enables AS-path, community and large-community
	// searches. They are release-gated on full-table load tests; until
	// enabled, such requests get QueryTypeUnavailable.
	ExpensiveEnabled bool
	// Ceilings bounds every request's budgets; zero fields take
	// query.Ceilings.
	Ceilings query.Budgets
	// MaxConcurrent bounds Execute calls running at once; later calls wait
	// within their deadline.
	MaxConcurrent int
	// MaxExpensive bounds concurrent expensive searches. There is no queue:
	// a search arriving while the budget is full gets NodeBusy.
	MaxExpensive int
	// MaxActiveProbes bounds concurrent probes, also without a queue.
	MaxActiveProbes int
	// PacketRate and PacketBurst pace every probe packet this node sends.
	PacketRate  float64
	PacketBurst int
	// BreakerCooldown is how long expensive searches stay suspended after
	// one times out, since a cancelled client does not stop bgpd's scan.
	BreakerCooldown time.Duration
	// DedupEntries and DedupBytes bound the duplicate-suppression cache.
	DedupEntries int
	DedupBytes   int
	// IdentityInterval is the time between FRR version/router-ID reads.
	IdentityInterval time.Duration
	// Index, when set, answers AS-path, community and large-community
	// searches from a local copy of bgpd's Loc-RIB instead of FRR's own
	// table scans, which a full-table load test showed starve bgpd. Searches
	// are refused until the index has the full table; they never fall back
	// to scans.
	Index *index.Index
	// Credentials reports whether mTLS credentials are loaded; nil means
	// always loaded.
	Credentials interface{ Err() error }
	// Metrics receives instrumentation; nil disables it.
	Metrics *Metrics
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time
}

// state is what the node last read about its own FRR.
type state struct {
	version  frr.Version
	frrErr   error
	routerID string
	asn      uint32
	read     bool
	readAt   time.Time
}

// retryUnavailable bounds how often a request re-reads FRR while it is
// unreachable.
const retryUnavailable = time.Second

// transient reports whether err may clear on its own as soon as FRR's
// daemons are back, such as a missing socket while bgpd starts.
func transient(err error) bool {
	c := frr.CodeOf(err)
	return c == frr.CodeUnavailable || c == frr.CodeTimeout
}

// Server implements fabricv1.FabricServiceServer.
type Server struct {
	fabricv1.UnimplementedFabricServiceServer

	cfg       Config
	sem       chan struct{}
	expensive chan struct{}
	probes    chan struct{}
	limiter   *rate.Limiter
	dedup     *dedupCache

	mu           sync.RWMutex
	st           state
	breakerUntil time.Time
	refreshMu    sync.Mutex
	refreshCh    chan struct{}
}

// NewServer validates cfg, applies defaults and returns a Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("node name is required")
	}
	if cfg.FRR == nil || cfg.Prober == nil {
		return nil, errors.New("FRR and Prober are required")
	}
	if len(cfg.PublicPolicy.Allow) > 0 {
		return nil, errors.New("the public destination policy may not carry allow exceptions")
	}
	seen := map[bool]bool{}
	for _, a := range cfg.ProbeSources {
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() {
			return nil, fmt.Errorf("probe source %s is not a usable address", a)
		}
		if seen[a.Is4()] {
			return nil, errors.New("more than one probe source for one address family")
		}
		seen[a.Is4()] = true
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&cfg.MaxConcurrent, DefaultMaxConcurrent)
	def(&cfg.MaxExpensive, DefaultMaxExpensive)
	def(&cfg.MaxActiveProbes, DefaultMaxActiveProbes)
	def(&cfg.PacketBurst, DefaultPacketBurst)
	def(&cfg.DedupEntries, DefaultDedupEntries)
	def(&cfg.DedupBytes, DefaultDedupBytes)
	if cfg.PacketRate <= 0 {
		cfg.PacketRate = DefaultPacketRate
	}
	if cfg.BreakerCooldown <= 0 {
		cfg.BreakerCooldown = DefaultBreakerCooldown
	}
	if cfg.IdentityInterval <= 0 {
		cfg.IdentityInterval = DefaultIdentityInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Ceilings = clampTo(cfg.Ceilings, query.Ceilings)
	s := &Server{
		cfg:       cfg,
		sem:       make(chan struct{}, cfg.MaxConcurrent),
		expensive: make(chan struct{}, cfg.MaxExpensive),
		probes:    make(chan struct{}, cfg.MaxActiveProbes),
		limiter:   rate.NewLimiter(rate.Limit(cfg.PacketRate), cfg.PacketBurst),
		dedup:     newDedupCache(cfg.DedupEntries, cfg.DedupBytes, cfg.Now),
		refreshCh: make(chan struct{}, 1),
	}
	if cfg.Metrics != nil {
		s.dedup.hits = cfg.Metrics.dedupHits.Inc
	}
	return s, nil
}

// clampTo lowers b's fields to ceiling, filling zeros from it.
func clampTo(b, ceiling query.Budgets) query.Budgets {
	c := func(v, max int) int {
		if v <= 0 || v > max {
			return max
		}
		return v
	}
	return query.Budgets{
		MaxNodes:              c(b.MaxNodes, ceiling.MaxNodes),
		MaxNodeResponseBytes:  c(b.MaxNodeResponseBytes, ceiling.MaxNodeResponseBytes),
		MaxObjectBytes:        c(b.MaxObjectBytes, ceiling.MaxObjectBytes),
		MaxPrefixes:           c(b.MaxPrefixes, ceiling.MaxPrefixes),
		MaxPathsPerPrefix:     c(b.MaxPathsPerPrefix, ceiling.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: c(b.MaxCommunitiesPerPath, ceiling.MaxCommunitiesPerPath),
	}
}

// requestID is the accepted request ID syntax: a Kubernetes-UID-like token.
var requestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// QueryFromProto converts a wire query into the query package's form.
func QueryFromProto(q *fabricv1.Query) query.Query {
	out := query.Query{Target: q.GetTarget()}
	switch q.GetType() {
	case fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP:
		out.Type = query.TypeRouteLookup
	case fabricv1.QueryType_QUERY_TYPE_AS_PATH:
		out.Type = query.TypeASPath
	case fabricv1.QueryType_QUERY_TYPE_COMMUNITY:
		out.Type = query.TypeCommunity
	case fabricv1.QueryType_QUERY_TYPE_LARGE_COMMUNITY:
		out.Type = query.TypeLargeCommunity
	case fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY:
		out.Type = query.TypeBGPSummary
	case fabricv1.QueryType_QUERY_TYPE_PING:
		out.Type = query.TypePing
	case fabricv1.QueryType_QUERY_TYPE_TRACEROUTE:
		out.Type = query.TypeTraceroute
	}
	switch q.GetAddressFamily() {
	case fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4:
		out.AddressFamily = query.IPv4
	case fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6:
		out.AddressFamily = query.IPv6
	}
	return out
}

// QueryToProto converts a query into its wire form.
func QueryToProto(q query.Query) *fabricv1.Query {
	out := &fabricv1.Query{Target: q.Target}
	switch q.Type {
	case query.TypeRouteLookup:
		out.Type = fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP
	case query.TypeASPath:
		out.Type = fabricv1.QueryType_QUERY_TYPE_AS_PATH
	case query.TypeCommunity:
		out.Type = fabricv1.QueryType_QUERY_TYPE_COMMUNITY
	case query.TypeLargeCommunity:
		out.Type = fabricv1.QueryType_QUERY_TYPE_LARGE_COMMUNITY
	case query.TypeBGPSummary:
		out.Type = fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY
	case query.TypePing:
		out.Type = fabricv1.QueryType_QUERY_TYPE_PING
	case query.TypeTraceroute:
		out.Type = fabricv1.QueryType_QUERY_TYPE_TRACEROUTE
	}
	switch q.AddressFamily {
	case query.IPv4:
		out.AddressFamily = fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4
	case query.IPv6:
		out.AddressFamily = fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6
	}
	return out
}

// Execute runs one query on this node.
func (s *Server) Execute(
	ctx context.Context, req *fabricv1.ExecuteRequest,
) (resp *fabricv1.ExecuteResponse, err error) {
	start := s.cfg.Now()
	typeLabel := req.GetQuery().GetType().String()
	if m := s.cfg.Metrics; m != nil {
		m.inFlight.Inc()
		defer func() {
			m.inFlight.Dec()
			outcome := "OK"
			if err != nil {
				outcome = string(errcode.Of(err))
			}
			m.requests.WithLabelValues(typeLabel, outcome).Inc()
			m.duration.WithLabelValues(typeLabel).Observe(s.cfg.Now().Sub(start).Seconds())
			if resp != nil {
				m.responseBytes.WithLabelValues(typeLabel).Observe(float64(proto.Size(resp)))
				if resp.GetObservation().GetTruncated() {
					m.truncated.WithLabelValues(typeLabel).Inc()
				}
			}
			m.dedupEntries.Set(float64(s.dedup.size()))
		}()
	}

	q, deadline, err := s.validate(ctx, req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	key := dedupKey{requestID: req.GetRequestId(), node: req.GetNode(), operation: req.GetQuery().GetType()}
	args := fmt.Sprintf("%s|%s|%s|%v", q.Type, q.AddressFamily, q.Target, req.GetBudgets().String())
	policy := s.policyFor(ctx)
	return s.dedup.do(ctx, key, args, req.GetExpiresAt().AsTime(), func() (*fabricv1.ExecuteResponse, error) {
		return s.execute(ctx, q, effectiveBudgets(req.GetBudgets(), s.cfg.Ceilings), policy)
	})
}

// validate checks a request and returns its canonical query and the
// absolute deadline that bounds it, queueing included.
func (s *Server) validate(ctx context.Context, req *fabricv1.ExecuteRequest) (query.Query, time.Time, error) {
	if !requestID.MatchString(req.GetRequestId()) {
		return query.Query{}, time.Time{}, errcode.Status(errcode.InvalidQuery, "request_id is missing or malformed")
	}
	if req.GetNode() != s.cfg.NodeName {
		return query.Query{}, time.Time{}, errcode.Status(errcode.WrongNode,
			fmt.Sprintf("request is for node %q, this is %q", req.GetNode(), s.cfg.NodeName))
	}
	if req.GetExpiresAt() == nil {
		return query.Query{}, time.Time{}, errcode.Status(errcode.InvalidQuery, "expires_at is required")
	}
	now := s.cfg.Now()
	expires := req.GetExpiresAt().AsTime()
	if !expires.After(now) {
		return query.Query{}, time.Time{}, errcode.Status(errcode.Expired, "request expired at "+expires.Format(time.RFC3339))
	}
	if expires.Sub(now) > query.MaxRequestLifetime {
		return query.Query{}, time.Time{}, errcode.Status(errcode.InvalidQuery,
			fmt.Sprintf("expires_at is more than %s away", query.MaxRequestLifetime))
	}
	in := QueryFromProto(req.GetQuery())
	q, err := query.Canonicalize(in)
	if err != nil {
		return query.Query{}, time.Time{}, errcode.FromError(err)
	}
	if q != in {
		return query.Query{}, time.Time{}, errcode.Status(errcode.InvalidQuery,
			fmt.Sprintf("query is not canonical (canonical form %+v)", q))
	}
	if q.Type.Expensive() {
		if !s.cfg.ExpensiveEnabled {
			return query.Query{}, time.Time{}, errcode.Status(errcode.QueryTypeUnavailable,
				string(q.Type)+" searches are not enabled on this node")
		}
		if reason := s.searchUnavailable(); reason != "" {
			return query.Query{}, time.Time{}, errcode.Status(errcode.QueryTypeUnavailable, reason)
		}
	}
	deadline := now.Add(query.MaxNodeExecution)
	if expires.Before(deadline) {
		deadline = expires
	}
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return q, deadline, nil
}

// policyFor returns the destination policy for the caller in ctx: the
// operator policy for an operator identity, the public policy otherwise.
func (s *Server) policyFor(ctx context.Context) query.DestinationPolicy {
	if id, ok := CallerFrom(ctx); ok && id.Role == identity.RoleOperator {
		return s.cfg.OperatorPolicy
	}
	return s.cfg.PublicPolicy
}

// execute runs a validated query within the node's budgets.
func (s *Server) execute(
	ctx context.Context, q query.Query, b budgets, policy query.DestinationPolicy,
) (*fabricv1.ExecuteResponse, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, errcode.Status(errcode.NodeBusy, "deadline passed waiting for an execution slot")
	}
	if q.Type.Expensive() {
		select {
		case s.expensive <- struct{}{}:
			defer func() { <-s.expensive }()
		default:
			return nil, errcode.Status(errcode.NodeBusy, "an expensive search is already running on this node")
		}
	}

	started := s.cfg.Now()
	obs := &fabricv1.Observation{Node: s.cfg.NodeName, SampleTime: timestamppb.New(started)}
	var err error
	if q.Type.Probe() {
		err = s.runProbe(ctx, q, policy, obs)
	} else {
		err = s.runFRR(ctx, q, b, obs)
	}
	if err != nil {
		return nil, errcode.FromError(err)
	}
	st := s.state()
	obs.RouterId, obs.Asn, obs.FrrVersion = st.routerID, st.asn, st.version.Raw
	obs.Duration = durationpb.New(s.cfg.Now().Sub(started))
	resp := &fabricv1.ExecuteResponse{Observation: obs}
	if err := fitResponse(resp, b.maxResponseBytes); err != nil {
		return nil, err
	}
	return resp, nil
}

// runFRR answers a lookup, search or summary from FRR.
func (s *Server) runFRR(ctx context.Context, q query.Query, b budgets, obs *fabricv1.Observation) error {
	if q.Type.Expensive() && s.cfg.Index != nil {
		return s.runIndexed(q, b, obs)
	}
	if err := s.frrReady(ctx); err != nil {
		return err
	}
	switch {
	case q.Type == query.TypeBGPSummary:
		cmd, err := frr.SummaryCommand(q.AddressFamily)
		if err != nil {
			return err
		}
		resp, err := s.run(ctx, cmd)
		if err != nil {
			return err
		}
		sum, err := frr.ParseSummary(resp)
		if err != nil {
			return err
		}
		obs.Result = &fabricv1.Observation_Summary{Summary: summaryProto(sum)}
		return nil

	case q.Type == query.TypeRouteLookup:
		cmd, err := frr.LookupCommand(q)
		if err != nil {
			return err
		}
		resp, err := s.run(ctx, cmd)
		if err != nil {
			return err
		}
		route, err := frr.ParseLookup(resp)
		if err != nil {
			return err
		}
		kind := fabricv1.LookupKind_LOOKUP_KIND_EXACT
		if query.Lookup(q) == query.LookupLongestMatch {
			kind = fabricv1.LookupKind_LOOKUP_KIND_LONGEST_MATCH
		}
		result := &fabricv1.RouteResult{LookupKind: kind}
		matched := uint32(0)
		if route != nil {
			matched = 1
			po, truncated := prefixObservation(*route, b)
			obs.Truncated = obs.Truncated || truncated
			po.Installation = s.installation(ctx, route.Prefix)
			result.Prefixes = append(result.Prefixes, po)
		}
		obs.Matched, obs.MatchedIsExact = &matched, true
		obs.Result = &fabricv1.Observation_Routes{Routes: result}
		return nil

	case q.Type.Expensive():
		cmd, err := frr.SearchCommand(q)
		if err != nil {
			return err
		}
		resp, err := s.run(ctx, cmd)
		if err != nil {
			if frr.CodeOf(err) == frr.CodeTimeout {
				s.tripBreaker()
			}
			return err
		}
		res, err := frr.ParseSearch(resp)
		if err != nil {
			return err
		}
		matched := uint32(len(res.Routes))
		obs.Matched, obs.MatchedIsExact = &matched, true
		result := &fabricv1.RouteResult{LookupKind: fabricv1.LookupKind_LOOKUP_KIND_SEARCH}
		for i, r := range res.Routes {
			if i == b.maxPrefixes {
				obs.Truncated = true
				break
			}
			po, truncated := prefixObservation(r, b)
			obs.Truncated = obs.Truncated || truncated
			result.Prefixes = append(result.Prefixes, po)
		}
		obs.Result = &fabricv1.Observation_Routes{Routes: result}
		return nil
	}
	return errcode.Status(errcode.InvalidQuery, "unsupported query type "+string(q.Type))
}

// searchUnavailable returns why expensive searches cannot run now, or "".
func (s *Server) searchUnavailable() string {
	switch {
	case !s.cfg.ExpensiveEnabled:
		return "AS-path and community searches are not enabled on this node"
	case s.cfg.Index != nil:
		if !s.cfg.Index.State().Synced {
			return "the search index has not received bgpd's full table yet"
		}
	default:
		if until := s.breaker(); !until.IsZero() {
			return "expensive searches are suspended until " + until.Format(time.RFC3339) + " after a scan timed out"
		}
	}
	return ""
}

// runIndexed answers a search from the index. Each prefix carries its
// selected path only, and the result reports the index's freshness.
func (s *Server) runIndexed(q query.Query, b budgets, obs *fabricv1.Observation) error {
	res, err := s.cfg.Index.Search(q, b.maxPrefixes)
	if err != nil {
		if errors.Is(err, index.ErrNotSynced) {
			return errcode.Status(errcode.QueryTypeUnavailable, err.Error())
		}
		return errcode.Status(errcode.InvalidQuery, err.Error())
	}
	matched := uint32(res.Matched)
	obs.Matched, obs.MatchedIsExact = &matched, true
	obs.Truncated = res.Matched > len(res.Routes)
	result := &fabricv1.RouteResult{LookupKind: fabricv1.LookupKind_LOOKUP_KIND_SEARCH, Index: indexStateProto(res.State)}
	for _, r := range res.Routes {
		po, truncated := prefixObservation(r, b)
		obs.Truncated = obs.Truncated || truncated
		result.Prefixes = append(result.Prefixes, po)
	}
	obs.Result = &fabricv1.Observation_Routes{Routes: result}
	return nil
}

func indexStateProto(st index.State) *fabricv1.IndexState {
	out := &fabricv1.IndexState{Version: st.Version, Routes: uint64(st.Routes)}
	if !st.SyncedAt.IsZero() {
		out.SyncedAt = timestamppb.New(st.SyncedAt)
	}
	if !st.LastUpdate.IsZero() {
		out.LastUpdate = timestamppb.New(st.LastUpdate)
	}
	return out
}

// installation reads zebra's evidence for prefix. A failure is recorded in
// the evidence; the BGP answer stands.
func (s *Server) installation(ctx context.Context, prefix string) *fabricv1.Installation {
	sampled := timestamppb.New(s.cfg.Now())
	fail := func(err error) *fabricv1.Installation {
		return &fabricv1.Installation{SampleTime: sampled, ErrorCode: string(errcode.Of(errcode.FromError(err))),
			ErrorMessage: errcode.Message(err)}
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return fail(err)
	}
	cmd, err := frr.RouteCommand(p)
	if err != nil {
		return fail(err)
	}
	resp, err := s.run(ctx, cmd)
	if err != nil {
		return fail(err)
	}
	inst, err := frr.ParseInstallation(resp, prefix)
	if err != nil {
		return fail(err)
	}
	out := installationProto(inst)
	out.SampleTime = sampled
	return out
}

// run sends a command and asks for an identity refresh when FRR is
// unreachable, since a daemon restart may have changed its version.
func (s *Server) run(ctx context.Context, cmd frr.Command) (frr.Response, error) {
	resp, err := s.cfg.FRR.Run(ctx, cmd)
	if frr.CodeOf(err) == frr.CodeUnavailable {
		s.RequestRefresh()
	}
	return resp, err
}

// runProbe sends a ping or traceroute from this node's source for the
// query's family.
func (s *Server) runProbe(
	ctx context.Context, q query.Query, policy query.DestinationPolicy, obs *fabricv1.Observation,
) error {
	dst, err := query.ResolvedProbe(q)
	if err != nil {
		return err
	}
	if err := policy.Check(dst); err != nil {
		return err
	}
	var src netip.Addr
	for _, a := range s.cfg.ProbeSources {
		if a.Is4() == dst.Is4() {
			src = a
		}
	}
	if !src.IsValid() {
		return errcode.Status(errcode.ProbeSourceUnavailable, "this node has no "+string(q.AddressFamily)+" probe source")
	}
	select {
	case s.probes <- struct{}{}:
		defer func() { <-s.probes }()
	default:
		return errcode.Status(errcode.NodeBusy, "the node's probe budget is full")
	}
	opts := probe.Options{Limiter: packetLimiter{s}}
	if q.Type == query.TypePing {
		res, err := s.cfg.Prober.Ping(ctx, src, dst, opts)
		if err != nil {
			return err
		}
		obs.Result = &fabricv1.Observation_Ping{Ping: res}
		return nil
	}
	res, err := s.cfg.Prober.Traceroute(ctx, src, dst, opts)
	if err != nil {
		return err
	}
	obs.Result = &fabricv1.Observation_Traceroute{Traceroute: res}
	return nil
}

// packetLimiter paces probe packets through the node-wide rate limiter and
// counts them.
type packetLimiter struct{ s *Server }

func (l packetLimiter) Wait(ctx context.Context) error {
	if err := l.s.limiter.Wait(ctx); err != nil {
		return err
	}
	if m := l.s.cfg.Metrics; m != nil {
		m.probePackets.Inc()
	}
	return nil
}

// breaker returns when expensive searches resume, or zero when they are not
// suspended.
func (s *Server) breaker() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Now().Before(s.breakerUntil) {
		return s.breakerUntil
	}
	return time.Time{}
}

func (s *Server) tripBreaker() {
	s.mu.Lock()
	s.breakerUntil = s.cfg.Now().Add(s.cfg.BreakerCooldown)
	s.mu.Unlock()
	slog.Warn("suspending expensive searches after a scan timed out", "until", s.breakerUntil)
	if m := s.cfg.Metrics; m != nil {
		m.breakerOpen.Set(1)
		time.AfterFunc(s.cfg.BreakerCooldown, func() {
			if s.breaker().IsZero() {
				m.breakerOpen.Set(0)
			}
		})
	}
}

// frrReady returns nil when FRR was last read at a supported version,
// reading it first if it never has been.
func (s *Server) frrReady(ctx context.Context) error {
	// Read FRR now if it never has been, or if the last read found it
	// unreachable: the daemons may have come up since, and a request must
	// not fail on a stale error until the next periodic refresh.
	if st := s.state(); !st.read || (transient(st.frrErr) && s.cfg.Now().Sub(st.readAt) >= retryUnavailable) {
		s.refresh(ctx)
	}
	st := s.state()
	if st.frrErr != nil {
		return st.frrErr
	}
	return nil
}

func (s *Server) state() state {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st
}

// RequestRefresh asks the identity loop to re-read FRR soon.
func (s *Server) RequestRefresh() {
	select {
	case s.refreshCh <- struct{}{}:
	default:
	}
}

// Run re-reads FRR's version, router ID and ASN every IdentityInterval, and
// sooner after FRR becomes unreachable, until ctx ends.
func (s *Server) Run(ctx context.Context) {
	for {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		s.refresh(rctx)
		cancel()
		// While FRR is unreachable, as during its own startup, look again
		// soon rather than after a full interval.
		wait := s.cfg.IdentityInterval
		if transient(s.state().frrErr) {
			wait = min(wait, 5*time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-s.refreshCh:
			// Debounce a burst of failures.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// refresh reads FRR's version, then its router ID and ASN.
func (s *Server) refresh(ctx context.Context) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	next := state{read: true, readAt: s.cfg.Now()}
	defer func() {
		s.mu.Lock()
		prev := s.st
		s.st = next
		s.mu.Unlock()
		if prev.version.Raw != next.version.Raw || (prev.frrErr == nil) != (next.frrErr == nil) {
			slog.Info("FRR state", "version", next.version.Raw, "routerID", next.routerID, "asn", next.asn, "error", next.frrErr)
		}
		if m := s.cfg.Metrics; m != nil {
			outcome := "OK"
			if next.frrErr != nil {
				outcome = string(errcode.Of(errcode.FromError(next.frrErr)))
			}
			m.identityRefresh.WithLabelValues(outcome).Inc()
			m.frrInfo.Reset()
			if next.version.Raw != "" {
				m.frrInfo.WithLabelValues(next.version.Raw, strconv.FormatBool(next.version.Supported())).Set(1)
			}
			m.available.Set(boolGauge(s.availability() == ""))
			if s.cfg.Credentials != nil {
				m.credentialsOK.Set(boolGauge(s.cfg.Credentials.Err() == nil))
			}
		}
	}()

	resp, err := s.cfg.FRR.Run(ctx, frr.VersionCommand())
	if err != nil {
		next.frrErr = err
		return
	}
	v, err := frr.ParseVersion(resp.Output)
	if err != nil {
		next.frrErr = err
		return
	}
	next.version = v
	if err := frr.CheckSupported(v); err != nil {
		next.frrErr = err
		return
	}
	for _, f := range []query.AddressFamily{query.IPv4, query.IPv6} {
		cmd, _ := frr.SummaryCommand(f)
		resp, err := s.cfg.FRR.Run(ctx, cmd)
		if err != nil {
			next.frrErr = err
			return
		}
		sum, err := frr.ParseSummary(resp)
		if err != nil {
			next.frrErr = err
			return
		}
		if sum.RouterID != "" {
			next.routerID, next.asn = sum.RouterID, sum.ASN
			return
		}
	}
}

// availability returns "" when diagnostics are available, else why not.
func (s *Server) availability() string {
	st := s.state()
	switch {
	case !st.read:
		return "FRR has not been read yet"
	case st.frrErr != nil:
		return st.frrErr.Error()
	}
	if s.cfg.Credentials != nil {
		if err := s.cfg.Credentials.Err(); err != nil {
			return "credentials: " + err.Error()
		}
	}
	return ""
}

// Info reports this node's identity and diagnostic availability.
func (s *Server) Info(context.Context, *fabricv1.InfoRequest) (*fabricv1.InfoResponse, error) {
	st := s.state()
	reason := s.availability()
	resp := &fabricv1.InfoResponse{
		Node:                 s.cfg.NodeName,
		Site:                 s.cfg.Site,
		RouterId:             st.routerID,
		Asn:                  st.asn,
		FrrVersion:           st.version.Raw,
		DiagnosticsAvailable: reason == "",
		UnavailableReason:    reason,
	}
	for _, t := range query.Types {
		if t.Expensive() && s.searchUnavailable() != "" {
			continue
		}
		resp.EnabledQueryTypes = append(resp.EnabledQueryTypes, QueryToProto(query.Query{Type: t}).GetType())
	}
	for _, a := range s.cfg.ProbeSources {
		resp.ProbeSources = append(resp.ProbeSources, a.String())
	}
	return resp, nil
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
