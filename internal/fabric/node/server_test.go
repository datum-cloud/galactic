// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/index"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
)

const fixtures = "../frr/testdata/frr-10.7"

// Node names and query targets the tests share.
const (
	testNode      = "edge-a"
	testPrefix    = "198.51.100.0/24"
	testASPath    = "^65001"
	testCommunity = "65002:100"
	testPingDst   = "1.1.1.1"
	testLoopback  = "10.255.0.7"
)

// fakeFRR answers commands from the frr package's captured fixtures.
type fakeFRR struct {
	mu        sync.Mutex
	responses map[string]frr.Response
	errs      map[string]error
	delay     time.Duration
	calls     map[string]int
	// block, when set, is waited on before answering.
	block chan struct{}
}

func newFakeFRR(t *testing.T) *fakeFRR {
	t.Helper()
	f := &fakeFRR{responses: map[string]frr.Response{}, errs: map[string]error{}, calls: map[string]int{}}
	for cmd, file := range map[string]string{
		"show version":                                   "version.txt",
		"show bgp ipv4 unicast summary json":             "bgp-summary-ipv4.json",
		"show bgp ipv6 unicast summary json":             "bgp-summary-ipv6.json",
		"show bgp ipv4 unicast 198.51.100.0/24 json":     "bgp-prefix-multipath-ipv4.json",
		"show bgp ipv4 unicast 198.51.100.7 json":        "bgp-addr-lpm-ipv4.json",
		"show bgp ipv4 unicast 8.8.8.8 json":             "bgp-addr-default-ipv4.json",
		"show bgp ipv4 unicast 10.99.0.0/16 json":        "bgp-prefix-absent-ipv4.json",
		"show bgp ipv4 unicast regexp ^65001 json":       "bgp-regexp-ipv4.json",
		"show bgp ipv4 unicast community 65002:100 json": "bgp-community-ipv4.json",
		"show ip route 198.51.100.0/24 json":             "zebra-route-ipv4.json",
		"show ip route 0.0.0.0/0 json":                   "zebra-route-default-ipv4.json",
	} {
		b, err := os.ReadFile(filepath.Join(fixtures, file))
		if err != nil {
			t.Fatal(err)
		}
		f.responses[cmd] = frr.Response{Output: b}
	}
	return f
}

func (f *fakeFRR) set(cmd string, resp frr.Response, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[cmd], f.errs[cmd] = resp, err
}

func (f *fakeFRR) setBlock(block chan struct{}, delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block, f.delay = block, delay
}

func (f *fakeFRR) count(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[cmd]
}

func (f *fakeFRR) Run(ctx context.Context, cmd frr.Command) (frr.Response, error) {
	f.mu.Lock()
	f.calls[cmd.String()]++
	resp, ok := f.responses[cmd.String()]
	err := f.errs[cmd.String()]
	delay, block := f.delay, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return frr.Response{}, &frr.Error{Code: frr.CodeTimeout, Message: "blocked"}
		}
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return frr.Response{}, &frr.Error{Code: frr.CodeTimeout, Message: "slow"}
		}
	}
	if err != nil {
		return frr.Response{}, err
	}
	if !ok {
		return frr.Response{Output: []byte("{}\n"), Warning: true}, nil
	}
	return resp, nil
}

type fakeProber struct {
	calls atomic.Int32
	block chan struct{}
}

func (p *fakeProber) Ping(ctx context.Context, src, dst netip.Addr, opts probe.Options) (*fabricv1.PingResult, error) {
	p.calls.Add(1)
	if p.block != nil {
		<-p.block
	}
	_ = opts.Limiter.Wait(ctx)
	return &fabricv1.PingResult{Source: src.String(), Destination: dst.String(), Sent: 3, Received: 3}, nil
}

func (p *fakeProber) Traceroute(
	_ context.Context, src, dst netip.Addr, _ probe.Options,
) (*fabricv1.TracerouteResult, error) {
	p.calls.Add(1)
	return &fabricv1.TracerouteResult{Source: src.String(), Destination: dst.String(), Reached: true}, nil
}

func newServer(t *testing.T, f *fakeFRR, mod func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		NodeName:       testNode,
		Site:           "dfw",
		FRR:            f,
		Prober:         &fakeProber{},
		ProbeSources:   []netip.Addr{netip.MustParseAddr("10.255.0.1"), netip.MustParseAddr("2001:db8:ff::1")},
		OperatorPolicy: query.DestinationPolicy{Allow: mustPrefixes("10.255.0.0/16")},
		Metrics:        NewMetrics(),
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out, err := query.ParsePrefixes(ss)
	if err != nil {
		panic(err)
	}
	return out
}

var reqSeq atomic.Int32

func request(q query.Query) *fabricv1.ExecuteRequest {
	c, err := query.Canonicalize(q)
	if err != nil {
		panic(err)
	}
	letter := 'a' + reqSeq.Add(1)%26
	return &fabricv1.ExecuteRequest{
		RequestId: "req-" + string(letter) + time.Now().Format("150405.000000000"),
		Node:      testNode,
		Query:     QueryToProto(c),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
	}
}

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if got := errcode.Of(err); got != code {
		t.Fatalf("error = %v (code %q), want %q", err, got, code)
	}
}

func TestSummary(t *testing.T) {
	s := newServer(t, newFakeFRR(t), nil)
	resp, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	if err != nil {
		t.Fatal(err)
	}
	obs := resp.GetObservation()
	if obs.GetNode() != testNode || obs.GetRouterId() != "10.255.0.1" || obs.GetAsn() != 65000 ||
		obs.GetFrrVersion() != "10.7.1_git" {
		t.Errorf("header = %+v", obs)
	}
	sum := obs.GetSummary()
	if sum.GetTotalPeers() != 4 || sum.GetEstablishedPeers() != 3 {
		t.Errorf("summary = %d/%d", sum.GetEstablishedPeers(), sum.GetTotalPeers())
	}
	if obs.Matched != nil || obs.GetMatchedIsExact() {
		t.Error("a summary has no matched count")
	}
}

func TestLookup(t *testing.T) {
	s := newServer(t, newFakeFRR(t), nil)

	resp, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeRouteLookup, Target: testPrefix}))
	if err != nil {
		t.Fatal(err)
	}
	obs := resp.GetObservation()
	routes := obs.GetRoutes()
	if routes.GetLookupKind() != fabricv1.LookupKind_LOOKUP_KIND_EXACT || len(routes.GetPrefixes()) != 1 {
		t.Fatalf("routes = %+v", routes)
	}
	if obs.GetMatched() != 1 || !obs.GetMatchedIsExact() || obs.GetTruncated() {
		t.Errorf("matched = %d exact=%v truncated=%v", obs.GetMatched(), obs.GetMatchedIsExact(), obs.GetTruncated())
	}
	po := routes.GetPrefixes()[0]
	if len(po.GetPaths()) != 2 || !po.GetPaths()[0].GetBest() || po.GetPaths()[1].GetBest() {
		t.Errorf("paths = %+v", po.GetPaths())
	}
	inst := po.GetInstallation()
	if !inst.GetPresent() || inst.GetSampleTime() == nil || inst.GetRoutes()[0].GetProtocol() != "bgp" ||
		inst.GetErrorCode() != "" {
		t.Errorf("installation = %+v", inst)
	}

	lpm, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeRouteLookup, Target: "8.8.8.8"}))
	if err != nil {
		t.Fatal(err)
	}
	r := lpm.GetObservation().GetRoutes()
	if r.GetLookupKind() != fabricv1.LookupKind_LOOKUP_KIND_LONGEST_MATCH ||
		r.GetPrefixes()[0].GetPrefix() != "0.0.0.0/0" {
		t.Errorf("longest match = %+v", r)
	}

	absent, err := s.Execute(context.Background(),
		request(query.Query{Type: query.TypeRouteLookup, Target: "10.99.0.0/16"}))
	if err != nil {
		t.Fatal(err)
	}
	o := absent.GetObservation()
	if o.GetMatched() != 0 || !o.GetMatchedIsExact() || len(o.GetRoutes().GetPrefixes()) != 0 {
		t.Errorf("absent = %+v", o)
	}
}

func TestInstallationFailureKeepsBGPAnswer(t *testing.T) {
	f := newFakeFRR(t)
	f.set("show ip route 198.51.100.0/24 json", frr.Response{},
		&frr.Error{Code: frr.CodeUnavailable, Message: "zebra restarting"})
	s := newServer(t, f, nil)
	resp, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeRouteLookup, Target: testPrefix}))
	if err != nil {
		t.Fatal(err)
	}
	inst := resp.GetObservation().GetRoutes().GetPrefixes()[0].GetInstallation()
	if inst.GetErrorCode() != string(errcode.FRRUnavailable) || inst.GetPresent() {
		t.Errorf("installation = %+v", inst)
	}
}

func TestValidation(t *testing.T) {
	s := newServer(t, newFakeFRR(t), nil)
	ctx := context.Background()
	base := func() *fabricv1.ExecuteRequest { return request(query.Query{Type: query.TypeBGPSummary}) }

	r := base()
	r.Node = "edge-b"
	_, err := s.Execute(ctx, r)
	wantCode(t, err, errcode.WrongNode)

	r = base()
	r.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.Expired)

	r = base()
	r.ExpiresAt = timestamppb.New(time.Now().Add(time.Hour))
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	r = base()
	r.ExpiresAt = nil
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	r = base()
	r.RequestId = "bad id\n"
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	// Not canonical: leading zeros in a community.
	r = base()
	r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP, Target: "2001:DB8::/32",
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6}
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	r = base()
	r.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP, Target: "1.1.1.0/24\nclear bgp *",
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4}
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	r = base()
	r.Query = &fabricv1.Query{}
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)
}

func TestExpensiveGate(t *testing.T) {
	f := newFakeFRR(t)
	q := query.Query{Type: query.TypeASPath, Target: testASPath}

	_, err := newServer(t, f, nil).Execute(context.Background(), request(q))
	wantCode(t, err, errcode.QueryTypeUnavailable)
	if f.count("show bgp ipv4 unicast regexp ^65001 json") != 0 {
		t.Error("a disabled search reached FRR")
	}

	s := newServer(t, f, func(c *Config) { c.ExpensiveEnabled = true })
	resp, err := s.Execute(context.Background(), request(q))
	if err != nil {
		t.Fatal(err)
	}
	obs := resp.GetObservation()
	if obs.GetMatched() != 4 || obs.GetRoutes().GetLookupKind() != fabricv1.LookupKind_LOOKUP_KIND_SEARCH {
		t.Errorf("search = matched %d, %+v", obs.GetMatched(), obs.GetRoutes().GetLookupKind())
	}
	for _, p := range obs.GetRoutes().GetPrefixes() {
		if p.GetInstallation() != nil {
			t.Error("searches carry no installation evidence")
		}
	}
}

func TestBreakerTripsOnTimedOutScan(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, func(c *Config) { c.ExpensiveEnabled = true; c.BreakerCooldown = time.Hour })
	s.refresh(context.Background())
	f.setBlock(nil, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := s.Execute(ctx, request(query.Query{Type: query.TypeCommunity, Target: testCommunity}))
	wantCode(t, err, errcode.Timeout)

	f.setBlock(nil, 0)
	_, err = s.Execute(context.Background(), request(query.Query{Type: query.TypeCommunity, Target: testCommunity}))
	wantCode(t, err, errcode.QueryTypeUnavailable)
	info, _ := s.Info(context.Background(), &fabricv1.InfoRequest{})
	for _, ty := range info.GetEnabledQueryTypes() {
		if ty == fabricv1.QueryType_QUERY_TYPE_COMMUNITY {
			t.Error("Info lists a suspended search type")
		}
	}
	// Cheap queries are unaffected.
	if _, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary})); err != nil {
		t.Errorf("summary during breaker: %v", err)
	}
}

func TestExpensiveNoQueue(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, func(c *Config) { c.ExpensiveEnabled = true })
	// Read FRR's identity before blocking it.
	s.refresh(context.Background())
	block := make(chan struct{})
	f.setBlock(block, 0)

	done := make(chan error, 1)
	go func() {
		_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeASPath, Target: testASPath}))
		done <- err
	}()
	waitFor(t, func() bool { return len(s.expensive) == 1 })
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeCommunity, Target: testCommunity}))
	wantCode(t, err, errcode.NodeBusy)
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrencyWaitsWithinDeadline(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, func(c *Config) { c.MaxConcurrent = 1 })
	s.refresh(context.Background())
	block := make(chan struct{})
	f.setBlock(block, 0)
	go func() { _, _ = s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary})) }()
	waitFor(t, func() bool { return len(s.sem) == 1 })

	// The second call's deadline passes while it waits for the slot.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := s.Execute(ctx, request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.NodeBusy)
	close(block)
}

func TestDeadlineClampedToExpiry(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, nil)
	s.refresh(context.Background())
	f.setBlock(nil, 5*time.Second)
	r := request(query.Query{Type: query.TypeBGPSummary})
	r.ExpiresAt = timestamppb.New(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	_, err := s.Execute(context.Background(), r)
	wantCode(t, err, errcode.Timeout)
	if time.Since(start) > 2*time.Second {
		t.Errorf("ran %v past the request's expiry", time.Since(start))
	}
}

func TestFRRUnavailableAndUnsupported(t *testing.T) {
	f := newFakeFRR(t)
	f.set("show version", frr.Response{}, &frr.Error{Code: frr.CodeUnavailable, Message: "no socket"})
	s := newServer(t, f, nil)
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.FRRUnavailable)
	info, _ := s.Info(context.Background(), &fabricv1.InfoRequest{})
	if info.GetDiagnosticsAvailable() || info.GetUnavailableReason() == "" {
		t.Errorf("info = %+v", info)
	}

	f.set("show version", frr.Response{Output: []byte("FRRouting 10.2_git (x) on Linux\n")}, nil)
	s.refresh(context.Background())
	_, err = s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.FRRVersionUnsupported)

	// Probes do not depend on FRR.
	ping := request(query.Query{Type: query.TypePing, Target: testPingDst})
	if _, err := s.Execute(context.Background(), ping); err != nil {
		t.Errorf("ping with FRR unsupported: %v", err)
	}
}

func TestUnavailableRequestsRefresh(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, nil)
	s.refresh(context.Background())
	f.set("show bgp ipv4 unicast summary json", frr.Response{}, &frr.Error{Code: frr.CodeUnavailable, Message: "restart"})
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.FRRUnavailable)
	select {
	case <-s.refreshCh:
	default:
		t.Error("no refresh requested after FRR became unreachable")
	}
}

func TestDuplicateSuppression(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, nil)
	s.refresh(context.Background())
	block := make(chan struct{})
	f.setBlock(block, 0)
	req := request(query.Query{Type: query.TypeRouteLookup, Target: testPrefix})

	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if _, err := s.Execute(context.Background(), req); err != nil {
				t.Error(err)
			}
		})
	}
	waitFor(t, func() bool { return f.count("show bgp ipv4 unicast 198.51.100.0/24 json") == 1 })
	close(block)
	wg.Wait()
	if _, err := s.Execute(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if n := f.count("show bgp ipv4 unicast 198.51.100.0/24 json"); n != 1 {
		t.Errorf("FRR ran the lookup %d times for one request", n)
	}

	conflict := request(query.Query{Type: query.TypeRouteLookup, Target: "203.0.113.0/24"})
	conflict.RequestId = req.RequestId
	_, err := s.Execute(context.Background(), conflict)
	wantCode(t, err, errcode.DuplicateConflict)
}

func TestDedupEviction(t *testing.T) {
	now := time.Now()
	c := newDedupCache(2, 1<<20, func() time.Time { return now })
	run := 0
	fn := func() (*fabricv1.ExecuteResponse, error) { run++; return &fabricv1.ExecuteResponse{}, nil }
	for i, id := range []string{"a", "b", "c"} {
		_, _ = c.do(context.Background(), dedupKey{requestID: id}, "x", now.Add(time.Minute), fn)
		if run != i+1 {
			t.Fatal("each new key should run")
		}
	}
	if n := c.size(); n != 2 {
		t.Errorf("entries = %d, want ceiling 2", n)
	}
	// "a" was evicted, so it may run again.
	_, _ = c.do(context.Background(), dedupKey{requestID: "a"}, "x", now.Add(time.Minute), fn)
	if run != 4 {
		t.Errorf("evicted key did not rerun")
	}
	// Expired entries are swept.
	now = now.Add(2 * time.Minute)
	_, _ = c.do(context.Background(), dedupKey{requestID: "z"}, "x", now.Add(time.Minute), fn)
	if n := c.size(); n != 1 {
		t.Errorf("entries after expiry = %d", n)
	}
}

func TestShaping(t *testing.T) {
	f := newFakeFRR(t)
	s := newServer(t, f, nil)
	r := request(query.Query{Type: query.TypeRouteLookup, Target: testPrefix})
	r.Budgets = &fabricv1.Budgets{MaxPathsPerPrefix: 1, MaxCommunitiesPerPath: 1}
	resp, err := s.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	obs := resp.GetObservation()
	po := obs.GetRoutes().GetPrefixes()[0]
	if !obs.GetTruncated() || len(po.GetPaths()) != 1 || !po.GetPaths()[0].GetBest() || po.GetTotalPaths() != 2 {
		t.Errorf("paths shaping: truncated=%v paths=%d total=%d", obs.GetTruncated(), len(po.GetPaths()), po.GetTotalPaths())
	}
	p := po.GetPaths()[0]
	if len(p.GetCommunities()) != 1 || p.GetTotalCommunities() != 3 || len(p.GetLargeCommunities()) != 1 {
		t.Errorf("communities shaping: %v (%d)", p.GetCommunities(), p.GetTotalCommunities())
	}
	if obs.GetMatched() != 1 || !obs.GetMatchedIsExact() {
		t.Error("shaping must not change the exact matched count")
	}

	// A search shaped to its prefix budget keeps the exact total.
	s2 := newServer(t, f, func(c *Config) { c.ExpensiveEnabled = true })
	r = request(query.Query{Type: query.TypeASPath, Target: testASPath})
	r.Budgets = &fabricv1.Budgets{MaxPrefixes: 2}
	resp, err = s2.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if o := resp.GetObservation(); len(o.GetRoutes().GetPrefixes()) != 2 || o.GetMatched() != 4 || !o.GetTruncated() {
		t.Errorf("search shaping: %d prefixes, matched %d", len(o.GetRoutes().GetPrefixes()), o.GetMatched())
	}

	// Byte budget: one byte less than the unshaped response.
	full, err := s2.Execute(context.Background(), request(query.Query{Type: query.TypeASPath, Target: testASPath}))
	if err != nil {
		t.Fatal(err)
	}
	r = request(query.Query{Type: query.TypeASPath, Target: testASPath})
	r.Budgets = &fabricv1.Budgets{MaxResponseBytes: uint32(proto.Size(full) - 1)}
	resp, err = s2.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if o := resp.GetObservation(); !o.GetTruncated() || len(o.GetRoutes().GetPrefixes()) >= 4 || o.GetMatched() != 4 {
		t.Errorf("byte shaping: %d prefixes truncated=%v", len(o.GetRoutes().GetPrefixes()), o.GetTruncated())
	}

	r = request(query.Query{Type: query.TypeASPath, Target: testASPath})
	r.Budgets = &fabricv1.Budgets{MaxResponseBytes: 50}
	_, err = s2.Execute(context.Background(), r)
	wantCode(t, err, errcode.ResponseTooLarge)
}

func TestFRRReadCapIsResponseTooLarge(t *testing.T) {
	f := newFakeFRR(t)
	f.set("show bgp ipv4 unicast summary json", frr.Response{}, &frr.Error{Code: frr.CodeResponseTooLarge, Message: "cap"})
	s := newServer(t, f, nil)
	s.refresh(context.Background())
	f.set("show bgp ipv4 unicast summary json", frr.Response{}, &frr.Error{Code: frr.CodeResponseTooLarge, Message: "cap"})
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.ResponseTooLarge)
}

func TestProbePolicy(t *testing.T) {
	prober := &fakeProber{}
	s := newServer(t, newFakeFRR(t), func(c *Config) { c.Prober = prober })
	ctx := context.Background()

	resp, err := s.Execute(ctx, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.GetObservation().GetPing(); p.GetSource() != "10.255.0.1" || p.GetReceived() != 3 {
		t.Errorf("ping = %+v", p)
	}
	tr, err := s.Execute(ctx, request(query.Query{Type: query.TypeTraceroute, Target: "2606:4700::1111"}))
	if err != nil || tr.GetObservation().GetTraceroute().GetSource() != "2001:db8:ff::1" {
		t.Fatalf("traceroute = %+v, %v", tr, err)
	}

	// The gateway (public) may not probe the fabric loopbacks; an operator
	// may, through its narrow exception.
	gwCtx := WithCaller(ctx, identity.Gateway("dfw"))
	opCtx := WithCaller(ctx, identity.Operator("dfw", "lab"))
	_, err = s.Execute(gwCtx, request(query.Query{Type: query.TypePing, Target: testLoopback}))
	wantCode(t, err, errcode.DestinationNotAllowed)
	if _, err := s.Execute(opCtx, request(query.Query{Type: query.TypePing, Target: testLoopback})); err != nil {
		t.Errorf("operator exception: %v", err)
	}
	_, err = s.Execute(opCtx, request(query.Query{Type: query.TypePing, Target: "192.168.1.1"}))
	wantCode(t, err, errcode.DestinationNotAllowed)

	// A hostname never reaches a node.
	r := request(query.Query{Type: query.TypePing, Target: "example.com"})
	_, err = s.Execute(ctx, r)
	wantCode(t, err, errcode.InvalidQuery)

	noV6 := newServer(t, newFakeFRR(t), func(c *Config) { c.ProbeSources = c.ProbeSources[:1] })
	_, err = noV6.Execute(ctx, request(query.Query{Type: query.TypePing, Target: "2606:4700::1111"}))
	wantCode(t, err, errcode.ProbeSourceUnavailable)
}

func TestProbeBudget(t *testing.T) {
	prober := &fakeProber{block: make(chan struct{})}
	s := newServer(t, newFakeFRR(t), func(c *Config) { c.Prober = prober; c.MaxActiveProbes = 1 })
	done := make(chan struct{})
	go func() {
		_, _ = s.Execute(context.Background(), request(query.Query{Type: query.TypePing, Target: testPingDst}))
		close(done)
	}()
	waitFor(t, func() bool { return prober.calls.Load() == 1 })
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypePing, Target: "9.9.9.9"}))
	wantCode(t, err, errcode.NodeBusy)
	close(prober.block)
	<-done
}

func TestNewServerRejects(t *testing.T) {
	base := Config{NodeName: "n", FRR: newFakeFRR(t), Prober: &fakeProber{}}
	for name, mod := range map[string]func(*Config){
		"no node":         func(c *Config) { c.NodeName = "" },
		"public allow":    func(c *Config) { c.PublicPolicy.Allow = mustPrefixes("10.0.0.0/8") },
		"loopback source": func(c *Config) { c.ProbeSources = []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
		"two v4 sources": func(c *Config) {
			c.ProbeSources = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
		},
		"unspecified":    func(c *Config) { c.ProbeSources = []netip.Addr{netip.IPv6Unspecified()} },
		"invalid source": func(c *Config) { c.ProbeSources = []netip.Addr{{}} },
	} {
		cfg := base
		mod(&cfg)
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIndexedSearch(t *testing.T) {
	ix := index.New()
	f := newFakeFRR(t)
	s := newServer(t, f, func(c *Config) { c.ExpensiveEnabled = true; c.Index = ix })
	q := query.Query{Type: query.TypeASPath, Target: "^65001"}

	_, err := s.Execute(context.Background(), request(q))
	wantCode(t, err, errcode.QueryTypeUnavailable)
	info, _ := s.Info(context.Background(), &fabricv1.InfoRequest{})
	for _, ty := range info.GetEnabledQueryTypes() {
		if ty == fabricv1.QueryType_QUERY_TYPE_AS_PATH {
			t.Error("Info lists searches before the index is synced")
		}
	}

	ix.BeginSession()
	for i, p := range []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"} {
		asn := uint32(65001)
		if i == 2 {
			asn = 65002
		}
		ix.Update(netip.MustParsePrefix(p), index.Attrs{
			ASPath: frr.ASPath{String: strconv.FormatUint(uint64(asn), 10),
				Segments: []frr.ASSegment{{Type: frr.SegmentSequence, ASNs: []uint32{asn}}}},
			OriginASN: asn, Origin: "IGP",
		})
	}
	ix.EndOfRIB(true)
	ix.EndOfRIB(false)

	r := request(q)
	r.Budgets = &fabricv1.Budgets{MaxPrefixes: 1}
	resp, err := s.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	obs := resp.GetObservation()
	routes := obs.GetRoutes()
	if obs.GetMatched() != 2 || !obs.GetMatchedIsExact() || !obs.GetTruncated() || len(routes.GetPrefixes()) != 1 ||
		routes.GetPrefixes()[0].GetPrefix() != "198.51.100.0/24" {
		t.Fatalf("indexed search = %+v", obs)
	}
	if st := routes.GetIndex(); st.GetVersion() != 3 || st.GetRoutes() != 3 || st.GetSyncedAt() == nil {
		t.Errorf("index state = %+v", st)
	}
	if f.count("show bgp ipv4 unicast regexp ^65001 json") != 0 {
		t.Error("an indexed search reached FRR")
	}
}

// A sidecar that first read FRR while bgpd was still starting must not keep
// failing requests on that stale error once bgpd is up.
func TestRecoversFromStartupUnavailable(t *testing.T) {
	now := time.Now()
	f := newFakeFRR(t)
	versionResp := f.responses["show version"]
	f.set("show version", frr.Response{}, &frr.Error{Code: frr.CodeUnavailable, Message: "no such file"})
	s := newServer(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
	s.refresh(context.Background())

	f.set("show version", versionResp, nil)
	// Within the retry bound the cached error still answers.
	_, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary}))
	wantCode(t, err, errcode.FRRUnavailable)
	// Once it passes, the request re-reads FRR and succeeds.
	now = now.Add(2 * time.Second)
	if _, err := s.Execute(context.Background(), request(query.Query{Type: query.TypeBGPSummary})); err != nil {
		t.Fatalf("still failing after FRR came up: %v", err)
	}
}
