// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
)

const (
	leaseNS    = "galactic-system"
	leaseName  = "fabric-api-gateway"
	leaseEpoch = "lease-uid/gateway-0_a"
)

func leaseReader(t *testing.T, holder string) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	return fake.NewClientBuilder().WithScheme(s).WithObjects(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName, UID: "lease-uid"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: ptr.To(holder), LeaseDurationSeconds: ptr.To[int32](15),
			RenewTime: &metav1.MicroTime{Time: time.Now().Add(time.Hour)},
		},
	}).Build()
}

// packetProber sends packets probe packets through the limiter, stopping
// at the first refusal, and reports how many it sent.
type packetProber struct {
	packets int
	sent    atomic.Int32
}

func (p *packetProber) send(ctx context.Context, opts probe.Options) error {
	for range p.packets {
		if err := opts.Limiter.Wait(ctx); err != nil {
			return err
		}
		p.sent.Add(1)
	}
	return nil
}

func (p *packetProber) Ping(
	ctx context.Context, src, dst netip.Addr, opts probe.Options,
) (*fabricv1.PingResult, error) {
	if err := p.send(ctx, opts); err != nil {
		return nil, err
	}
	return &fabricv1.PingResult{Source: src.String(), Destination: dst.String(), Sent: uint32(p.packets)}, nil
}

func (p *packetProber) Traceroute(
	ctx context.Context, src, dst netip.Addr, opts probe.Options,
) (*fabricv1.TracerouteResult, error) {
	if err := p.send(ctx, opts); err != nil {
		return nil, err
	}
	return &fabricv1.TracerouteResult{Source: src.String(), Destination: dst.String()}, nil
}

func permitServer(t *testing.T, prober Prober, mod func(*Permits)) *Server {
	t.Helper()
	p := &Permits{
		Reader: leaseReader(t, "gateway-0_a"), Namespace: leaseNS, LeaseName: leaseName,
		Started: time.Now().Add(-time.Hour),
	}
	if mod != nil {
		mod(p)
	}
	return newServer(t, newFakeFRR(t), func(c *Config) {
		c.Prober = prober
		c.Permits = p
		c.PacketRate, c.PacketBurst = 1000, 1000
	})
}

// permitFor returns a gateway permit matching req, for a ping's packets.
func permitFor(req *fabricv1.ExecuteRequest) *fabricv1.ProbePermit {
	q := QueryFromProto(req.GetQuery())
	dst, _ := query.ResolvedProbe(q)
	return &fabricv1.ProbePermit{
		Id: "permit-" + req.GetRequestId(), Epoch: leaseEpoch, RequestId: req.GetRequestId(), Node: testNode,
		Destination: dst.String(), Operation: req.GetQuery().GetType(), Packets: query.PingCount,
		Deadline: timestamppb.New(time.Now().Add(20 * time.Second)),
	}
}

func TestPermitConsumedOnce(t *testing.T) {
	prober := &packetProber{packets: 3}
	metrics := NewMetrics()
	s := permitServer(t, prober, func(p *Permits) { p.Metrics = metrics })
	ctx := WithCaller(t.Context(), identity.Gateway("dfw"))

	req := request(query.Query{Type: query.TypePing, Target: testPingDst})
	req.Permit = permitFor(req)
	if _, err := s.Execute(ctx, req); err != nil {
		t.Fatal(err)
	}
	// The same permit on another attempt is refused, though the request
	// itself is new.
	again := request(query.Query{Type: query.TypePing, Target: testPingDst})
	again.Permit = req.GetPermit()
	again.Permit.RequestId = again.GetRequestId()
	_, err := s.Execute(ctx, again)
	wantCode(t, err, errcode.LimiterUnavailable)
	if n := prober.sent.Load(); n != 3 {
		t.Errorf("sent %d packets, want 3", n)
	}
	for outcome, want := range map[string]float64{PermitAccepted: 1, permitReplayed: 1} {
		if n := testutil.ToFloat64(metrics.permits.WithLabelValues(outcome)); n != want {
			t.Errorf("%s permits = %g, want %g", outcome, n, want)
		}
	}
	if info, _ := s.Info(ctx, &fabricv1.InfoRequest{}); !info.GetProbePermits() {
		t.Error("Info does not report probe permits")
	}
}

func TestPermitRefusals(t *testing.T) {
	ctx := WithCaller(t.Context(), identity.Gateway("dfw"))
	cases := map[string]struct {
		mod     func(*fabricv1.ProbePermit)
		perm    func(*Permits)
		code    errcode.Code
		outcome string
	}{
		"other epoch": {
			mod:  func(p *fabricv1.ProbePermit) { p.Epoch = "lease-uid/gateway-1_b" },
			code: errcode.OwnershipLost, outcome: permitEpoch,
		},
		"other node": {
			mod:  func(p *fabricv1.ProbePermit) { p.Node = "other" },
			code: errcode.LimiterUnavailable, outcome: permitMismatch,
		},
		"other request": {
			mod:  func(p *fabricv1.ProbePermit) { p.RequestId = "x" },
			code: errcode.LimiterUnavailable, outcome: permitMismatch,
		},
		"other dest": {
			mod:  func(p *fabricv1.ProbePermit) { p.Destination = "9.9.9.9" },
			code: errcode.LimiterUnavailable, outcome: permitMismatch,
		},
		"other operation": {
			mod:  func(p *fabricv1.ProbePermit) { p.Operation = fabricv1.QueryType_QUERY_TYPE_TRACEROUTE },
			code: errcode.LimiterUnavailable, outcome: permitMismatch,
		},
		"expired": {mod: func(p *fabricv1.ProbePermit) {
			p.Deadline = timestamppb.New(time.Now().Add(-time.Second))
		}, code: errcode.LimiterUnavailable, outcome: permitExpired},
		"too long-lived": {mod: func(p *fabricv1.ProbePermit) {
			p.Deadline = timestamppb.New(time.Now().Add(time.Minute))
		}, code: errcode.LimiterUnavailable, outcome: permitExpired},
		"no id": {
			mod:  func(p *fabricv1.ProbePermit) { p.Id = "" },
			code: errcode.LimiterUnavailable, outcome: permitMalformed,
		},
		"startup refusal": {
			perm: func(p *Permits) { p.Started = time.Now() },
			code: errcode.LimiterUnavailable, outcome: permitStarting,
		},
		"clock unsynchronised": {
			perm: func(p *Permits) { p.Clock = func() error { return errors.New("unsynchronised") } },
			code: errcode.LimiterUnavailable, outcome: permitClock,
		},
		"lease unreadable": {perm: func(p *Permits) {
			p.Reader = leaseReader(t, "gateway-0_a")
			p.LeaseName = "missing"
		}, code: errcode.OwnershipLost, outcome: permitLease},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			prober := &packetProber{packets: 3}
			metrics := NewMetrics()
			s := permitServer(t, prober, func(p *Permits) {
				p.Metrics = metrics
				if tc.perm != nil {
					tc.perm(p)
				}
			})
			req := request(query.Query{Type: query.TypePing, Target: testPingDst})
			req.Permit = permitFor(req)
			if tc.mod != nil {
				tc.mod(req.Permit)
			}
			_, err := s.Execute(ctx, req)
			wantCode(t, err, tc.code)
			if prober.sent.Load() != 0 {
				t.Error("a refused permit sent packets")
			}
			if n := testutil.ToFloat64(metrics.permits.WithLabelValues(tc.outcome)); n != 1 {
				t.Errorf("%s refusals counted %g times", tc.outcome, n)
			}
			if n := testutil.ToFloat64(metrics.permits.WithLabelValues(PermitAccepted)); n != 0 {
				t.Errorf("a refused permit counted as accepted")
			}
		})
	}
}

func TestPermitSetFailsClosed(t *testing.T) {
	s := permitServer(t, &packetProber{packets: 3}, func(p *Permits) { p.MaxConsumed = 1 })
	ctx := WithCaller(t.Context(), identity.Gateway("dfw"))
	first := request(query.Query{Type: query.TypePing, Target: testPingDst})
	first.Permit = permitFor(first)
	if _, err := s.Execute(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := request(query.Query{Type: query.TypePing, Target: testPingDst})
	second.Permit = permitFor(second)
	_, err := s.Execute(ctx, second)
	wantCode(t, err, errcode.LimiterUnavailable)
}

func TestPermitAllowanceAndDeadline(t *testing.T) {
	ctx := WithCaller(t.Context(), identity.Gateway("dfw"))
	// A prober that would send more than the permit allows is stopped at
	// the allowance.
	prober := &packetProber{packets: 5}
	s := permitServer(t, prober, nil)
	req := request(query.Query{Type: query.TypePing, Target: testPingDst})
	req.Permit = permitFor(req)
	if _, err := s.Execute(ctx, req); err == nil {
		t.Fatal("a probe past its allowance succeeded")
	}
	if n := prober.sent.Load(); n != 3 {
		t.Errorf("sent %d packets, want the allowance of 3", n)
	}

	// The permit's deadline bounds the probe.
	var deadline time.Time
	s = permitServer(t, proberFunc(func(ctx context.Context) {
		deadline, _ = ctx.Deadline()
	}), nil)
	req = request(query.Query{Type: query.TypePing, Target: testPingDst})
	req.Permit = permitFor(req)
	want := req.GetPermit().GetDeadline().AsTime()
	if _, err := s.Execute(ctx, req); err != nil {
		t.Fatal(err)
	}
	if deadline.After(want) {
		t.Errorf("probe deadline %s is after the permit's %s", deadline, want)
	}
}

type proberFunc func(context.Context)

func (f proberFunc) Ping(ctx context.Context, src, dst netip.Addr, _ probe.Options) (*fabricv1.PingResult, error) {
	f(ctx)
	return &fabricv1.PingResult{Source: src.String(), Destination: dst.String()}, nil
}

func (f proberFunc) Traceroute(ctx context.Context, src, dst netip.Addr, _ probe.Options,
) (*fabricv1.TracerouteResult, error) {
	f(ctx)
	return &fabricv1.TracerouteResult{Source: src.String(), Destination: dst.String()}, nil
}

func TestPermitRequired(t *testing.T) {
	gw := WithCaller(t.Context(), identity.Gateway("dfw"))
	op := WithCaller(t.Context(), identity.Operator("dfw", "alice"))

	required := permitServer(t, &packetProber{packets: 3}, func(p *Permits) { p.Require = true })
	_, err := required.Execute(gw, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	wantCode(t, err, errcode.LimiterUnavailable)
	// Reads never need a permit.
	if _, err := required.Execute(gw, request(query.Query{Type: query.TypeBGPSummary})); err != nil {
		t.Errorf("summary: %v", err)
	}
	// With no gateway to ask, a direct operator probe is refused.
	_, err = required.Execute(op, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	wantCode(t, err, errcode.LimiterUnavailable)

	// An operator may never supply its own permit.
	optional := permitServer(t, &packetProber{packets: 3}, nil)
	req := request(query.Query{Type: query.TypePing, Target: testPingDst})
	req.Permit = permitFor(req)
	_, err = optional.Execute(op, req)
	wantCode(t, err, errcode.InvalidQuery)

	// A node without a permit checker refuses a permit it cannot verify.
	bare := newServer(t, newFakeFRR(t), nil)
	req = request(query.Query{Type: query.TypePing, Target: testPingDst})
	req.Permit = permitFor(req)
	_, err = bare.Execute(gw, req)
	wantCode(t, err, errcode.LimiterUnavailable)
	if info, _ := bare.Info(gw, &fabricv1.InfoRequest{}); info.GetProbePermits() {
		t.Error("a node without a permit checker reports probe permits")
	}
}

// fakeGateway issues permits for direct operator probes and records
// releases.
type fakeGateway struct {
	mu       sync.Mutex
	requests []*permitv1.RequestPermitRequest
	released []string
	refuse   error
}

func (g *fakeGateway) RequestPermit(_ context.Context, in *permitv1.RequestPermitRequest,
	_ ...grpc.CallOption) (*permitv1.RequestPermitResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, in)
	if g.refuse != nil {
		return nil, g.refuse
	}
	req := &fabricv1.ExecuteRequest{RequestId: in.GetRequestId(), Query: in.GetQuery()}
	pm := permitFor(req)
	pm.Id = fmt.Sprintf("direct-%d", len(g.requests))
	return &permitv1.RequestPermitResponse{Permit: pm}, nil
}

func (g *fakeGateway) ReleasePermit(_ context.Context, in *permitv1.ReleasePermitRequest,
	_ ...grpc.CallOption) (*permitv1.ReleasePermitResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.released = append(g.released, in.GetId())
	return &permitv1.ReleasePermitResponse{}, nil
}

func TestDirectOperatorPermit(t *testing.T) {
	gw := &fakeGateway{}
	prober := &packetProber{packets: 3}
	s := permitServer(t, prober, func(p *Permits) { p.Require = true; p.Gateway = gw })
	op := WithCaller(t.Context(), identity.Operator("dfw", "alice"))

	req := request(query.Query{Type: query.TypePing, Target: testPingDst})
	if _, err := s.Execute(op, req); err != nil {
		t.Fatal(err)
	}
	gw.mu.Lock()
	if len(gw.requests) != 1 || gw.requests[0].GetOperator() != "alice" || gw.requests[0].GetNode() != testNode ||
		gw.requests[0].GetRequestId() != req.GetRequestId() {
		t.Errorf("permit requests = %v", gw.requests)
	}
	if len(gw.released) != 1 || gw.released[0] != "direct-1" {
		t.Errorf("released = %v", gw.released)
	}
	gw.refuse = errcode.Retry(errcode.Throttled, "budget", "destination", time.Second)
	gw.mu.Unlock()

	// A throttled operator probe reaches the operator as Throttled, with
	// its retry guidance, and sends nothing.
	_, err := s.Execute(op, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	wantCode(t, err, errcode.Throttled)
	if d, ok := errcode.RetryDelay(err); !ok || d != time.Second {
		t.Errorf("retry = %s, %v", d, ok)
	}
	if n := prober.sent.Load(); n != 3 {
		t.Errorf("sent %d packets, want 3", n)
	}

	gw.mu.Lock()
	gw.refuse = errors.New("connection refused")
	gw.mu.Unlock()
	_, err = s.Execute(op, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	wantCode(t, err, errcode.LimiterUnavailable)

	// During its startup refusal a node does not ask for a permit it could
	// not use, which would charge the operator's budget for nothing.
	starting := &fakeGateway{}
	s = permitServer(t, prober, func(p *Permits) { p.Require, p.Gateway, p.Started = true, starting, time.Now() })
	_, err = s.Execute(op, request(query.Query{Type: query.TypePing, Target: testPingDst}))
	wantCode(t, err, errcode.LimiterUnavailable)
	if len(starting.requests) != 0 {
		t.Error("a starting node requested a permit")
	}
}

// A probe whose target is not a probe destination is counted as invalid,
// not as a permit that does not match.
func TestPermitInvalidTarget(t *testing.T) {
	metrics := NewMetrics()
	p := &Permits{Reader: leaseReader(t, "gateway-0_a"), Namespace: leaseNS, LeaseName: leaseName,
		Started: time.Now().Add(-time.Hour), Metrics: metrics}
	q := query.Query{Type: query.TypePing, Target: "not-an-address"}
	pm := &fabricv1.ProbePermit{Id: "permit", Epoch: leaseEpoch, Node: testNode,
		Deadline: timestamppb.New(time.Now().Add(20 * time.Second))}
	if _, err := p.consume(t.Context(), pm, testNode, "req", q, time.Now()); err == nil {
		t.Fatal("a permit for an invalid target was accepted")
	}
	if n := testutil.ToFloat64(metrics.permits.WithLabelValues(permitInvalid)); n != 1 {
		t.Errorf("invalid permits = %g", n)
	}
	if n := testutil.ToFloat64(metrics.permits.WithLabelValues(permitMismatch)); n != 0 {
		t.Errorf("an invalid target counted as a mismatch")
	}
}
