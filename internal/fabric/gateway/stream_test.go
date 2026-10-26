// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/testpki"
)

// releaseBound is the contract's local cleanup allowance after a trigger.
const releaseBound = 2 * time.Second

// idle reports whether svc holds no execution slot, queued job,
// reservation or live stream.
func idle(svc *Service) bool {
	e := svc.Runner.Executor
	e.mu.Lock()
	busy := e.inUse+e.waiting+e.reserved > 0
	e.mu.Unlock()
	a := svc.Admission
	a.mu.Lock()
	defer a.mu.Unlock()
	return !busy && a.streams == 0
}

// within fails the test unless cond holds within d of since, polled.
func within(t *testing.T, what string, since time.Time, d time.Duration, cond func() bool) {
	t.Helper()
	for !cond() {
		if time.Since(since) > d {
			t.Fatalf("%s: not within %s", what, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("%s after %s", what, time.Since(since).Round(time.Millisecond))
}

// cancelAnswer runs until its call's context ends and records when. It
// signals started once running.
type cancelAnswer struct {
	started chan struct{}
	mu      sync.Mutex
	at      time.Time
}

func newCancelAnswer() *cancelAnswer { return &cancelAnswer{started: make(chan struct{}, 1)} }

func (c *cancelAnswer) answer(ctx context.Context, _ *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
	c.started <- struct{}{}
	<-ctx.Done()
	c.mu.Lock()
	c.at = time.Now()
	c.mu.Unlock()
	return nil, errcode.Status(errcode.Timeout, "cancelled")
}

func (c *cancelAnswer) cancelled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.at.IsZero()
}

// bigAnswer answers with an observation of at least size serialized bytes.
func bigAnswer(name string, size int) routerAnswer {
	return func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		obs := pingObservation(name, 3)
		obs.GetPing().Replies[0].Address = strings.Repeat("a", size)
		return obs, nil
	}
}

func routerNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("router-%02d", i)
	}
	return out
}

// handlerEnds records when, and with what, each server stream handler
// returned.
type handlerEnds struct {
	mu   sync.Mutex
	ends map[string]error
	at   map[string]time.Time
}

func (h *handlerEnds) interceptor(
	srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	err := handler(srv, ss)
	h.mu.Lock()
	if h.ends == nil {
		h.ends, h.at = map[string]error{}, map[string]time.Time{}
	}
	h.ends[info.FullMethod], h.at[info.FullMethod] = err, time.Now()
	h.mu.Unlock()
	return err
}

func (h *handlerEnds) ended(method string) (error, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.at[method]
	return h.ends[method], ok
}

// serveStoppable serves svc like serveGateway and also returns the server.
func serveStoppable(t *testing.T, creds *identity.Credentials, svc *Service, opts ...grpc.ServerOption) (
	string, *grpc.Server,
) {
	t.Helper()
	srv := NewServer(creds, svc.Allowlist, &Debug{Elected: svc.Elected}, svc, noPermits(svc.Elected), opts...)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String(), srv
}

// dialService connects as the test service identity with a fixed 64 KiB
// receive window, so a client that stops reading stalls the server.
func dialService(t *testing.T, addr string, creds *identity.Credentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(creds.ClientConfig(identity.Gateway(testSite)))),
		grpc.WithInitialWindowSize(transportWindow), grpc.WithInitialConnWindowSize(transportWindow),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type testPKI struct {
	gateway, service *identity.Credentials
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	return testPKI{
		gateway: loadCreds(t, ca, dir, identity.Gateway(testSite)),
		service: loadCreds(t, ca, filepath.Join(dir, "svc"), identity.Service(testSite, testService)),
	}
}

// A consumer that stops reading cannot hold the request's execution: once
// a write blocks for SendBound the handler ends, the transport aborts the
// write, and the running routers, queue, reservation and live stream are
// released, on the leader and through a follower alike.
func TestServiceStalledConsumerOverTransport(t *testing.T) {
	pki := newTestPKI(t)
	runMethod := servicev1.LookingGlassService_RunDiagnostic_FullMethodName
	forwardMethod := forwardv1.ForwardService_ForwardDiagnostic_FullMethodName
	for _, viaFollower := range []bool{false, true} {
		t.Run(fmt.Sprintf("via follower %t", viaFollower), func(t *testing.T) {
			names := routerNames(8)
			slow := newCancelAnswer()
			nodes := &routerNodes{answers: map[string]routerAnswer{}}
			for _, n := range names[1:] {
				nodes.answers[n] = bigAnswer(n, 100<<10)
			}
			nodes.answers[names[0]] = slow.answer
			leader := newService(t, routerPods(names...), nodes, 8)
			var leaderEnds, followerEnds handlerEnds
			addr, _ := serveStoppable(t, pki.gateway, leader, grpc.ChainStreamInterceptor(leaderEnds.interceptor))
			ends, method := &leaderEnds, runMethod
			if viaFollower {
				addr, _ = serveStoppable(t, pki.gateway, followerService(t, pki.gateway, addr),
					grpc.ChainStreamInterceptor(followerEnds.interceptor))
				ends = &followerEnds
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			stream, err := servicev1.NewLookingGlassServiceClient(dialService(t, addr, pki.service)).
				RunDiagnostic(ctx, validRequest(time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			if ev, err := stream.Recv(); err != nil || ev.GetSnapshot() == nil {
				t.Fatalf("first event %v, %v", ev, err)
			}
			<-slow.started
			// The consumer reads nothing more. The routers answer at once,
			// so the write blocks as soon as the window fills: the handler
			// ends within SendBound of that, and cleanup within another
			// releaseBound.
			stalled := time.Now()
			bound := SendBound + releaseBound
			within(t, "handler ended", stalled, bound, func() bool { _, ok := ends.ended(method); return ok })
			if err, _ := ends.ended(method); status.Code(err) != codes.Canceled {
				t.Errorf("handler status %v, want CANCELLED", err)
			}
			if viaFollower {
				within(t, "leader handler ended", stalled, bound+releaseBound, func() bool {
					_, ok := leaderEnds.ended(forwardMethod)
					return ok
				})
			}
			within(t, "running router cancelled", stalled, bound+releaseBound, slow.cancelled)
			within(t, "execution released", stalled, bound+releaseBound, func() bool { return idle(leader) })
		})
	}
}

// A finished outcome that cannot enter the stream's buffer within
// SendBound cancels the request, even while each write still finishes
// within its own bound.
func TestServiceStalledHandOff(t *testing.T) {
	names := routerNames(8)
	slow := newCancelAnswer()
	nodes := &routerNodes{answers: map[string]routerAnswer{names[0]: slow.answer}}
	svc := newService(t, routerPods(names...), nodes, 8)
	stream := &slowStream{ctx: node.WithCaller(t.Context(), identity.Service(testSite, testService)),
		delay: SendBound * 3 / 4}
	done := make(chan error, 1)
	go func() { done <- svc.RunDiagnostic(validRequest(time.Now()), stream) }()
	<-slow.started
	start := time.Now()
	var err error
	select {
	case err = <-done:
	case <-time.After(4 * SendBound):
		t.Fatal("a stalled hand-off did not end the request")
	}
	if errcode.Of(err) != errcode.Cancelled {
		t.Errorf("err = %v, want Cancelled", err)
	}
	within(t, "running router cancelled", start, 4*SendBound, slow.cancelled)
	within(t, "execution released", start, 4*SendBound, func() bool { return idle(svc) })
}

// slowStream takes delay to send each event.
type slowStream struct {
	grpc.ServerStream
	ctx   context.Context
	delay time.Duration
}

func (s *slowStream) Context() context.Context { return s.ctx }

func (s *slowStream) Send(*servicev1.DiagnosticEvent) error {
	time.Sleep(s.delay)
	return nil
}

// eventSize sums the serialized size of events.
func eventSize(events []*servicev1.DiagnosticEvent) int {
	n := 0
	for _, ev := range events {
		n += proto.Size(ev)
	}
	return n
}

func TestServiceOutputBounds(t *testing.T) {
	t.Run("oversized outcome", func(t *testing.T) {
		nodes := &routerNodes{answers: map[string]routerAnswer{routerA: bigAnswer(routerA, maxOutcomeBytes)}}
		svc := newService(t, routerPods(routerA, routerB), nodes, 8)
		events, err := collect(t, svc, validRequest(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		_, outcomes, c := checkGrammar(t, events)
		if f := outcomes[routerA].GetFailure(); f.GetReason() != string(errcode.ResponseTooLarge) {
			t.Errorf("oversized outcome = %v", outcomes[routerA])
		}
		if c.GetReason() != CompletePartialResults || c.GetSuccessful() != 1 {
			t.Errorf("complete = %v", c)
		}
	})
	t.Run("stream budget", func(t *testing.T) {
		names := routerNames(6)
		nodes := &routerNodes{answers: map[string]routerAnswer{}}
		for _, n := range names {
			nodes.answers[n] = bigAnswer(n, 100<<10)
		}
		svc := newService(t, routerPods(names...), nodes, 8)
		// Room for the snapshot, the terminal event and two outcomes.
		svc.outputLimit = maxCompleteBytes + 230<<10
		events, err := collect(t, svc, validRequest(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		_, outcomes, c := checkGrammar(t, events)
		limited := 0
		for _, o := range outcomes {
			if o.GetFailure().GetReason() == string(errcode.OutputLimitExceeded) {
				limited++
			}
		}
		if c.GetReason() != string(errcode.OutputLimitExceeded) || c.GetSuccessful() != 2 || limited != 4 {
			t.Errorf("complete %v, %d outcomes over the budget: %v", c, limited, outcomes)
		}
		if n := eventSize(events); n > svc.outputLimit {
			t.Errorf("stream wrote %d bytes, over its %d budget", n, svc.outputLimit)
		}
	})
}

// Every live stream at once, each router answering the largest outcome the
// stream accepts, stays within each stream's output budget and a bounded
// number of goroutines.
func TestServiceMaximumOutcomesBounded(t *testing.T) {
	const streams, routers = 16, 16
	names := routerNames(routers)
	nodes := &routerNodes{answers: map[string]routerAnswer{}}
	for _, n := range names {
		nodes.answers[n] = bigAnswer(n, maxOutcomeBytes-4<<10)
	}
	svc := newService(t, routerPods(names...), nodes, 8)
	l := roomyLimits()
	l.Streams, l.ProjectStreams = streams, 1
	withAdmission(t, svc, l)
	svc.Runner.QueueWait = 20 * time.Second

	base := runtime.NumGoroutine()
	var peak atomic.Int64
	sampling, stopSampling := context.WithCancel(t.Context())
	go func() {
		for sampling.Err() == nil {
			if n := int64(runtime.NumGoroutine()); n > peak.Load() {
				peak.Store(n)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	var wg sync.WaitGroup
	results := make([][]*servicev1.DiagnosticEvent, streams)
	errs := make([]error, streams)
	for i := range streams {
		wg.Go(func() {
			results[i], errs[i] = collectWithin(t, svc, requestFor(fmt.Sprintf("project-%02d", i), i, nil), time.Minute)
		})
	}
	wg.Wait()
	stopSampling()
	for i := range streams {
		if errs[i] != nil {
			t.Fatalf("stream %d: %v", i, errs[i])
		}
		_, _, c := checkGrammar(t, results[i])
		if c.GetReason() != CompleteSucceeded || c.GetSuccessful() != routers {
			t.Errorf("stream %d: complete %v", i, c)
		}
		if n := eventSize(results[i]); n > MaxStreamBytes {
			t.Errorf("stream %d wrote %d bytes", i, n)
		}
	}
	// Per stream: its handler, writer and producer, one goroutine per
	// router, and a small allowance for the runtime and test harness.
	if bound := int64(base + streams*(routers+4) + 32); peak.Load() > bound {
		t.Errorf("peak goroutines %d, over %d", peak.Load(), bound)
	}
	if !idle(svc) {
		t.Error("execution not released")
	}
}

// collectWithin is collect with its own timeout, safe off the test
// goroutine.
func collectWithin(t *testing.T, svc *Service, req *runReq, d time.Duration) ([]*servicev1.DiagnosticEvent, error) {
	events, done := run(t, svc, req, 0)
	var out []*servicev1.DiagnosticEvent
	timeout := time.After(d)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return out, <-done
			}
			out = append(out, ev)
		case <-timeout:
			return out, errors.New("stream did not finish")
		}
	}
}

// Caller cancellation during discovery, while queued and while executing
// releases the request's work within releaseBound.
func TestServiceCancellationBounds(t *testing.T) {
	caller := identity.Service(testSite, testService)
	t.Run("discovery", func(t *testing.T) {
		svc := newService(t, routerPods(routerA), &routerNodes{}, 8)
		listing := make(chan struct{}, 1)
		svc.Discoverer.Reader = stallReader{Reader: svc.Discoverer.Reader, listing: listing}
		ctx, cancel := context.WithCancel(node.WithCaller(t.Context(), caller))
		done := make(chan error, 1)
		go func() {
			stream := &chanStream{ctx: ctx, events: make(chan *servicev1.DiagnosticEvent, 8)}
			done <- svc.RunDiagnostic(validRequest(time.Now()), stream)
		}()
		<-listing
		start := time.Now()
		cancel()
		var err error
		within(t, "request ended", start, releaseBound, func() bool {
			select {
			case err = <-done:
				return true
			default:
				return false
			}
		})
		if errcode.Of(err) != errcode.Cancelled {
			t.Errorf("err = %v", err)
		}
		within(t, "execution released", start, releaseBound, func() bool { return idle(svc) })
	})
	t.Run("queued and executing", func(t *testing.T) {
		a, b := newCancelAnswer(), newCancelAnswer()
		nodes := &routerNodes{answers: map[string]routerAnswer{routerA: a.answer, routerB: b.answer}}
		svc := newService(t, routerPods(routerA, routerB), nodes, 1)
		svc.Runner.QueueWait = time.Minute
		ctx, cancel := context.WithCancel(node.WithCaller(t.Context(), caller))
		stream := &chanStream{ctx: ctx, events: make(chan *servicev1.DiagnosticEvent, 8)}
		done := make(chan error, 1)
		go func() { done <- svc.RunDiagnostic(validRequest(time.Now()), stream) }()
		// One router holds the only slot; the other queues behind it.
		running, queued := a, b
		select {
		case <-a.started:
		case <-b.started:
			running, queued = b, a
		}
		within(t, "second router queued", time.Now(), releaseBound,
			func() bool { return svc.Runner.Executor.Depth() == 1 })
		start := time.Now()
		cancel()
		within(t, "request ended", start, releaseBound, func() bool { return len(done) == 1 })
		within(t, "running router cancelled", start, releaseBound, running.cancelled)
		within(t, "execution released", start, releaseBound, func() bool { return idle(svc) })
		if len(queued.started) != 0 {
			t.Error("the queued router ran after cancellation")
		}
	})
}

// Stopping the gateway server cancels a running service request's routers
// within releaseBound.
func TestGatewayStopCancelsServiceWork(t *testing.T) {
	pki := newTestPKI(t)
	running := newCancelAnswer()
	svc := newService(t, routerPods(routerA), &routerNodes{answers: map[string]routerAnswer{routerA: running.answer}}, 8)
	addr, srv := serveStoppable(t, pki.gateway, svc)
	stream, err := servicev1.NewLookingGlassServiceClient(dialService(t, addr, pki.service)).
		RunDiagnostic(t.Context(), validRequest(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	<-running.started
	start := time.Now()
	srv.Stop()
	within(t, "running router cancelled", start, releaseBound, running.cancelled)
	within(t, "execution released", start, releaseBound, func() bool { return idle(svc) })
}

// blackhole relays TCP between a client and the gateway until frozen, then
// drops every byte in both directions without closing either side.
type blackhole struct {
	frozen atomic.Bool
}

func (b *blackhole) serve(t *testing.T, target string) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			var d net.Dialer
			out, err := d.DialContext(t.Context(), "tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			t.Cleanup(func() { _ = in.Close(); _ = out.Close() })
			go b.pipe(in, out)
			go b.pipe(out, in)
		}
	}()
	return l.Addr().String()
}

func (b *blackhole) pipe(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if !b.frozen.Load() {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
}

// A connection that goes silent is detected by keepalive within 10 s, and
// its request's routers are cancelled within releaseBound after that.
func TestServiceBlackholedConnection(t *testing.T) {
	pki := newTestPKI(t)
	running := newCancelAnswer()
	svc := newService(t, routerPods(routerA), &routerNodes{answers: map[string]routerAnswer{routerA: running.answer}}, 8)
	addr, _ := serveStoppable(t, pki.gateway, svc)
	var hole blackhole
	proxied := hole.serve(t, addr)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	stream, err := servicev1.NewLookingGlassServiceClient(dialService(t, proxied, pki.service)).
		RunDiagnostic(ctx, validRequest(time.Now().Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	<-running.started
	start := time.Now()
	hole.frozen.Store(true)
	within(t, "running router cancelled", start, 10*time.Second+releaseBound, running.cancelled)
	within(t, "execution released", start, 10*time.Second+releaseBound, func() bool { return idle(svc) })
}

// A forwarded stream the leader loses is never forwarded again, and no
// router runs twice.
func TestForwardedStreamIsNotReplayed(t *testing.T) {
	pki := newTestPKI(t)
	running := newCancelAnswer()
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: running.answer}}
	leader := newService(t, routerPods(routerA, routerB), nodes, 8)
	leaderAddr, leaderSrv := serveStoppable(t, pki.gateway, leader)
	var forwards atomic.Int32
	count := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string,
		streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if method == forwardv1.ForwardService_ForwardDiagnostic_FullMethodName {
			forwards.Add(1)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
	addr := serveFollower(t, pki.gateway, leaderAddr, grpc.WithStreamInterceptor(count))
	stream, err := servicev1.NewLookingGlassServiceClient(dialService(t, addr, pki.service)).
		RunDiagnostic(t.Context(), validRequest(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if ev, err := stream.Recv(); err != nil || ev.GetSnapshot() == nil {
		t.Fatalf("first event %v, %v", ev, err)
	}
	<-running.started
	leaderSrv.Stop()
	for {
		_, err := stream.Recv()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.Fatal("the interrupted stream ended as if delivered")
		}
		break
	}
	within(t, "leader's router cancelled", time.Now(), releaseBound, running.cancelled)
	if n := forwards.Load(); n != 1 {
		t.Errorf("forwarded %d times", n)
	}
	nodes.mu.Lock()
	defer nodes.mu.Unlock()
	for n, c := range nodes.calls {
		if c > 1 {
			t.Errorf("%s ran %d times", n, c)
		}
	}
}

// handOff makes another process the election lease's holder.
func handOff(t *testing.T, c client.Client) {
	t.Helper()
	var lease coordinationv1.Lease
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: DefaultNamespace, Name: testLease}, &lease); err != nil {
		t.Fatal(err)
	}
	lease.Spec.HolderIdentity = ptr.To("gateway-1_other")
	if err := c.Update(t.Context(), &lease); err != nil {
		t.Fatal(err)
	}
}

// A gateway that missed its own replacement, as a paused process would,
// dispatches nothing once the lease names another holder: its queued
// router never runs, the stream ends with OwnershipLost, and it admits no
// new request.
func TestStaleOwnerDispatchesNothing(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	nodes := &routerNodes{answers: map[string]routerAnswer{
		routerA: blockAnswer(routerA, release, started), routerB: blockAnswer(routerB, release, started),
	}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 1)
	svc.Runner.QueueWait = time.Minute
	lease := newSwitchableLease(t)
	adm, err := NewAdmission(roomyLimits(), &limit.Authority{
		Reader: lease, Namespace: DefaultNamespace, Name: testLease, Identity: testHolder, Hold: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	activate(t, adm)
	svc.Admission, svc.Runner.Admission, svc.Runner.Executor = adm, adm, NewExecutor(1, 0, 0)

	events, done := run(t, svc, requestFor("project-a", 1, nil), 0)
	<-started
	// The router that did not start waits behind the only slot.
	queued := routerB
	nodes.mu.Lock()
	if nodes.calls[routerB] == 1 {
		queued = routerA
	}
	nodes.mu.Unlock()
	handOff(t, lease.Client)
	close(release)
	var got []*servicev1.DiagnosticEvent
	for ev := range events {
		got = append(got, ev)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, outcomes, c := checkGrammar(t, got)
	if c.GetReason() != string(errcode.OwnershipLost) ||
		outcomes[queued].GetFailure().GetReason() != string(errcode.OwnershipLost) {
		t.Errorf("outcomes %v, complete %v", outcomes, c)
	}
	if _, err := collect(t, svc, requestFor("project-a", 2, nil)); errcode.Of(err) != errcode.OwnershipLost {
		t.Errorf("new request on the stale owner: %v", err)
	}
	if nodes.total() != 1 {
		t.Errorf("calls after the hand-off: %v", nodes.calls)
	}
}

func TestRPCCaps(t *testing.T) {
	caps := newRPCCaps()
	for method, capacity := range map[string]int{
		servicev1.LookingGlassService_RunDiagnostic_FullMethodName: MaxServiceRPCs,
		forwardv1.ForwardService_ForwardDiagnostic_FullMethodName:  MaxForwardRPCs,
	} {
		hold, entered := make(chan struct{}), make(chan struct{}, capacity)
		var wg sync.WaitGroup
		for range capacity {
			wg.Go(func() {
				_ = caps.stream(nil, nil, &grpc.StreamServerInfo{FullMethod: method}, func(any, grpc.ServerStream) error {
					entered <- struct{}{}
					<-hold
					return nil
				})
			})
		}
		for range capacity {
			<-entered
		}
		err := caps.stream(nil, nil, &grpc.StreamServerInfo{FullMethod: method},
			func(any, grpc.ServerStream) error { return nil })
		wantRetry(t, err, errcode.QueueFull, string(limit.ScopeQueue))
		close(hold)
		wg.Wait()
		if err := caps.stream(nil, nil, &grpc.StreamServerInfo{FullMethod: method},
			func(any, grpc.ServerStream) error { return nil }); err != nil {
			t.Errorf("%s after release: %v", method, err)
		}
	}
	// Other methods are not capped.
	if err := caps.stream(nil, nil, &grpc.StreamServerInfo{FullMethod: "/other/Method"},
		func(any, grpc.ServerStream) error { return nil }); err != nil {
		t.Error(err)
	}
}

// Service identities hold at most MaxServiceConns connections to a
// replica; other identities are not counted, and a closed connection frees
// its slot.
func TestServiceConnectionCap(t *testing.T) {
	pki := newTestPKI(t)
	svc := newService(t, nil, &routerNodes{}, 8)
	addr, _ := serveStoppable(t, pki.gateway, svc)
	capabilities := func(conn *grpc.ClientConn) error {
		_, err := servicev1.NewLookingGlassServiceClient(conn).GetCapabilities(t.Context(),
			&servicev1.GetCapabilitiesRequest{ApiMajor: ServiceAPIMajor, Cell: testSite})
		return err
	}
	conns := make([]*grpc.ClientConn, 0, MaxServiceConns)
	for i := range MaxServiceConns {
		conn := dialService(t, addr, pki.service)
		if err := capabilities(conn); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	if err := capabilities(dialService(t, addr, pki.service)); status.Code(err) != codes.Unavailable {
		t.Errorf("connection over the cap: %v", err)
	}
	// The gateway identity is not a service connection.
	if _, err := fabricv1.NewFabricGatewayServiceClient(dialAs(t, addr, pki.gateway)).
		ListNodes(t.Context(), &fabricv1.ListNodesRequest{}); status.Code(err) == codes.Unavailable {
		t.Errorf("gateway connection refused: %v", err)
	}
	_ = conns[0].Close()
	within(t, "slot freed", time.Now(), releaseBound, func() bool {
		return capabilities(dialService(t, addr, pki.service)) == nil
	})
}
