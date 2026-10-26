// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/testpki"
)

const (
	routerA = "router-a"
	routerB = "router-b"
	routerC = "router-c"
)

// routerAnswer answers one router's Execute.
type routerAnswer func(ctx context.Context, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error)

// routerNodes is a NodeClients whose routers each answer with their own
// function, ok by default, and which counts every call. Every router
// enforces probe permits unless it is listed in legacy.
type routerNodes struct {
	mu      sync.Mutex
	answers map[string]routerAnswer
	calls   map[string]int
	legacy  map[string]bool
}

func (f *routerNodes) Client(n Node) (fabricv1.FabricServiceClient, error) {
	return &routerClient{f: f, node: n.Name}, nil
}

// total returns the number of calls to every router.
func (f *routerNodes) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

type routerClient struct {
	fabricv1.FabricServiceClient
	f    *routerNodes
	node string
}

func (c *routerClient) Execute(
	ctx context.Context, req *fabricv1.ExecuteRequest, _ ...grpc.CallOption,
) (*fabricv1.ExecuteResponse, error) {
	c.f.mu.Lock()
	if c.f.calls == nil {
		c.f.calls = map[string]int{}
	}
	c.f.calls[c.node]++
	answer := c.f.answers[c.node]
	c.f.mu.Unlock()
	if answer == nil {
		answer = okAnswer(c.node)
	}
	obs, err := answer(ctx, req)
	if err != nil {
		return nil, err
	}
	return &fabricv1.ExecuteResponse{Observation: obs}, nil
}

func (c *routerClient) Info(
	context.Context, *fabricv1.InfoRequest, ...grpc.CallOption,
) (*fabricv1.InfoResponse, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return &fabricv1.InfoResponse{Node: c.node, ProbePermits: !c.f.legacy[c.node]}, nil
}

func okAnswer(name string) routerAnswer {
	return func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		return pingObservation(name, 3), nil
	}
}

// pingObservation is a ping observation that received replies of 3.
func pingObservation(name string, replies uint32) *fabricv1.Observation {
	obs := &fabricv1.Observation{
		Node: name, RouterId: "192.0.2.1", Asn: 64512, SampleTime: timestamppb.Now(),
		Result: &fabricv1.Observation_Ping{Ping: &fabricv1.PingResult{
			Source: "2001:db8::a", Destination: "2001:db8::1", Sent: 3, Received: replies,
		}},
	}
	for i := range uint32(3) {
		obs.GetPing().Replies = append(obs.GetPing().Replies, &fabricv1.ProbeReply{Sequence: i + 1, Timeout: i >= replies})
	}
	return obs
}

func failAnswer(code errcode.Code) routerAnswer {
	return func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		return nil, errcode.Status(code, "raw failure naming 2001:db8::1")
	}
}

// blockAnswer blocks until release closes or the call's context ends. It
// signals started, when not nil, once the call is running.
func blockAnswer(name string, release <-chan struct{}, started chan<- struct{}) routerAnswer {
	return func(ctx context.Context, _ *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		if started != nil {
			started <- struct{}{}
		}
		select {
		case <-release:
			return pingObservation(name, 3), nil
		case <-ctx.Done():
			return nil, errcode.Status(errcode.Timeout, "blocked")
		}
	}
}

// certified returns a running certs pod for each node.
func certified(nodes ...string) []client.Object {
	out := make([]client.Object, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, certsPod("certs-"+n, n, time.Now().Add(-time.Hour), corev1.PodRunning))
	}
	return out
}

func routerPods(nodes ...string) []client.Object {
	out := make([]client.Object, 0, 2*len(nodes))
	for _, n := range nodes {
		out = append(out, fabricPod("fr-"+n, n, nil))
	}
	return append(out, certified(nodes...)...)
}

// newService returns an enabled leader whose discoverer lists objs and
// whose routers answer through nodes.
func newService(t *testing.T, objs []client.Object, nodes *routerNodes, slots int) *Service {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	reader := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	sel, _ := labels.Parse(DefaultPodSelector)
	certs, _ := labels.Parse(DefaultCertsSelector)
	adm := newTestAdmission(t, roomyLimits())
	return &Service{
		Cell: testSite, Allowlist: testAllowlist, Elected: elected, Enabled: true, Revision: "abc123",
		Discoverer: &Discoverer{Reader: reader, Namespace: DefaultNamespace, Selector: sel, CertsSelector: certs},
		Runner: &Runner{Clients: nodes, Executor: NewExecutor(slots, 0, 0), QueueWait: 200 * time.Millisecond,
			Admission: adm},
		Admission: adm,
	}
}

// chanStream is a RunDiagnostic server stream that hands each event to a
// channel, and fails a send once failAt events were sent, or every send
// when failAt is negative.
type chanStream struct {
	grpc.ServerStream
	ctx    context.Context
	events chan *servicev1.DiagnosticEvent
	failAt int
	sent   int
}

func (s *chanStream) Context() context.Context { return s.ctx }

func (s *chanStream) Send(ev *servicev1.DiagnosticEvent) error {
	if s.failAt < 0 || (s.failAt > 0 && s.sent >= s.failAt) {
		return errors.New("stream broken")
	}
	s.sent++
	s.events <- proto.CloneOf(ev)
	return nil
}

// run starts RunDiagnostic for req and returns its events channel and its
// final error.
func run(t *testing.T, svc *Service, req *servicev1.RunDiagnosticRequest, failAt int) (
	<-chan *servicev1.DiagnosticEvent, <-chan error,
) {
	t.Helper()
	stream := &chanStream{
		ctx:    node.WithCaller(t.Context(), identity.Service(testSite, testService)),
		events: make(chan *servicev1.DiagnosticEvent, 512),
		failAt: failAt,
	}
	done := make(chan error, 1)
	go func() {
		err := svc.RunDiagnostic(req, stream)
		close(stream.events)
		done <- err
	}()
	return stream.events, done
}

// collect runs req to its end and returns every event and the final error.
func collect(t *testing.T, svc *Service, req *servicev1.RunDiagnosticRequest) ([]*servicev1.DiagnosticEvent, error) {
	t.Helper()
	events, done := run(t, svc, req, 0)
	var out []*servicev1.DiagnosticEvent
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return out, <-done
			}
			out = append(out, ev)
		case <-timeout:
			t.Fatal("stream did not finish")
		}
	}
}

func next(t *testing.T, events <-chan *servicev1.DiagnosticEvent) *servicev1.DiagnosticEvent {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event arrived")
		return nil
	}
}

// checkGrammar verifies a fully delivered stream: consecutive sequences
// from 1, one snapshot first, one complete last, exactly one outcome per
// selected router and none for an omitted one, and counts that reconcile
// with the snapshot.
func checkGrammar(t *testing.T, events []*servicev1.DiagnosticEvent) (
	*servicev1.Snapshot, map[string]*servicev1.RouterOutcome, *servicev1.Complete,
) {
	t.Helper()
	if len(events) < 2 {
		t.Fatalf("stream has %d events", len(events))
	}
	for i, ev := range events {
		if ev.GetSequence() != uint64(i+1) || ev.GetRequestId() == "" || ev.GetRequestId() != events[0].GetRequestId() {
			t.Fatalf("event %d: sequence %d, request %q", i, ev.GetSequence(), ev.GetRequestId())
		}
	}
	snap := events[0].GetSnapshot()
	done := events[len(events)-1].GetComplete()
	if snap == nil || done == nil {
		t.Fatalf("stream does not open with a snapshot and close with complete: %v", events)
	}
	selected := map[string]string{}
	for _, r := range snap.GetRouters() {
		if r.GetSelected() {
			selected[r.GetNode()] = r.GetPodUid()
		} else if r.GetPodUid() != "" || r.GetOmittedReason() == "" {
			t.Errorf("omitted router %v carries a pod or no reason", r)
		}
	}
	outcomes := map[string]*servicev1.RouterOutcome{}
	var successful, failed uint32
	for _, ev := range events[1 : len(events)-1] {
		o := ev.GetOutcome()
		if o == nil {
			t.Fatalf("event %d is not an outcome: %v", ev.GetSequence(), ev)
		}
		pod, ok := selected[o.GetNode()]
		if !ok || outcomes[o.GetNode()] != nil || o.GetPodUid() != pod {
			t.Fatalf("outcome %v is not the first for a selected router", o)
		}
		outcomes[o.GetNode()] = o
		if o.GetObservation() != nil {
			successful++
		} else {
			failed++
		}
	}
	if len(outcomes) != len(selected) {
		t.Errorf("%d outcomes for %d selected routers", len(outcomes), len(selected))
	}
	expected := uint32(len(snap.GetRouters()))
	omitted := expected - uint32(len(selected))
	if done.GetSnapshotId() != snap.GetSnapshotId() || done.GetExpected() != expected ||
		done.GetSuccessful() != successful || done.GetFailed() != failed || done.GetOmitted() != omitted ||
		done.GetExpected() != done.GetSuccessful()+done.GetFailed()+done.GetOmitted() {
		t.Errorf("complete %v does not reconcile with %d routers, %d ok, %d failed", done, expected, successful, failed)
	}
	return snap, outcomes, done
}

func omitted(snap *servicev1.Snapshot) map[string]string {
	out := map[string]string{}
	for _, r := range snap.GetRouters() {
		if !r.GetSelected() {
			out[r.GetNode()] = r.GetOmittedReason()
		}
	}
	return out
}

func TestServiceStreamsFinishedRoutersFirst(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: blockAnswer(routerA, release, started)}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 8)
	events, done := run(t, svc, validRequest(time.Now()), 0)

	if snap := next(t, events).GetSnapshot(); len(snap.GetRouters()) != 2 {
		t.Fatalf("snapshot = %v", snap)
	}
	// router-b's outcome arrives while router-a, first by name, is running
	// and cannot finish until release closes.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("router-a never started")
	}
	fast := next(t, events).GetOutcome()
	if fast.GetNode() != routerB || fast.GetObservation() == nil {
		t.Fatalf("first outcome = %v", fast)
	}
	close(release)
	if slow := next(t, events).GetOutcome(); slow.GetNode() != routerA || slow.GetObservation() == nil {
		t.Fatalf("second outcome = %v", slow)
	}
	c := next(t, events).GetComplete()
	if c.GetReason() != CompleteSucceeded || c.GetExpected() != 2 || c.GetSuccessful() != 2 {
		t.Errorf("complete = %v", c)
	}
	if err := <-done; err != nil {
		t.Errorf("RunDiagnostic = %v", err)
	}
}

func TestServiceCoverage(t *testing.T) {
	now := time.Now()
	pod := func(name, n string, mod func(*corev1.Pod)) client.Object { return fabricPod(name, n, mod) }
	many := func(n int) []client.Object {
		names := make([]string, 0, n)
		for i := range n {
			names = append(names, fmt.Sprintf("router-%03d", i))
		}
		return routerPods(names...)
	}
	truncated := func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		obs := pingObservation(routerA, 3)
		obs.Truncated = true
		return obs, nil
	}
	for name, tc := range map[string]struct {
		objs     []client.Object
		answers  map[string]routerAnswer
		nodes    []string
		reason   string
		omitted  map[string]string
		failures map[string]string
		counts   [5]uint32 // expected, successful, failed, omitted, truncated
	}{
		"all succeed": {
			objs: routerPods(routerA, routerB), reason: CompleteSucceeded, counts: [5]uint32{2, 2, 0, 0, 0},
		},
		"partial failure": {
			objs:     routerPods(routerA, routerB),
			answers:  map[string]routerAnswer{routerB: failAnswer(errcode.NodeUnreachable)},
			reason:   CompletePartialResults,
			failures: map[string]string{routerB: "NodeUnreachable"},
			counts:   [5]uint32{2, 1, 1, 0, 0},
		},
		"every router fails": {
			objs: routerPods(routerA, routerB),
			answers: map[string]routerAnswer{
				routerA: failAnswer(errcode.FRRUnavailable), routerB: failAnswer(errcode.Internal),
			},
			reason:   CompleteExecutionFailed,
			failures: map[string]string{routerA: "FRRUnavailable", routerB: "Internal"},
			counts:   [5]uint32{2, 0, 2, 0, 0},
		},
		"empty inventory": {reason: CompleteNoNodesAvailable},
		"no usable router": {
			objs: append(certified(routerA), pod("fr-router-a", routerA, func(p *corev1.Pod) {
				p.Status.Phase = corev1.PodPending
			})),
			reason:  CompleteNoNodesAvailable,
			omitted: map[string]string{routerA: OmitPodNotRunning},
			counts:  [5]uint32{1, 0, 0, 1, 0},
		},
		"explicit subset": {
			objs:    append(routerPods(routerA, routerB), pod("fr-router-c", routerC, nil)),
			nodes:   []string{routerA},
			reason:  CompleteSucceeded,
			omitted: map[string]string{routerB: OmitNotRequested, routerC: OmitNotRequested},
			counts:  [5]uint32{3, 1, 0, 2, 0},
		},
		"requested router unavailable": {
			objs:    append(routerPods(routerA, routerB), pod("fr-router-c", routerC, nil)),
			nodes:   []string{routerA, routerC},
			reason:  CompletePartialResults,
			omitted: map[string]string{routerB: OmitNotRequested, routerC: OmitNoCertificate},
			counts:  [5]uint32{3, 1, 0, 2, 0},
		},
		"omissions": {
			objs: append(append(routerPods(routerA), certified(routerB, routerC, "router-d")...),
				pod("fr-router-b", routerB, func(p *corev1.Pod) { p.Spec.Containers = p.Spec.Containers[:1] }),
				pod("fr-router-c", routerC, func(p *corev1.Pod) {
					p.DeletionTimestamp, p.Finalizers = &metav1.Time{Time: now}, []string{"test/keep"}
				}),
				pod("fr-router-d", "router-d", func(p *corev1.Pod) { p.Status.HostIP = "" }),
				pod("fr-unscheduled", "", nil),
			),
			reason: CompletePartialResults,
			omitted: map[string]string{
				routerB: OmitNoSidecar, routerC: OmitPodTerminating, "router-d": OmitNoHostIP,
			},
			counts: [5]uint32{4, 1, 0, 3, 0},
		},
		"duplicate pods": {
			objs: append(certified(routerA),
				pod("fr-old", routerA, func(p *corev1.Pod) { p.CreationTimestamp = metav1.NewTime(now.Add(-time.Hour)) }),
				pod("fr-new", routerA, func(p *corev1.Pod) { p.CreationTimestamp = metav1.NewTime(now) }),
				pod("fr-broken", routerA, func(p *corev1.Pod) {
					p.CreationTimestamp = metav1.NewTime(now.Add(time.Hour))
					p.Status.Phase = corev1.PodFailed
				}),
			),
			reason: CompleteSucceeded,
			counts: [5]uint32{1, 1, 0, 0, 0},
		},
		"fan-out cap": {
			objs:    many(MaxServiceNodes + 1),
			reason:  CompletePartialResults,
			omitted: map[string]string{fmt.Sprintf("router-%03d", MaxServiceNodes): OmitNodeBudget},
			counts:  [5]uint32{MaxServiceNodes + 1, MaxServiceNodes, 0, 1, 0},
		},
		"truncated observation": {
			objs:    routerPods(routerA, routerB),
			answers: map[string]routerAnswer{routerA: truncated},
			reason:  CompletePartialResults,
			counts:  [5]uint32{2, 2, 0, 0, 1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			nodes := &routerNodes{answers: tc.answers}
			svc := newService(t, tc.objs, nodes, 8)
			req := validRequest(time.Now())
			req.Nodes = tc.nodes
			events, err := collect(t, svc, req)
			if err != nil {
				t.Fatalf("RunDiagnostic = %v", err)
			}
			snap, outcomes, c := checkGrammar(t, events)
			got := [5]uint32{c.GetExpected(), c.GetSuccessful(), c.GetFailed(), c.GetOmitted(), c.GetTruncatedRouters()}
			if c.GetReason() != tc.reason || got != tc.counts {
				t.Errorf("complete = %v, want %s %v", c, tc.reason, tc.counts)
			}
			if om := omitted(snap); len(tc.omitted) > 0 || len(om) > 0 {
				for n, r := range tc.omitted {
					if om[n] != r {
						t.Errorf("router %s omitted as %q, want %q", n, om[n], r)
					}
				}
				if len(om) != len(tc.omitted) {
					t.Errorf("omitted = %v, want %v", om, tc.omitted)
				}
			}
			for n, reason := range tc.failures {
				f := outcomes[n].GetFailure()
				if f.GetReason() != reason || f.GetMessage() == "" || f.GetMessage() == "raw failure naming 2001:db8::1" {
					t.Errorf("router %s failure = %v, want sanitized %s", n, f, reason)
				}
			}
			if name == "omissions" && snap.GetUnscheduledPodCount() != 1 {
				t.Errorf("unscheduled pods = %d", snap.GetUnscheduledPodCount())
			}
			if name == "duplicate pods" && snap.GetRouters()[0].GetPodUid() != "uid-fr-new" {
				t.Errorf("router-a runs on %q, want the newest usable pod", snap.GetRouters()[0].GetPodUid())
			}
		})
	}
}

func TestServiceRefusesBeforeSnapshot(t *testing.T) {
	big := make([]string, 0, MaxInventoryRouters+1)
	for i := range MaxInventoryRouters + 1 {
		big = append(big, fmt.Sprintf("r%03d", i))
	}
	for name, tc := range map[string]struct {
		objs  []client.Object
		nodes []string
		want  errcode.Code
	}{
		"unknown router":       {routerPods(routerA), []string{routerA, "router-z"}, errcode.InvalidQuery},
		"oversized inventory":  {routerPods(big...), nil, errcode.InventoryTooLarge},
		"unscheduled selected": {[]client.Object{fabricPod("fr-x", "", nil)}, []string{"router-x"}, errcode.InvalidQuery},
	} {
		nodes := &routerNodes{}
		svc := newService(t, tc.objs, nodes, 8)
		req := validRequest(time.Now())
		req.Nodes = tc.nodes
		events, err := collect(t, svc, req)
		if errcode.Of(err) != tc.want || len(events) != 0 {
			t.Errorf("%s: %d events, %v; want %s and none", name, len(events), err, tc.want)
		}
	}
}

// A request that expires or is cancelled while the router inventory is
// being read fails with its own reason, not as a backend failure.
func TestServiceDiscoveryCutShort(t *testing.T) {
	svc := newService(t, nil, &routerNodes{}, 8)
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	svc.Discoverer.Reader = fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			<-ctx.Done()
			return fmt.Errorf("list: %w", ctx.Err())
		},
	}).Build()

	req := validRequest(time.Now())
	req.ExpiresAt = timestamppb.New(time.Now().Add(200 * time.Millisecond))
	if events, err := collect(t, svc, req); errcode.Of(err) != errcode.DeadlineExceeded || len(events) != 0 {
		t.Errorf("expired during discovery: %v, %d events", err, len(events))
	}

	ctx, cancel := context.WithCancel(node.WithCaller(t.Context(), identity.Service(testSite, testService)))
	stream := &chanStream{ctx: ctx, events: make(chan *servicev1.DiagnosticEvent, 1)}
	time.AfterFunc(100*time.Millisecond, cancel)
	// A new attempt: the first one's request ID stays registered.
	req = validRequest(time.Now())
	req.RequestId = "c0ffee00-926f-43dc-b03d-c29550a827ab"
	if err := svc.RunDiagnostic(req, stream); errcode.Of(err) != errcode.Cancelled {
		t.Errorf("cancelled during discovery: %v", err)
	}
}

// Packet loss, silent hops, an empty route lookup and a zebra failure are
// observations, not router failures.
func TestServiceObservationsAreNotFailures(t *testing.T) {
	answers := map[string]routerAnswer{
		"router-loss": func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			return pingObservation("router-loss", 0), nil
		},
		"router-hops": func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			return &fabricv1.Observation{Node: "router-hops", Result: &fabricv1.Observation_Traceroute{
				Traceroute: &fabricv1.TracerouteResult{Hops: []*fabricv1.Hop{
					{Ttl: 1, Probes: []*fabricv1.ProbeReply{{Sequence: 1, Timeout: true}}},
				}},
			}}, nil
		},
		"router-empty": func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			return &fabricv1.Observation{Node: "router-empty", Result: &fabricv1.Observation_Routes{
				Routes: &fabricv1.RouteResult{},
			}}, nil
		},
		"router-zebra": func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			return &fabricv1.Observation{Node: "router-zebra", Result: &fabricv1.Observation_Routes{
				Routes: &fabricv1.RouteResult{Prefixes: []*fabricv1.PrefixObservation{{
					Prefix: "192.0.2.0/24", Installation: &fabricv1.Installation{ErrorCode: "FRRUnavailable"},
				}}},
			}}, nil
		},
	}
	svc := newService(t, routerPods("router-empty", "router-hops", "router-loss", "router-zebra"),
		&routerNodes{answers: answers}, 8)
	events, err := collect(t, svc, validRequest(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	_, outcomes, c := checkGrammar(t, events)
	if c.GetReason() != CompleteSucceeded || c.GetSuccessful() != 4 {
		t.Errorf("complete = %v", c)
	}
	if outcomes["router-loss"].GetObservation().GetPing().GetReceived() != 0 ||
		outcomes["router-zebra"].GetObservation().GetRoutes().GetPrefixes()[0].GetInstallation().GetErrorCode() == "" {
		t.Errorf("observations were altered: %v", outcomes)
	}
}

func TestServiceDeadlineAndQueue(t *testing.T) {
	// One slot, both routers blocking: the one that takes the slot holds it
	// past the other's queue bound, so the other fails with QueueTimeout;
	// the request's deadline then cuts the first short.
	release := make(chan struct{})
	defer close(release)
	nodes := &routerNodes{answers: map[string]routerAnswer{
		routerA: blockAnswer(routerA, release, nil), routerB: blockAnswer(routerB, release, nil),
	}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 1)
	svc.Runner.Executor = NewExecutor(1, 1, 0)
	req := validRequest(time.Now())
	// The queue bound is 200 ms; the expiration leaves seconds of margin.
	req.ExpiresAt = timestamppb.New(time.Now().Add(3 * time.Second))
	events, err := collect(t, svc, req)
	if err != nil {
		t.Fatal(err)
	}
	_, outcomes, c := checkGrammar(t, events)
	reasons := map[string]bool{}
	for _, o := range outcomes {
		reasons[o.GetFailure().GetReason()] = true
	}
	if !reasons[string(errcode.QueueTimeout)] || !reasons[string(errcode.DeadlineExceeded)] {
		t.Errorf("outcomes = %v, want one QueueTimeout and one DeadlineExceeded", outcomes)
	}
	if c.GetReason() != string(errcode.DeadlineExceeded) {
		t.Errorf("complete = %v", c)
	}
}

func TestServiceStreamFailureStopsExecution(t *testing.T) {
	// The snapshot cannot be delivered: no router runs.
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA), nodes, 8)
	events, done := run(t, svc, validRequest(time.Now()), -1)
	for range events {
	}
	if err := <-done; err == nil || nodes.total() != 0 {
		t.Errorf("snapshot failure: %v, %d calls", err, nodes.total())
	}

	// An outcome cannot be delivered: the router still running is
	// cancelled and RunDiagnostic returns.
	// router-b answers only once router-a is running, so router-a is under
	// way when the stream breaks.
	cancelled, running := make(chan struct{}), make(chan struct{})
	nodes = &routerNodes{answers: map[string]routerAnswer{
		routerA: func(ctx context.Context, _ *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			close(running)
			<-ctx.Done()
			close(cancelled)
			return nil, errcode.Status(errcode.Timeout, "cancelled")
		},
		routerB: func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
			<-running
			return pingObservation(routerB, 3), nil
		},
	}}
	svc = newService(t, routerPods(routerA, routerB), nodes, 8)
	events, done = run(t, svc, validRequest(time.Now()), 1)
	for range events {
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("RunDiagnostic succeeded on a broken stream")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunDiagnostic did not return")
	}
	select {
	case <-cancelled:
	default:
		t.Error("the running router was not cancelled")
	}
}

func TestRunnerStreamNeverRetries(t *testing.T) {
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: failAnswer(errcode.NodeUnreachable)}}
	r := &Runner{Clients: nodes, Executor: NewExecutor(0, 0, 0)}
	q := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY, Target: "",
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4})
	routers := []Node{{Name: routerA, Selected: true}}
	expires := time.Now().Add(10 * time.Second)
	r.Stream(t.Context(), "p", "id", q, routers, nil, expires, nil, func(Outcome) {})
	if n := nodes.total(); n != 1 {
		t.Errorf("Stream called the router %d times", n)
	}
	r.Run(t.Context(), "p", "id", q, routers, nil, expires)
	if n := nodes.total(); n != 3 {
		t.Errorf("Run no longer repeats a cheap read: %d calls in all", n)
	}
}

func TestServiceCapabilities(t *testing.T) {
	ctx := node.WithCaller(t.Context(), identity.Service(testSite, testService))
	svc := newService(t, nil, &routerNodes{}, 8)
	req := &servicev1.GetCapabilitiesRequest{Cell: testSite, ApiMajor: ServiceAPIMajor}
	on, err := svc.GetCapabilities(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !on.GetEnabled() || on.GetContractRevision() != "abc123" || len(on.GetOperations()) != 4 ||
		on.GetLimits().GetMaxSelectedRouters() != MaxServiceNodes ||
		on.GetLimits().GetMaxInventoryRouters() != MaxInventoryRouters || !on.GetGeneratedAt().IsValid() {
		t.Errorf("capabilities = %v", on)
	}
	for _, op := range on.GetOperations() {
		if len(op.GetAddressFamilies()) != 2 {
			t.Errorf("operation %v serves %d families", op.GetType(), len(op.GetAddressFamilies()))
		}
	}
	if a := on.GetLimits().GetAdmission(); a.GetProjectActiveJobs() != 2 || a.GetTraceroutePackets() != 20 ||
		a.GetRequestProject().GetBurst() != roomyLimits().RequestProject.Burst ||
		a.GetQueueWait().AsDuration() != limit.MaxQueueWait {
		t.Errorf("admission limits = %v", a)
	}
	if f := on.GetFeatures(); !slices.Equal(f, []string{
		FeatureRouterOutcomes, FeatureTerminalCoverage, FeatureAggregateProbeBudgets,
	}) {
		t.Errorf("features = %v", f)
	}
	again, _ := svc.GetCapabilities(ctx, req)
	svc.Enabled = false
	off, _ := svc.GetCapabilities(ctx, req)
	// With execution off nothing is advertised as enforced.
	if slices.Contains(off.GetFeatures(), FeatureAggregateProbeBudgets) || off.GetLimits().GetAdmission() != nil {
		t.Errorf("disabled capabilities = %v", off)
	}
	if again.GetPolicyRevision() != on.GetPolicyRevision() || off.GetPolicyRevision() == on.GetPolicyRevision() {
		t.Errorf("policy revisions %q, %q, %q", on.GetPolicyRevision(), again.GetPolicyRevision(), off.GetPolicyRevision())
	}

	// A request requiring an unserved feature, or a budget above its
	// maximum, is refused before any work.
	svc.Enabled = true
	for name, edit := range map[string]func(*runReq){
		"unknown feature": func(r *runReq) { r.RequiredFeatures = []string{"router-outcomes-v2"} },
		"large budget":    func(r *runReq) { r.Budgets = &fabricv1.Budgets{MaxPathsPerPrefix: 9} },
	} {
		req := validRequest(time.Now())
		edit(req)
		if events, err := collect(t, svc, req); err == nil || len(events) != 0 {
			t.Errorf("%s: %v, %d events", name, err, len(events))
		}
	}
	req2 := validRequest(time.Now())
	req2.RequiredFeatures = []string{FeatureRouterOutcomes, FeatureTerminalCoverage, FeatureAggregateProbeBudgets}
	req2.Budgets = &fabricv1.Budgets{MaxPathsPerPrefix: 8}
	if _, err := collect(t, svc, req2); err != nil {
		t.Errorf("served features: %v", err)
	}

	// Without an Admission the service is neither advertised as enabled nor
	// executes, and aggregate probe budgets are neither advertised nor
	// accepted as a requirement.
	svc.Admission = nil
	bare, _ := svc.GetCapabilities(ctx, req)
	if bare.GetEnabled() || slices.Contains(bare.GetFeatures(), FeatureAggregateProbeBudgets) ||
		bare.GetLimits().GetAdmission() != nil {
		t.Errorf("capabilities without admission = %v", bare)
	}
	req3 := validRequest(time.Now())
	req3.RequiredFeatures = []string{FeatureAggregateProbeBudgets}
	if _, err := collect(t, svc, req3); errcode.Of(err) != errcode.VersionUnsupported {
		t.Errorf("aggregate budgets required without admission: %v", err)
	}
	if _, err := collect(t, svc, validRequest(time.Now())); errcode.Of(err) != errcode.ServiceDisabled {
		t.Errorf("execution without admission: %v", err)
	}
}

// The generated public client receives the whole stream over mTLS, from the
// leader and relayed by a follower.
func TestServiceStreamOverTransport(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	svcCreds := loadCreds(t, ca, filepath.Join(dir, "svc"), identity.Service(testSite, testService))
	for _, name := range []string{"leader", "follower"} {
		// Each path gets its own leader, whose attempt cache has not seen
		// the request ID.
		leader := newService(t, routerPods(routerA, routerB), &routerNodes{}, 8)
		addr := serveGateway(t, gwCreds, &Debug{Elected: elected}, leader)
		if name == "follower" {
			addr = serveFollower(t, gwCreds, addr)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		stream, err := servicev1.NewLookingGlassServiceClient(dialAs(t, addr, svcCreds)).
			RunDiagnostic(ctx, validRequest(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		var events []*servicev1.DiagnosticEvent
		for {
			ev, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			events = append(events, ev)
		}
		cancel()
		if len(events) == 0 || events[0].GetRequestId() != testRequestID {
			t.Errorf("%s: events do not echo the request ID", name)
		}
		if _, _, c := checkGrammar(t, events); c.GetReason() != CompleteSucceeded || c.GetSuccessful() != 2 {
			t.Errorf("%s: complete = %v", name, c)
		}
	}
}

// stallReader blocks every List until its context ends.
type stallReader struct {
	client.Reader
	listing chan struct{}
}

func (r stallReader) List(ctx context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	r.listing <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

func TestServiceOwnershipLostDuringDiscovery(t *testing.T) {
	lease := newSwitchableLease(t)
	svc := newService(t, routerPods(routerA), &routerNodes{}, 8)
	adm, err := NewAdmission(roomyLimits(), &limit.Authority{
		Reader: lease, Namespace: DefaultNamespace, Name: testLease, Identity: testHolder, Hold: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	activate(t, adm)
	svc.Admission, svc.Runner.Admission, svc.Runner.Executor = adm, adm, adm.Executor()
	listing := make(chan struct{}, 1)
	svc.Discoverer.Reader = stallReader{Reader: svc.Discoverer.Reader, listing: listing}
	go adm.Authority.Watch(t.Context(), 50*time.Millisecond)

	_, done := run(t, svc, requestFor("project-a", 1, nil), 0)
	<-listing
	lease.fail(true)
	select {
	case err := <-done:
		if errcode.Of(err) != errcode.OwnershipLost {
			t.Errorf("err = %v, want OwnershipLost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discovery outlived the election")
	}
}
