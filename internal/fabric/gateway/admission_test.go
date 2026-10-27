// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/node"
)

const (
	testLease  = "fabric-api-gateway"
	testHolder = "gateway-0_test"
	// probeTarget6 and probeTarget4 are probe destinations.
	probeTarget6 = "2606:4700::1"
	probeTarget4 = "9.9.9.9"
	// podA is router-a's fabric-router pod UID.
	podA = "pod-a"
)

// switchableLease serves an election Lease held by testHolder, whose reads
// fail while failing is set.
type switchableLease struct {
	client.Client
	mu      sync.Mutex
	failing bool
}

func (l *switchableLease) fail(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failing = on
}

func newSwitchableLease(t *testing.T) *switchableLease {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	l := &switchableLease{}
	l.Client = fake.NewClientBuilder().WithScheme(s).WithObjects(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultNamespace, Name: testLease, UID: "lease-uid"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: ptr.To(testHolder), LeaseDurationSeconds: ptr.To[int32](15),
			// Renewed in the future, so the term never lapses during a test.
			RenewTime: &metav1.MicroTime{Time: time.Now().Add(time.Hour)},
		},
	}).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			l.mu.Lock()
			failing := l.failing
			l.mu.Unlock()
			if failing {
				return errors.New("api unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	return l
}

// roomyLimits are limits no ordinary test reaches.
func roomyLimits() limit.Limits {
	l := limit.Defaults()
	big := limit.Rate{PerSecond: 1000, Burst: 10000}
	l.RequestCell, l.RequestProject = big, big
	l.PacketCell, l.PacketPrincipal, l.PacketHost, l.PacketPrefix = big, big, big, big
	l.ProjectStreams = l.Streams
	return l
}

// newTestAdmission returns an admission whose authority has already served
// its recovery hold, with every bucket refilled.
func newTestAdmission(t *testing.T, l limit.Limits) *Admission {
	t.Helper()
	lease := newSwitchableLease(t)
	auth := &limit.Authority{
		Reader: lease, Namespace: DefaultNamespace, Name: testLease, Identity: testHolder, Hold: time.Nanosecond,
	}
	adm, err := NewAdmission(l, auth)
	if err != nil {
		t.Fatal(err)
	}
	activate(t, adm)
	return adm
}

// activate ends the authority's hold and fills its buckets.
func activate(t *testing.T, adm *Admission) {
	t.Helper()
	_, _, _ = adm.Authority.Check(t.Context())
	time.Sleep(time.Millisecond)
	if _, _, err := adm.Authority.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	adm.Buckets.Reset(time.Now().Add(-time.Hour))
}

// withAdmission gives svc and its runner a fresh admission under l, and an
// executor bounded by l.
func withAdmission(t *testing.T, svc *Service, l limit.Limits) *Admission {
	t.Helper()
	adm := newTestAdmission(t, l)
	svc.Admission, svc.Runner.Admission = adm, adm
	svc.Runner.Executor = adm.Executor()
	return adm
}

// requestID returns a distinct lowercase UUID for n.
func requestID(n int) string {
	return fmt.Sprintf("%08x-926f-43dc-b03d-c29550a827ab", n)
}

func requestFor(project string, n int, mod func(*runReq)) *runReq {
	req := validRequest(time.Now())
	req.ProjectId, req.RequestId = project, requestID(n)
	if mod != nil {
		mod(req)
	}
	return req
}

func wantRetry(t *testing.T, err error, code errcode.Code, scope string) time.Duration {
	t.Helper()
	if errcode.Of(err) != code {
		t.Fatalf("err = %v, want %s", err, code)
	}
	md := errcode.Metadata(err)
	if md[errcode.MetadataScope] != scope || md[errcode.MetadataExecutionStarted] != "false" {
		t.Fatalf("metadata = %v, want scope %s", md, scope)
	}
	d, ok := errcode.RetryDelay(err)
	if !ok || d <= 0 {
		t.Fatalf("no retry guidance on %v", err)
	}
	return d
}

func TestServiceRequestTokens(t *testing.T) {
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA), nodes, 8)
	l := roomyLimits()
	l.RequestProject = limit.Rate{PerSecond: 0.2, Burst: 2}
	withAdmission(t, svc, l)

	for i := range 2 {
		if _, err := collect(t, svc, requestFor("project-a", i, nil)); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	calls := nodes.total()
	_, err := collect(t, svc, requestFor("project-a", 2, nil))
	if d := wantRetry(t, err, errcode.Throttled, "project"); d > 5*time.Second {
		t.Errorf("retry %s exceeds one token at 0.2/s", d)
	}
	if nodes.total() != calls {
		t.Error("a throttled request reached a router")
	}
	// Another project, behind the same service identity, is not throttled.
	if _, err := collect(t, svc, requestFor("project-b", 3, nil)); err != nil {
		t.Errorf("project-b: %v", err)
	}
}

func TestServiceDuplicateAttempts(t *testing.T) {
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA), nodes, 8)
	if _, err := collect(t, svc, requestFor("project-a", 1, nil)); err != nil {
		t.Fatal(err)
	}
	calls := nodes.total()
	_, err := collect(t, svc, requestFor("project-a", 1, nil))
	if errcode.Of(err) != errcode.DuplicateRequest {
		t.Errorf("identical retry: %v", err)
	}
	// A later expiration is the same attempt.
	_, err = collect(t, svc, requestFor("project-a", 1, func(r *runReq) {
		r.ExpiresAt = timestamppb.New(time.Now().Add(40 * time.Second))
	}))
	if errcode.Of(err) != errcode.DuplicateRequest {
		t.Errorf("retry with a later expiration: %v", err)
	}
	_, err = collect(t, svc, requestFor("project-a", 1, func(r *runReq) { r.Query.Target = "2606:4700::2" }))
	if errcode.Of(err) != errcode.DuplicateConflict {
		t.Errorf("changed arguments: %v", err)
	}
	if nodes.total() != calls {
		t.Error("a duplicate reached a router")
	}
	// The same request ID in another project is another attempt.
	if _, err := collect(t, svc, requestFor("project-b", 1, nil)); err != nil {
		t.Errorf("other project: %v", err)
	}
}

func TestServiceStreamLimit(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: blockAnswer(routerA, release, started)}}
	svc := newService(t, routerPods(routerA), nodes, 8)
	l := roomyLimits()
	l.ProjectStreams = 1
	withAdmission(t, svc, l)

	events, done := run(t, svc, requestFor("project-a", 1, nil), 0)
	<-started
	_, err := collect(t, svc, requestFor("project-a", 2, nil))
	wantRetry(t, err, errcode.QueueFull, "queue")
	close(release)
	for range events {
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The ended stream no longer counts.
	if _, err := collect(t, svc, requestFor("project-a", 3, nil)); err != nil {
		t.Errorf("after the first stream ended: %v", err)
	}
}

// A request's router jobs are admitted to the queue all together or not at
// all: a second request from a project whose first still fills its share
// is refused before its snapshot, and runs nothing.
func TestServiceAtomicQueueReservation(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	answers := map[string]routerAnswer{}
	for _, n := range []string{routerA, routerB, routerC} {
		answers[n] = blockAnswer(n, release, started)
	}
	nodes := &routerNodes{answers: answers}
	svc := newService(t, routerPods(routerA, routerB, routerC), nodes, 8)
	l := roomyLimits()
	l.PrincipalSlots, l.PrincipalQueue = 2, 3
	withAdmission(t, svc, l)

	events, done := run(t, svc, requestFor("project-a", 1, nil), 0)
	<-started
	<-started
	waitDepth(t, svc.Runner.Executor, 1)
	got, err := collect(t, svc, requestFor("project-a", 2, nil))
	wantRetry(t, err, errcode.QueueFull, "queue")
	if len(got) != 0 {
		t.Errorf("a refused request sent %d events", len(got))
	}
	// Another project's share is its own.
	other, otherDone := run(t, svc, requestFor("project-b", 3, nil), 0)
	close(release)
	for range events {
	}
	for range other {
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-otherDone; err != nil {
		t.Fatal(err)
	}
	if n := nodes.total(); n != 6 {
		t.Errorf("%d router calls, want 6", n)
	}
}

func TestServicePacketBudget(t *testing.T) {
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA, routerB, routerC), nodes, 8)
	l := roomyLimits()
	// One traceroute's worth of packets per destination host.
	l.PacketHost = limit.Rate{PerSecond: 1, Burst: limit.TraceroutePackets}
	withAdmission(t, svc, l)

	events, err := collect(t, svc, requestFor("project-a", 1, func(r *runReq) {
		r.Query.Type = fabricv1.QueryType_QUERY_TYPE_TRACEROUTE
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, outcomes, c := checkGrammar(t, events)
	throttled := 0
	for _, o := range outcomes {
		if o.GetFailure().GetReason() == string(errcode.Throttled) {
			throttled++
		}
	}
	if throttled != 2 || c.GetSuccessful() != 1 || c.GetReason() != CompletePartialResults {
		t.Errorf("throttled %d, complete %v", throttled, c)
	}
	for _, o := range outcomes {
		if f := o.GetFailure(); f != nil && (f.GetScope() != "destination" || f.GetRetryDelay().AsDuration() <= 0) {
			t.Errorf("throttled router carries no retry guidance: %v", f)
		}
	}
	if n := nodes.total(); n != 1 {
		t.Errorf("%d routers probed, want 1", n)
	}
}

func TestServiceRecoveryHold(t *testing.T) {
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA), nodes, 8)
	adm, err := NewAdmission(roomyLimits(), &limit.Authority{
		Reader: newSwitchableLease(t), Namespace: DefaultNamespace, Name: testLease, Identity: testHolder,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.Admission, svc.Runner.Admission = adm, adm
	_, err = collect(t, svc, requestFor("project-a", 1, nil))
	if d := wantRetry(t, err, errcode.LimiterUnavailable, "cell"); d > limit.RecoveryHold ||
		d < limit.RecoveryHold-time.Minute {
		t.Errorf("remaining hold %s", d)
	}
	if nodes.total() != 0 {
		t.Error("a request ran during the recovery hold")
	}
	// Operator and FabricQuery probes wait out the hold too; reads do not.
	ping := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: probeTarget6,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6})
	routers := []Node{{Name: routerA, PodUID: podA, Selected: true}}
	out := svc.Runner.Run(t.Context(), "operator/alice", "op-1", ping, routers, nil, time.Now().Add(10*time.Second))
	if errcode.Of(out[0].Err) != errcode.LimiterUnavailable {
		t.Errorf("operator probe during the hold: %v", out[0].Err)
	}
	summary := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4})
	out = svc.Runner.Run(t.Context(), "ns/cluster", "fq-1", summary, routers, nil, time.Now().Add(10*time.Second))
	if out[0].Err != nil {
		t.Errorf("FabricQuery read during the hold: %v", out[0].Err)
	}
}

// Losing the election cancels the request's running routers and ends the
// stream with OwnershipLost, every selected router accounted for.
func TestServiceOwnershipLost(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	lease := newSwitchableLease(t)
	nodes := &routerNodes{answers: map[string]routerAnswer{
		routerA: blockAnswer(routerA, release, started), routerB: blockAnswer(routerB, release, started),
	}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 8)
	l := roomyLimits()
	l.PrincipalSlots = 1
	adm, err := NewAdmission(l, &limit.Authority{
		Reader: lease, Namespace: DefaultNamespace, Name: testLease, Identity: testHolder, Hold: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	activate(t, adm)
	svc.Admission, svc.Runner.Admission, svc.Runner.Executor = adm, adm, adm.Executor()
	defer close(release)
	go adm.Authority.Watch(t.Context(), 50*time.Millisecond)

	events, done := run(t, svc, requestFor("project-a", 1, nil), 0)
	<-started
	// One router runs and the other waits for its slot when the lease
	// becomes unreadable; the watch notices within its interval.
	lost := time.Now()
	lease.fail(true)
	var got []*servicev1.DiagnosticEvent
	for ev := range events {
		got = append(got, ev)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d := time.Since(lost); d > 2*time.Second {
		t.Errorf("work outlived the loss by %s", d)
	}
	_, outcomes, c := checkGrammar(t, got)
	if len(outcomes) != 2 || c.GetReason() != string(errcode.OwnershipLost) || c.GetFailed() != 2 {
		t.Errorf("outcomes %v, complete %v", outcomes, c)
	}
}

func TestRunnerRefusesNodesWithoutPermits(t *testing.T) {
	nodes := &routerNodes{legacy: map[string]bool{routerA: true}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 8)
	events, err := collect(t, svc, requestFor("project-a", 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, outcomes, _ := checkGrammar(t, events)
	for _, o := range outcomes {
		want := ""
		if o.GetNode() == routerA {
			want = string(errcode.QueryTypeUnavailable)
		}
		if o.GetFailure().GetReason() != want {
			t.Errorf("%s: %v", o.GetNode(), o)
		}
	}
	nodes.mu.Lock()
	defer nodes.mu.Unlock()
	if nodes.calls[routerA] != 0 {
		t.Error("a probe reached a node that does not enforce permits")
	}
}

func TestRunnerAttachesPermit(t *testing.T) {
	var mu sync.Mutex
	var got *fabricv1.ProbePermit
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: func(_ context.Context,
		req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		mu.Lock()
		got = req.GetPermit()
		mu.Unlock()
		return pingObservation(routerA, 3), nil
	}}}
	svc := newService(t, routerPods(routerA), nodes, 8)
	req := requestFor("project-a", 1, nil)
	if _, err := collect(t, svc, req); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.GetEpoch() != "lease-uid/"+testHolder || got.GetNode() != routerA || got.GetRequestId() != req.GetRequestId() ||
		got.GetDestination() != probeTarget6 || got.GetPackets() != limit.PingPackets || got.GetId() == "" ||
		got.GetOperation() != fabricv1.QueryType_QUERY_TYPE_PING ||
		got.GetDeadline().AsTime().After(req.GetExpiresAt().AsTime()) {
		t.Errorf("permit = %v", got)
	}
}

// A probe whose node answer was lost keeps its slot until the job's
// deadline plus the grace: the node may still be sending it. A typed
// answer, or a read without an answer, frees the slot at once.
func TestRunnerHoldsSlotWithoutAnswer(t *testing.T) {
	lost := func(context.Context, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		return nil, status.Error(codes.Unavailable, "connection reset")
	}
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: lost, routerB: failAnswer(errcode.FRRUnavailable)}}
	adm := newTestAdmission(t, roomyLimits())
	r := &Runner{Clients: nodes, Executor: NewExecutor(1, 0, 0), Admission: adm}
	summary := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4})
	ping := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: probeTarget6,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6})
	nodeA := []Node{{Name: routerA, PodUID: podA, Selected: true}}
	nodeB := []Node{{Name: routerB, PodUID: "pod-b", Selected: true}}
	later := time.Now().Add(time.Minute)

	for name, run := range map[string]func(){
		"typed failure":       func() { r.Run(t.Context(), "p", "id-1", ping, nodeB, nil, later) },
		"read without answer": func() { r.Run(t.Context(), "p", "id-2", summary, nodeA, nil, later) },
	} {
		run()
		rel, err := tryAcquire(r.Executor)
		if err != nil {
			t.Fatalf("%s: slot held: %v", name, err)
		}
		rel()
	}
	// A probe without an answer: held.
	expires := time.Now().Add(300 * time.Millisecond)
	r.Run(t.Context(), "p", "id-3", ping, nodeA, nil, expires)
	if _, err := tryAcquire(r.Executor); err == nil {
		t.Fatal("slot freed although the node never answered")
	}
	// Released after the deadline plus the grace.
	time.Sleep(time.Until(expires.Add(ReservationGrace + 100*time.Millisecond)))
	if rel, err := tryAcquire(r.Executor); err != nil {
		t.Fatalf("slot still held past its grace: %v", err)
	} else {
		rel()
	}
}

func tryAcquire(e *Executor) (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	return e.Acquire(ctx, "probe", false)
}

// The published capabilities fixture shows the contract's default limits
// exactly as a gateway reports them.
func TestCapabilitiesFixtureMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile("../../../api/fabric/service/v1/testdata/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var caps servicev1.GetCapabilitiesResponse
	if err := protojson.Unmarshal(data, &caps); err != nil {
		t.Fatal(err)
	}
	if want := admissionLimits(limit.Defaults()); !proto.Equal(caps.GetLimits().GetAdmission(), want) {
		t.Errorf("fixture admission = %v, want %v", caps.GetLimits().GetAdmission(), want)
	}
}

// With aggregate budgets a full principal queue refuses an operator or
// FabricQuery job with QueueFull and retry guidance.
func TestRunnerQueueFull(t *testing.T) {
	adm := newTestAdmission(t, roomyLimits())
	e := NewExecutor(1, 0, 1)
	r := &Runner{Clients: &routerNodes{}, Executor: e, Admission: adm}
	hold, err := e.Acquire(t.Context(), "other", false)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if rel, err := e.Acquire(ctx, "other", false); err == nil {
			rel()
		}
	}()
	waitDepth(t, e, 1)
	summary := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4})
	out := r.Run(t.Context(), "ns/cluster", "fq-1", summary, []Node{{Name: routerA, Selected: true}}, nil,
		time.Now().Add(10*time.Second))
	wantRetry(t, out[0].Err, errcode.QueueFull, "queue")
}
