// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/pkg/workerclient"
)

// scriptedWorker is a WorkerClient holding one claim per attachment, with
// Worker's generation rules.
type scriptedWorker struct {
	mu     sync.Mutex
	gen    map[string]uint64
	spec   map[string]*workerv1alpha1.ClaimSpec
	calls  []string
	refuse error
}

func newScriptedWorker() *scriptedWorker {
	return &scriptedWorker{gen: map[string]uint64{}, spec: map[string]*workerv1alpha1.ClaimSpec{}}
}

func genMD(gen uint64) map[string]string {
	return map[string]string{workerv1alpha1.MetadataCurrentGeneration: strconv.FormatUint(gen, 10)}
}

func (s *scriptedWorker) Request(_ context.Context, k *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "request/"+strconv.FormatUint(gen, 10))
	if s.refuse != nil {
		return nil, s.refuse
	}
	uid := k.GetAttachmentUid()
	if cur, ok := s.gen[uid]; ok {
		return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists, "exists", genMD(cur))
	}
	s.gen[uid], s.spec[uid] = gen, spec
	return &workerv1alpha1.ClaimStatus{Key: k, Generation: gen}, nil
}

func (s *scriptedWorker) Update(_ context.Context, k *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "update/"+strconv.FormatUint(gen, 10))
	uid := k.GetAttachmentUid()
	cur, ok := s.gen[uid]
	switch {
	case !ok:
		return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimNotFound, "none", nil)
	case gen < cur:
		return nil, refusal.New(codes.Aborted, workerv1alpha1.ReasonStaleGeneration, "stale", genMD(cur))
	case gen == cur && !proto.Equal(spec, s.spec[uid]):
		return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonGenerationConflict, "conflict",
			genMD(cur))
	}
	s.gen[uid], s.spec[uid] = gen, spec
	return &workerv1alpha1.ClaimStatus{Key: k, Generation: gen}, nil
}

func (s *scriptedWorker) Release(_ context.Context, k *workerv1alpha1.ClaimKey,
	gen uint64) (*workerv1alpha1.ClaimStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "release/"+strconv.FormatUint(gen, 10))
	uid := k.GetAttachmentUid()
	cur, ok := s.gen[uid]
	switch {
	case !ok:
		return nil, nil
	case gen < cur:
		return nil, refusal.New(codes.Aborted, workerv1alpha1.ReasonStaleGeneration, "stale", genMD(cur))
	}
	delete(s.gen, uid)
	return &workerv1alpha1.ClaimStatus{Key: k, Generation: gen, Released: true}, nil
}

func (s *scriptedWorker) Observe(context.Context, *workerv1alpha1.ClaimKey) (*workerclient.Observer, error) {
	return nil, errors.New("not served")
}

func (s *scriptedWorker) takeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = nil
	return out
}

// nopGates is LinkGates that records nothing.
type nopGates struct{}

func (nopGates) SetLink(uint32, netip.Addr) error { return nil }
func (nopGates) DeleteGates(uint32) error         { return nil }
func (nopGates) DeleteLink(uint32) error          { return nil }

var testLink = Link{VPC: vpcA, AttachmentUID: uid1, Index: 7, Name: "E00000000aXXXXX",
	Addr: netip.MustParseAddr("2001:db8:100::10")}

// TestWorkerDatapathResumesGeneration takes up the generation a claim had
// before galactic-edge restarted, which Worker reports in its refusal, and
// sends nothing for a spec Worker already holds.
func TestWorkerDatapathResumesGeneration(t *testing.T) {
	w := newScriptedWorker()
	w.gen[uid1] = 7
	d := &WorkerDatapath{Client: w, Node: node, Gates: nopGates{}}
	if err := d.Prepare(testLink); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.takeCalls(), ","); got != "request/1,update/8" {
		t.Fatalf("calls = %s, want request/1,update/8", got)
	}
	if err := d.Prepare(testLink); err != nil {
		t.Fatal(err)
	}
	if got := w.takeCalls(); len(got) != 0 {
		t.Fatalf("an unchanged spec was sent again: %v", got)
	}
	// A prefix change is sent at the next generation.
	if err := d.SyncRoutes(0, []LinkRoutes{{Link: testLink,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:200::/48")}}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.takeCalls(), ","); got != "update/9" {
		t.Fatalf("calls = %s, want update/9", got)
	}
	if got := w.spec[uid1].GetEdgeLink().GetPrefixes(); len(got) != 1 || got[0] != "2001:db8:200::/48" {
		t.Fatalf("prefixes Worker holds = %v", got)
	}
}

// TestWorkerDatapathReleasesUnknownClaim releases a claim this process never
// saw from the generation Worker reports.
func TestWorkerDatapathReleasesUnknownClaim(t *testing.T) {
	w := newScriptedWorker()
	w.gen[uid1] = 4
	d := &WorkerDatapath{Client: w, Node: node, Gates: nopGates{}}
	if err := d.Unregister(testLink); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.takeCalls(), ","); got != "release/1,release/4" {
		t.Fatalf("calls = %s, want release/1,release/4", got)
	}
	if _, ok := w.gen[uid1]; ok {
		t.Fatal("the claim was not released")
	}
	// Clearing an ifindex with no attachment touches no claim.
	if err := d.Unregister(Link{VPC: vpcA, Index: 7}); err != nil {
		t.Fatal(err)
	}
	if got := w.takeCalls(); len(got) != 0 {
		t.Fatalf("clearing an ifindex called Worker: %v", got)
	}
}

// TestWorkerDatapathRefusal reports Worker's refusal as WorkerRefused with
// Worker's reason, and a revoked claim's status the same way.
func TestWorkerDatapathRefusal(t *testing.T) {
	w := newScriptedWorker()
	w.refuse = refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized, "not admitted", nil)
	d := &WorkerDatapath{Client: w, Node: node, Gates: nopGates{}, Wait: 50 * time.Millisecond}
	err := d.Register(testLink)
	var we *WorkerError
	if !errors.As(err, &we) || we.Reason != ReasonWorkerRefused ||
		we.WorkerReason != workerv1alpha1.ReasonVPCNotAuthorized {
		t.Fatalf("Register = %v, want WorkerRefused/VPCNotAuthorized", err)
	}
	if workerReason(err) != ReasonWorkerRefused {
		t.Fatalf("condition reason = %s", workerReason(err))
	}

	// Admitted, then revoked while Register waits.
	w.refuse = nil
	d = &WorkerDatapath{Client: w, Node: node, Gates: nopGates{}, Wait: time.Second}
	go func() {
		time.Sleep(20 * time.Millisecond)
		d.record(&workerv1alpha1.ClaimStatus{Key: &workerv1alpha1.ClaimKey{Node: node, Vpc: vpcA,
			AttachmentUid: uid1}, Generation: 1, ObservedGeneration: 1,
			Conditions: []*workerv1alpha1.Condition{{Type: workerv1alpha1.ConditionAdmitted,
				Status: workerv1alpha1.ConditionStatus_CONDITION_STATUS_FALSE,
				Reason: workerv1alpha1.ReasonAuthorizationRevoked}}})
	}()
	err = d.Register(testLink)
	if !errors.As(err, &we) || we.WorkerReason != workerv1alpha1.ReasonAuthorizationRevoked {
		t.Fatalf("Register of a revoked claim = %v, want AuthorizationRevoked", err)
	}

	// No status in time is WorkerPending, which keeps nothing Programmed.
	d = &WorkerDatapath{Client: newScriptedWorker(), Node: node, Gates: nopGates{}, Wait: 20 * time.Millisecond}
	err = d.Register(testLink)
	if !errors.As(err, &we) || we.Reason != ReasonWorkerPending || we.Unreachable {
		t.Fatalf("Register with no status = %v, want WorkerPending and reachable", err)
	}

	// A Worker that cannot answer is unreachable, resyncing included.
	for _, down := range []error{
		errWorkerDown,
		refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "resyncing", nil),
	} {
		w := newScriptedWorker()
		w.refuse = down
		d = &WorkerDatapath{Client: w, Node: node, Gates: nopGates{}}
		err = d.Prepare(testLink)
		if !errors.As(err, &we) || we.Reason != ReasonWorkerUnavailable || !we.Unreachable {
			t.Fatalf("Prepare against %v = %v, want WorkerUnavailable and unreachable", down, err)
		}
	}
}

// TestCollectorWorker exports Worker's capability state and the claims by
// state.
func TestCollectorWorker(t *testing.T) {
	d := &WorkerDatapath{Client: newScriptedWorker(), Node: node, Gates: nopGates{},
		Capabilities: func() *workerv1alpha1.GetCapabilitiesResponse {
			return &workerv1alpha1.GetCapabilitiesResponse{Capabilities: []*workerv1alpha1.Capability{
				{Name: workerv1alpha1.CapabilityLocalRoutedLink,
					State: workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE},
				{Name: workerv1alpha1.CapabilityLocalTap, State: workerv1alpha1.CapabilityState_CAPABILITY_STATE_UNAVAILABLE,
					Reason: workerv1alpha1.ReasonDatapathNotLoaded},
			}}
		}}
	cond := func(t string, ok bool) *workerv1alpha1.Condition {
		s := workerv1alpha1.ConditionStatus_CONDITION_STATUS_FALSE
		if ok {
			s = workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
		}
		return &workerv1alpha1.Condition{Type: t, Status: s}
	}
	d.record(&workerv1alpha1.ClaimStatus{Key: &workerv1alpha1.ClaimKey{Node: node, Vpc: vpcA, AttachmentUid: "a"},
		Generation: 1, ObservedGeneration: 1, Conditions: []*workerv1alpha1.Condition{
			cond(workerv1alpha1.ConditionAdmitted, true), cond(workerv1alpha1.ConditionReady, true)}})
	d.record(&workerv1alpha1.ClaimStatus{Key: &workerv1alpha1.ClaimKey{Node: node, Vpc: vpcA, AttachmentUid: "b"},
		Generation: 1, ObservedGeneration: 1, Conditions: []*workerv1alpha1.Condition{
			cond(workerv1alpha1.ConditionAdmitted, false)}})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(Collector{Agent: &Agent{Datapath: d, MTU: mtu}})
	want := "# HELP galactic_edge_foundation_worker_capability Galactic Worker's state of each capability, " +
		"as it last reported it to galactic-edge: 1 when available. reason is Worker's contract reason for " +
		"an unavailable one. Exported only when Worker registers the node's edge links (--worker-socket).\n" +
		"# TYPE galactic_edge_foundation_worker_capability gauge\n" +
		`galactic_edge_foundation_worker_capability{capability="local.routed_link",reason=""} 1` + "\n" +
		`galactic_edge_foundation_worker_capability{capability="local.tap",reason="DatapathNotLoaded"} 0` + "\n" +
		"# HELP galactic_edge_foundation_worker_claims galactic-edge's edge link claims on Galactic Worker, " +
		"by state: ready, programmed (not yet carrying traffic), pending (not yet programmed) or refused " +
		"(not admitted).\n" +
		"# TYPE galactic_edge_foundation_worker_claims gauge\n" +
		`galactic_edge_foundation_worker_claims{state="pending"} 0` + "\n" +
		`galactic_edge_foundation_worker_claims{state="programmed"} 0` + "\n" +
		`galactic_edge_foundation_worker_claims{state="ready"} 1` + "\n" +
		`galactic_edge_foundation_worker_claims{state="refused"} 1` + "\n"
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "galactic_edge_foundation_worker_capability",
		"galactic_edge_foundation_worker_claims"); err != nil {
		t.Fatal(err)
	}
}
