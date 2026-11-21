// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// fakeWorkerClaims records the calls the manager makes.
type fakeWorkerClaims struct {
	mu        sync.Mutex
	requested []*workerv1alpha1.RequestRequest
	released  []*workerv1alpha1.ClaimKey
	requestFn func(key *workerv1alpha1.ClaimKey) error
	stream    chan *workerv1alpha1.ClaimStatus
	caps      []*workerv1alpha1.Capability
}

func (f *fakeWorkerClaims) Request(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requested = append(f.requested, &workerv1alpha1.RequestRequest{Key: key, Generation: gen, Spec: spec})
	if f.requestFn != nil {
		return nil, f.requestFn(key)
	}
	return &workerv1alpha1.ClaimStatus{Key: key}, nil
}

func (f *fakeWorkerClaims) Release(_ context.Context, key *workerv1alpha1.ClaimKey, _ uint64) (
	*workerv1alpha1.ClaimStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, key)
	return nil, nil
}

func (f *fakeWorkerClaims) Observe(context.Context, *workerv1alpha1.ClaimKey) (statusStream, error) {
	return chanStream(f.stream), nil
}

func (f *fakeWorkerClaims) Capabilities() *workerv1alpha1.GetCapabilitiesResponse {
	return &workerv1alpha1.GetCapabilitiesResponse{Capabilities: f.caps}
}

func (f *fakeWorkerClaims) Close() error { return nil }

func (f *fakeWorkerClaims) requests() []*workerv1alpha1.RequestRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*workerv1alpha1.RequestRequest(nil), f.requested...)
}

type chanStream chan *workerv1alpha1.ClaimStatus

func (c chanStream) Recv() (*workerv1alpha1.ClaimStatus, error) {
	st, ok := <-c
	if !ok {
		return nil, io.EOF
	}
	return st, nil
}

// fakePlumbing records what the manager programs.
type fakePlumbing struct {
	mu         sync.Mutex
	programmed []localTarget
	removed    []localTarget
	pruned     [][]localTarget
	fail       error
}

func (p *fakePlumbing) Program(t localTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return p.fail
	}
	p.programmed = append(p.programmed, t)
	return nil
}

func (p *fakePlumbing) Unprogram(t localTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removed = append(p.removed, t)
	return nil
}

func (p *fakePlumbing) Prune(keep []localTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruned = append(p.pruned, keep)
	return nil
}

const (
	testUID = "uid-a"
	vpcA    = "vpcA"
	vpcB    = "vpcB"
)

var testShard = shardIdentity{Name: "shard-a", UID: testUID}

func pairStatus(vpc string, ifindex int32, sid string, ready bool, reason string) *workerv1alpha1.ClaimStatus {
	cs := workerv1alpha1.ConditionStatus_CONDITION_STATUS_FALSE
	if ready {
		cs = workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
	}
	return &workerv1alpha1.ClaimStatus{
		Key:        &workerv1alpha1.ClaimKey{Node: "n1", Vpc: vpc, AttachmentUid: testShard.UID},
		Conditions: []*workerv1alpha1.Condition{{Type: workerv1alpha1.ConditionReady, Status: cs, Reason: reason}},
		HandoffInterfaces: []*workerv1alpha1.HandoffInterface{
			{Role: workerv1alpha1.HandoffRoleNAT, Name: "Gnat" + vpc, Ifindex: ifindex, TenantSid: sid},
			{Role: workerv1alpha1.HandoffRoleTenant, Name: "Gten" + vpc, Ifindex: ifindex + 1},
		},
	}
}

func newTestWorker() (*natWorker, *fakeWorkerClaims, *fakePlumbing) {
	plumb := &fakePlumbing{}
	claims := &fakeWorkerClaims{stream: make(chan *workerv1alpha1.ClaimStatus, 8)}
	w := newNATWorker("n1", func(context.Context) (claimAPI, error) { return claims, nil }, plumb)
	w.retry = 10 * time.Millisecond
	w.setSession(claims, true)
	return w, claims, plumb
}

func TestNATWorker_ClaimsOnePairPerVPCNamingItsShard(t *testing.T) {
	w, claims, _ := newTestWorker()
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcB, vpcA, vpcA, ""})
	w.reconcile(context.Background(), claims)

	reqs := claims.requests()
	if len(reqs) != 2 {
		t.Fatalf("requested %d claims, want one per VPC (2)", len(reqs))
	}
	for i, vpc := range []string{vpcA, vpcB} {
		r := reqs[i]
		if r.GetKey().GetVpc() != vpc || r.GetKey().GetNode() != "n1" || r.GetKey().GetAttachmentUid() != testUID {
			t.Errorf("claim %d key = %v, want node n1, VPC %s, the shard's UID", i, r.GetKey(), vpc)
		}
		spec := r.GetSpec()
		if spec.GetHandoff() != workerv1alpha1.Handoff_HANDOFF_VETH_PAIR || len(spec.GetDestinations()) != 1 ||
			spec.GetDestinations()[0].GetShard().GetName() != "shard-a" || r.GetGeneration() != claimGeneration {
			t.Errorf("claim %d = %v, want a veth_pair claim whose one destination is shard-a", i, r)
		}
	}

	// Accepted claims are not requested again on the next pass.
	w.reconcile(context.Background(), claims)
	if got := len(claims.requests()); got != 2 {
		t.Errorf("requested %d claims after a second pass, want still 2", got)
	}
}

func TestNATWorker_NoShardNoClaim(t *testing.T) {
	w, claims, _ := newTestWorker()
	w.SetVPCs([]string{vpcA})
	w.reconcile(context.Background(), claims)
	if got := len(claims.requests()); got != 0 {
		t.Errorf("requested %d claims with no programmed shard, want 0", got)
	}
	if r := w.snapshot().VPCs[vpcA]; r.Ready || r.Reason != "ShardNotProgrammed" {
		t.Errorf("readiness = %+v, want not ready, ShardNotProgrammed", r)
	}
}

func TestNATWorker_ProgramsReportedPairAndFollowsReplacement(t *testing.T) {
	w, claims, plumb := newTestWorker()
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA})
	w.reconcile(context.Background(), claims)

	sid := "fc00:0:1:1:123::"
	w.handleStatus(pairStatus(vpcA, 0, "", false, workerv1alpha1.ReasonPending))
	if len(plumb.programmed) != 0 {
		t.Fatalf("programmed %v before Worker reported a NAT end", plumb.programmed)
	}

	w.handleStatus(pairStatus(vpcA, 20, sid, true, workerv1alpha1.ReasonAsExpected))
	want := localTarget{VPC: vpcA, NATName: "GnatvpcA", NATIfindex: 20, TenantName: "GtenvpcA",
		TenantSID: netip.MustParseAddr(sid)}
	if len(plumb.programmed) != 1 || plumb.programmed[0] != want {
		t.Fatalf("programmed %+v, want %+v", plumb.programmed, want)
	}
	if r := w.snapshot().VPCs[vpcA]; !r.Ready {
		t.Errorf("readiness = %+v, want ready", r)
	}

	// The same status again changes nothing.
	w.handleStatus(pairStatus(vpcA, 20, sid, true, workerv1alpha1.ReasonAsExpected))
	if len(plumb.programmed) != 1 {
		t.Errorf("reprogrammed an unchanged pair: %+v", plumb.programmed)
	}

	// A recreated pair: new ifindex, same SID. The old rows go, the new
	// ones are written.
	w.handleStatus(pairStatus(vpcA, 30, sid, true, workerv1alpha1.ReasonAsExpected))
	if len(plumb.removed) != 1 || plumb.removed[0].NATIfindex != 20 {
		t.Errorf("removed %+v, want the old pair at ifindex 20", plumb.removed)
	}
	if len(plumb.programmed) != 2 || plumb.programmed[1].NATIfindex != 30 {
		t.Errorf("programmed %+v, want the new pair at ifindex 30", plumb.programmed)
	}

	// Withdrawal removes the rows.
	st := pairStatus(vpcA, 30, sid, false, workerv1alpha1.ReasonReleased)
	st.Released = true
	w.handleStatus(st)
	if len(plumb.removed) != 2 || plumb.removed[1].NATIfindex != 30 {
		t.Errorf("removed %+v, want the pair at ifindex 30 after the claim was released", plumb.removed)
	}
}

func TestNATWorker_ReleasesVPCsThatLeaveAndClaimsForANewShard(t *testing.T) {
	w, claims, plumb := newTestWorker()
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA, vpcB})
	w.reconcile(context.Background(), claims)
	w.handleStatus(pairStatus(vpcA, 20, "fc00::a", true, ""))

	w.SetVPCs([]string{vpcB})
	w.reconcile(context.Background(), claims)
	if len(claims.released) != 1 || claims.released[0].GetVpc() != vpcA {
		t.Fatalf("released %v, want vpcA's claim", claims.released)
	}
	if len(plumb.removed) != 1 || plumb.removed[0].VPC != vpcA {
		t.Errorf("removed %+v, want vpcA's pair", plumb.removed)
	}

	w.SetShard(shardIdentity{Name: "shard-b", UID: "uid-b"})
	w.reconcile(context.Background(), claims)
	w.reconcile(context.Background(), claims)
	if len(claims.released) != 2 || claims.released[1].GetAttachmentUid() != testUID {
		t.Fatalf("released %v, want vpcB's claim for the old shard", claims.released)
	}
	reqs := claims.requests()
	last := reqs[len(reqs)-1]
	if last.GetKey().GetAttachmentUid() != "uid-b" ||
		last.GetSpec().GetDestinations()[0].GetShard().GetName() != "shard-b" {
		t.Errorf("last request = %v, want vpcB's claim for shard-b", last)
	}
}

func workerError(code codes.Code, reason string) error {
	st, _ := status.New(code, reason).WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: workerv1alpha1.ErrorDomain})
	return st.Err()
}

func TestNATWorker_RefusalIsReportedAndRetried(t *testing.T) {
	w, claims, _ := newTestWorker()
	claims.requestFn = func(*workerv1alpha1.ClaimKey) error {
		return workerError(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	}
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA})
	w.reconcile(context.Background(), claims)
	if r := w.snapshot().VPCs[vpcA]; r.Ready || r.Reason != workerv1alpha1.ReasonVPCNotAuthorized {
		t.Errorf("readiness = %+v, want not ready, VPCNotAuthorized", r)
	}
	w.reconcile(context.Background(), claims)
	if got := len(claims.requests()); got != 2 {
		t.Errorf("requested %d times, want a refused claim retried on the next pass", got)
	}

	// A claim that exists already counts as made.
	claims.requestFn = func(*workerv1alpha1.ClaimKey) error {
		return workerError(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists)
	}
	w.reconcile(context.Background(), claims)
	w.reconcile(context.Background(), claims)
	if got := len(claims.requests()); got != 3 {
		t.Errorf("requested %d times, want no retry after ClaimExists", got)
	}
}

func TestNATWorker_PrunesOnceEveryClaimReported(t *testing.T) {
	w, claims, plumb := newTestWorker()
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA, vpcB})
	w.reconcile(context.Background(), claims)
	w.handleStatus(pairStatus(vpcA, 20, "fc00::a", true, ""))
	w.reconcile(context.Background(), claims)
	if len(plumb.pruned) != 0 {
		t.Fatalf("pruned before vpcB's claim reported: %v", plumb.pruned)
	}
	w.handleStatus(pairStatus(vpcB, 0, "", false, workerv1alpha1.ReasonPending))
	w.reconcile(context.Background(), claims)
	w.reconcile(context.Background(), claims)
	if len(plumb.pruned) != 1 || len(plumb.pruned[0]) != 1 || plumb.pruned[0][0].NATIfindex != 20 {
		t.Errorf("pruned %v, want one prune keeping vpcA's pair", plumb.pruned)
	}
}

func TestNATWorker_RunRequestsAgainAfterTheStreamEnds(t *testing.T) {
	plumb := &fakePlumbing{}
	var mu sync.Mutex
	var sessions []*fakeWorkerClaims
	dial := func(context.Context) (claimAPI, error) {
		mu.Lock()
		defer mu.Unlock()
		c := &fakeWorkerClaims{stream: make(chan *workerv1alpha1.ClaimStatus)}
		sessions = append(sessions, c)
		return c, nil
	}
	w := newNATWorker("n1", dial, plumb)
	w.retry = 10 * time.Millisecond
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sessions) == 1 && len(sessions[0].requests()) == 1
	})
	// Worker restarts: the stream ends.
	mu.Lock()
	close(sessions[0].stream)
	mu.Unlock()
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sessions) >= 2 && len(sessions[1].requests()) == 1
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOwnShard(t *testing.T) {
	programmed := []metav1.Condition{{Type: bgpv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue}}
	shard := func(name, node string, sid string, conds []metav1.Condition) bgpv1alpha1.EgressShard {
		s := bgpv1alpha1.EgressShard{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name)}}
		s.Spec.TargetRef.Name = node
		s.Status.ShardSID = sid
		s.Status.Conditions = conds
		return s
	}
	ok := shard("a", "n1", "fc00:9::", programmed)
	if got := ownShard([]bgpv1alpha1.EgressShard{ok, shard("b", "n2", "fc00:8::", programmed)}, "n1"); got !=
		(shardIdentity{Name: "a", UID: testUID}) {
		t.Errorf("ownShard = %+v, want shard a", got)
	}
	for name, shards := range map[string][]bgpv1alpha1.EgressShard{
		"none":         nil,
		"two":          {ok, shard("c", "n1", "fc00:7::", programmed)},
		"no SID":       {shard("a", "n1", "", programmed)},
		"unprogrammed": {shard("a", "n1", "fc00:9::", nil)},
	} {
		if got := ownShard(shards, "n1"); got.valid() {
			t.Errorf("%s: ownShard = %+v, want none", name, got)
		}
	}
}

func TestNodeVPCs(t *testing.T) {
	att := func(vpc, node string, deleting bool) cloudv1alpha1.VPCAttachment {
		a := cloudv1alpha1.VPCAttachment{}
		a.Status.VPC, a.Status.Node = vpc, node
		if deleting {
			now := metav1.Now()
			a.DeletionTimestamp = &now
		}
		return a
	}
	got := nodeVPCs([]cloudv1alpha1.VPCAttachment{
		att("A", "n1", false), att("A", "n1", false), att("B", "n2", false), att("C", "n1", true), att("", "n1", false),
		att("D", "n1", false),
	}, "n1")
	if strings.Join(got, ",") != "A,D" {
		t.Errorf("nodeVPCs = %v, want [A D]", got)
	}
}

type fakeCounters map[uint32][]uint64

func (f fakeCounters) Lookup(key, valueOut any) error {
	v, ok := f[key.(uint32)] //nolint:forcetypeassert // test-only
	if !ok {
		return errors.New("missing")
	}
	*valueOut.(*[]uint64) = v //nolint:forcetypeassert // test-only
	return nil
}

func TestWorkerCollector(t *testing.T) {
	w, claims, _ := newTestWorker()
	w.setSession(&fakeWorkerClaims{caps: []*workerv1alpha1.Capability{
		{Name: workerv1alpha1.CapabilityLocalVethPair, State: workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE,
			Allowed: true},
		{Name: workerv1alpha1.CapabilityLocalTap, State: workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE},
	}}, true)
	w.SetShard(testShard)
	w.SetVPCs([]string{vpcA})
	w.reconcile(context.Background(), claims)
	w.handleStatus(pairStatus(vpcA, 20, "fc00::a", false, workerv1alpha1.ReasonHandoffHookMissing))

	c := &workerCollector{worker: w, stats: fakeCounters{0: {3, 4}, 1: {5}, 2: {0}, 3: {1}}}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			parts := []string{f.GetName()}
			for _, l := range m.GetLabel() {
				parts = append(parts, l.GetName()+"="+l.GetValue())
			}
			key := strings.Join(parts, ",")
			v := m.GetGauge().GetValue() + m.GetCounter().GetValue()
			got[key] = v
		}
	}
	for key, want := range map[string]float64{
		"galactic_nat_worker_session_up": 1,
		"galactic_nat_worker_capability_available,capability=local.tap,reason=CapabilityNotAllowed": 0,
		"galactic_nat_worker_capability_available,capability=local.veth_pair,reason=":               1,
		"galactic_nat_local_handoff_ready,reason=HandoffHookMissing,vpc=vpcA":                       0,
		"galactic_nat_local_packets_total,stat=forward":                                             7,
		"galactic_nat_local_packets_total,stat=return":                                              5,
		"galactic_nat_local_packets_total,stat=return_no_pair":                                      0,
		"galactic_nat_local_packets_total,stat=forward_unclaimed":                                   1,
	} {
		if v, ok := got[key]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, want)
		}
	}
	if len(got) != 8 {
		t.Errorf("collected %d series, want 8: %v", len(got), got)
	}

	w.setSession(nil, false)
	if r := w.snapshot().VPCs[vpcA]; r.Ready || r.Reason != "NoSession" {
		t.Errorf("readiness without a session = %+v, want NoSession", r)
	}
}
