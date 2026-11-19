// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/refusal"
)

const (
	claimTestNode = "node-a"
	testVPCA      = "vpcA"
	testVPCB      = "vpcB"
	testProxyA    = "proxy-a"
	// testBackendALocal is VPC A's backend on this node.
	testBackendALocal = "be-a-local"
)

// fakeWorker is a ClaimClient that keeps claims by VPC and refuses calls
// while held is set, as Worker does while another pod holds a claim.
type fakeWorker struct {
	claims map[string]*workerv1alpha1.ClaimStatus
	specs  map[string]*workerv1alpha1.ClaimSpec
	held   bool
	calls  []string
	// modes is how the fake resolves each destination attachment.
	modes map[string]workerv1alpha1.Mode
}

func newFakeWorker() *fakeWorker {
	return &fakeWorker{claims: map[string]*workerv1alpha1.ClaimStatus{},
		specs: map[string]*workerv1alpha1.ClaimSpec{}, modes: map[string]workerv1alpha1.Mode{}}
}

func (f *fakeWorker) status(key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) *workerv1alpha1.ClaimStatus {
	st := &workerv1alpha1.ClaimStatus{Key: key, Generation: gen, ObservedGeneration: gen,
		Conditions: []*workerv1alpha1.Condition{{Type: workerv1alpha1.ConditionReady,
			Status: workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE}},
		HandoffInterfaces: []*workerv1alpha1.HandoffInterface{
			{Role: workerv1alpha1.HandoffRoleHost, Name: "Ghost", Ifindex: 5, LinkLocal: "fe80::1"},
			{Role: workerv1alpha1.HandoffRolePod, Name: "Gpod" + key.GetVpc(), Ifindex: 2},
		}}
	for _, d := range spec.GetDestinations() {
		mode, ok := f.modes[d.GetAttachment().GetUid()]
		st.Destinations = append(st.Destinations, &workerv1alpha1.DestinationStatus{Destination: d,
			Mode: mode, Resolved: ok, Ready: ok})
	}
	return st
}

func (f *fakeWorker) Request(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	f.calls = append(f.calls, fmt.Sprintf("request %s %d", key.GetVpc(), gen))
	if cur, ok := f.claims[key.GetVpc()]; ok {
		if f.held {
			return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimHeldByAnotherPod, "held", nil)
		}
		if cur.GetGeneration() != gen {
			return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists, "exists", nil)
		}
	}
	f.claims[key.GetVpc()], f.specs[key.GetVpc()] = f.status(key, gen, spec), spec
	return f.claims[key.GetVpc()], nil
}

func (f *fakeWorker) Update(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	f.calls = append(f.calls, fmt.Sprintf("update %s %d", key.GetVpc(), gen))
	cur, ok := f.claims[key.GetVpc()]
	switch {
	case !ok:
		return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimNotFound, "missing", nil)
	case f.held:
		return nil, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimHeldByAnotherPod, "held", nil)
	case gen <= cur.GetGeneration():
		return nil, refusal.New(codes.Aborted, workerv1alpha1.ReasonStaleGeneration, "stale", nil)
	}
	f.claims[key.GetVpc()], f.specs[key.GetVpc()] = f.status(key, gen, spec), spec
	return f.claims[key.GetVpc()], nil
}

func (f *fakeWorker) Release(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64) (
	*workerv1alpha1.ClaimStatus, error) {
	f.calls = append(f.calls, fmt.Sprintf("release %s %d", key.GetVpc(), gen))
	delete(f.claims, key.GetVpc())
	return nil, nil
}

type fakeInputs struct {
	atts     []ProxyAttachment
	backends []BackendAttachment
}

func (f *fakeInputs) Attachments(context.Context) ([]ProxyAttachment, error) { return f.atts, nil }
func (f *fakeInputs) Backends(context.Context) ([]BackendAttachment, error)  { return f.backends, nil }

// fakePodLink records each VPC's last configuration.
type fakePodLink struct {
	local   map[string][]netip.Addr
	gateway map[string][]netip.Addr
	podEnd  map[string]string
	missing map[string]bool
}

func newFakePodLink() *fakePodLink {
	return &fakePodLink{local: map[string][]netip.Addr{}, gateway: map[string][]netip.Addr{},
		podEnd: map[string]string{}, missing: map[string]bool{}}
}

func (f *fakePodLink) Configure(vpc, podEnd string, gateway []netip.Addr, hostLL netip.Addr, local []netip.Addr) error {
	if f.missing[vpc] {
		return errVRFMissing
	}
	if hostLL != netip.MustParseAddr("fe80::1") {
		return fmt.Errorf("hostLL %s", hostLL)
	}
	f.local[vpc], f.gateway[vpc], f.podEnd[vpc] = local, gateway, podEnd
	return nil
}

var (
	gwAddr = netip.MustParseAddr("2001:db8:ff::1")
	// The two VPCs' backends share an address.
	sharedBackend = netip.MustParseAddr("2001:db8:1::10")
)

func claimFixture() (*fakeWorker, *fakeInputs, *fakePodLink, *Claims) {
	w := newFakeWorker()
	in := &fakeInputs{
		atts: []ProxyAttachment{
			{VPC: testVPCA, UID: testProxyA, Addresses: []netip.Addr{gwAddr}},
			{VPC: testVPCB, UID: "proxy-b", Addresses: []netip.Addr{gwAddr}},
		},
		backends: []BackendAttachment{
			{VPC: testVPCA, UID: testBackendALocal, Address: sharedBackend},
			{VPC: testVPCA, UID: "be-a-remote", Address: netip.MustParseAddr("2001:db8:1::20")},
			{VPC: testVPCB, UID: "be-b-local", Address: sharedBackend},
			// No proxy attachment in VPC C: no claim.
			{VPC: "vpcC", UID: "be-c", Address: sharedBackend},
		},
	}
	w.modes[testBackendALocal] = workerv1alpha1.Mode_MODE_LOCAL
	w.modes["be-a-remote"] = workerv1alpha1.Mode_MODE_FABRIC
	w.modes["be-b-local"] = workerv1alpha1.Mode_MODE_LOCAL
	l := newFakePodLink()
	return w, in, l, NewClaims(w, in, l, claimTestNode, NewClaimMetrics())
}

// TestClaimsPerVPCAndRouteChoice holds one socket claim per VPC that has
// both a proxy attachment and a backend, and routes only the backends Worker
// resolves to Local over the routed link, in each VPC's own VRF, even when
// two VPCs' backends share an address.
func TestClaimsPerVPCAndRouteChoice(t *testing.T) {
	w, _, l, c := claimFixture()
	ctx := context.Background()
	if err := c.Ready(); err == nil {
		t.Fatal("Ready before the first sync = nil")
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.claims) != 2 || w.claims["vpcC"] != nil {
		t.Fatalf("claims = %v, want VPC A and VPC B only", w.calls)
	}
	spec := w.specs[testVPCA]
	if spec.GetHandoff() != workerv1alpha1.Handoff_HANDOFF_SOCKET || len(spec.GetDestinations()) != 2 ||
		spec.GetDestinations()[0].GetAttachment().GetUid() != testBackendALocal {
		t.Fatalf("VPC A spec = %v, want a socket claim on both backends in UID order", spec)
	}
	if k := w.claims[testVPCA].GetKey(); k.GetAttachmentUid() != testProxyA || k.GetNode() != claimTestNode {
		t.Fatalf("VPC A key = %v, want the proxy's attachment on this node", k)
	}
	for _, vpc := range []string{testVPCA, testVPCB} {
		if got := l.local[vpc]; !slices.Equal(got, []netip.Addr{sharedBackend}) {
			t.Fatalf("%s local routes = %v, want only the Local backend", vpc, got)
		}
		if got := l.gateway[vpc]; !slices.Equal(got, []netip.Addr{gwAddr}) || l.podEnd[vpc] != "Gpod"+vpc {
			t.Fatalf("%s pod end %s with gateway %v", vpc, l.podEnd[vpc], got)
		}
	}
	if err := c.Ready(); err != nil {
		t.Fatalf("Ready = %v", err)
	}

	// A sync with nothing changed calls nothing.
	before := len(w.calls)
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != before {
		t.Fatalf("an unchanged sync called %v", w.calls[before:])
	}

	// The Local backend moves off-node: Worker resolves it to Fabric, and
	// its route over the link goes.
	w.modes[testBackendALocal] = workerv1alpha1.Mode_MODE_FABRIC
	c.Observe(w.status(w.claims[testVPCA].GetKey(), 1, w.specs[testVPCA]))
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := l.local[testVPCA]; len(got) != 0 {
		t.Fatalf("VPC A local routes after the move = %v, want none", got)
	}

	// A new backend updates the claim at the next generation.
	c.inputs.(*fakeInputs).backends = append(c.inputs.(*fakeInputs).backends,
		BackendAttachment{VPC: testVPCB, UID: "be-b-2", Address: netip.MustParseAddr("2001:db8:1::30")})
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.claims[testVPCB].GetGeneration(); got != 2 || len(w.specs[testVPCB].GetDestinations()) != 2 {
		t.Fatalf("VPC B generation %d with %v, want 2 with both backends", got, w.specs[testVPCB])
	}

	// VPC B loses its backends: its claim is released; VPC A's stays.
	in2 := c.inputs.(*fakeInputs)
	in2.backends = slices.DeleteFunc(in2.backends, func(b BackendAttachment) bool { return b.VPC == testVPCB })
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if w.claims[testVPCB] != nil || w.claims[testVPCA] == nil {
		t.Fatalf("calls %v: want VPC B released and VPC A kept", w.calls)
	}
}

// TestClaimsWaitForThePreviousPod keeps retrying, not ready, while Worker
// refuses the claim because the proxy's previous pod still holds it, and
// takes the claim over once that pod is gone.
func TestClaimsWaitForThePreviousPod(t *testing.T) {
	w, in, l, c := claimFixture()
	in.atts = in.atts[:1]
	ctx := context.Background()
	// The previous pod's claim, at generation 3.
	key := &workerv1alpha1.ClaimKey{Node: claimTestNode, Vpc: testVPCA, AttachmentUid: testProxyA}
	prev := w.status(key, 3, &workerv1alpha1.ClaimSpec{})
	w.claims[testVPCA], w.held = prev, true

	if err := c.Sync(ctx); err == nil {
		t.Fatal("Sync while the previous pod holds the claim = nil")
	}
	if err := c.Ready(); err == nil {
		t.Fatal("Ready while the previous pod holds the claim = nil")
	}
	// Observe reports the claim; the next attempt updates past it and is
	// still refused.
	c.Observe(prev)
	if err := c.Sync(ctx); err == nil {
		t.Fatal("Sync while the previous pod holds the claim = nil")
	}
	if l.podEnd[testVPCA] != "" {
		t.Fatal("the pod end was configured from the previous pod's claim")
	}

	// The previous pod is gone.
	w.held = false
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.claims[testVPCA].GetGeneration(); got != 4 {
		t.Fatalf("generation %d after the takeover, want 4; calls %v", got, w.calls)
	}
	if err := c.Ready(); err != nil {
		t.Fatalf("Ready after the takeover = %v", err)
	}
	if !proto.Equal(w.specs[testVPCA], c.claims[testVPCA].spec) {
		t.Fatal("the recorded spec differs from Worker's")
	}
}

// TestClaimsReleaseLeftoversAndAll releases a claim an earlier container
// made that is no longer wanted, and every claim at shutdown.
func TestClaimsReleaseLeftoversAndAll(t *testing.T) {
	w, _, _, c := claimFixture()
	ctx := context.Background()
	stale := &workerv1alpha1.ClaimKey{Node: claimTestNode, Vpc: "vpcGone", AttachmentUid: "proxy-x"}
	w.claims["vpcGone"] = w.status(stale, 2, &workerv1alpha1.ClaimSpec{})
	c.Observe(w.claims["vpcGone"])
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.calls, "release vpcGone 2") {
		t.Fatalf("calls %v, want the leftover released at its generation", w.calls)
	}
	if err := c.ReleaseAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.claims) != 0 {
		t.Fatalf("claims after ReleaseAll = %v", w.claims)
	}
}

// TestClaimsNotReadyWithoutTheVRF reports a claim whose VRF the Store has
// not created yet as not ready.
func TestClaimsNotReadyWithoutTheVRF(t *testing.T) {
	_, _, l, c := claimFixture()
	l.missing[testVPCA] = true
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(); err == nil {
		t.Fatal("Ready without VPC A's VRF = nil")
	}
	if st, reason := claimStateOf(c.claims[testVPCA]); st != ClaimNotWired || reason != ReasonVRFMissing {
		t.Fatalf("state %s/%s, want unconfigured/VRFMissing", st, reason)
	}
}

// TestClaimMetrics reports each claim's state and its destinations' modes,
// and counts calls by outcome.
func TestClaimMetrics(t *testing.T) {
	w, _, l, _ := claimFixture()
	m := NewClaimMetrics()
	reg := prometheus.NewRegistry()
	reg.MustRegister(m.collectors()...)
	l.missing[testVPCB] = true
	c := NewClaims(w, &fakeInputs{atts: []ProxyAttachment{
		{VPC: testVPCA, UID: testProxyA, Addresses: []netip.Addr{gwAddr}},
		{VPC: testVPCB, UID: "proxy-b", Addresses: []netip.Addr{gwAddr}},
	}, backends: []BackendAttachment{
		{VPC: testVPCA, UID: testBackendALocal, Address: sharedBackend},
		{VPC: testVPCA, UID: "be-a-remote", Address: netip.MustParseAddr("2001:db8:1::20")},
		{VPC: testVPCB, UID: "be-unknown", Address: sharedBackend},
	}}, l, claimTestNode, m)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		state, reason string
		want          float64
	}{{ClaimReady, "", 1}, {ClaimNotWired, ReasonVRFMissing, 1}} {
		if got := testutil.ToFloat64(m.claims.WithLabelValues(tc.state, tc.reason)); got != tc.want {
			t.Errorf("worker_claims{%s,%s} = %v, want %v", tc.state, tc.reason, got, tc.want)
		}
	}
	for mode, want := range map[string]float64{"local": 1, "fabric": 1, "unresolved": 1} {
		if got := testutil.ToFloat64(m.destinations.WithLabelValues(mode)); got != want {
			t.Errorf("worker_destinations{%s} = %v, want %v", mode, got, want)
		}
	}
	if got := testutil.ToFloat64(m.operations.WithLabelValues("request", "success")); got != 2 {
		t.Errorf("successful requests = %v, want 2", got)
	}
	m.SetCapabilities([]*workerv1alpha1.Capability{{Name: workerv1alpha1.CapabilityLocalSocket,
		State: workerv1alpha1.CapabilityState_CAPABILITY_STATE_UNAVAILABLE, Reason: "ModuleNotRunning"}})
	if got := testutil.ToFloat64(m.capabilities.WithLabelValues(workerv1alpha1.CapabilityLocalSocket,
		"unavailable", "ModuleNotRunning")); got != 1 {
		t.Errorf("worker_capability = %v, want 1", got)
	}
}
