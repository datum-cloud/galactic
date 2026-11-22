// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package localhandoff

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	testNode = "node-a"
	uidA     = "uid-a"
	uidB     = "uid-b"
	vpcA     = "vpcA"
)

var (
	sidA1 = netip.MustParseAddr("2001:db8:1:1:e001:1::")
	sidA2 = netip.MustParseAddr("2001:db8:1:1:e001:2::")
	sidB1 = netip.MustParseAddr("2001:db8:1:1:e002:3::")
)

type fakeTable struct {
	mu   sync.Mutex
	rows map[netip.Addr]uint32
}

func newFakeTable() *fakeTable { return &fakeTable{rows: map[netip.Addr]uint32{}} }

func (t *fakeTable) Set(sid netip.Addr, tap uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rows[sid] = tap
	return nil
}

func (t *fakeTable) Delete(sid netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.rows, sid)
	return nil
}

func (t *fakeTable) List() (map[netip.Addr]uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[netip.Addr]uint32{}
	for k, v := range t.rows {
		out[k] = v
	}
	return out, nil
}

func (t *fakeTable) get(sid netip.Addr) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.rows[sid]
	return v, ok
}

type call struct {
	method string
	key    *workerv1alpha1.ClaimKey
	gen    uint64
	spec   *workerv1alpha1.ClaimSpec
}

// fakeWorker holds claims as Worker would, by attachment UID.
type fakeWorker struct {
	mu     sync.Mutex
	gens   map[string]uint64
	calls  []call
	refuse error
}

func newFakeWorker() *fakeWorker { return &fakeWorker{gens: map[string]uint64{}} }

func reasonErr(code codes.Code, reason string) error {
	st, _ := status.New(code, reason).WithDetails(&errdetails.ErrorInfo{Reason: reason,
		Domain: workerv1alpha1.ErrorDomain})
	return st.Err()
}

func (f *fakeWorker) Request(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"Request", key, gen, spec})
	if f.refuse != nil {
		return nil, f.refuse
	}
	if g, ok := f.gens[key.GetAttachmentUid()]; ok && g != gen {
		return nil, reasonErr(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists)
	}
	f.gens[key.GetAttachmentUid()] = gen
	return &workerv1alpha1.ClaimStatus{Key: key, Generation: gen}, nil
}

func (f *fakeWorker) Update(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"Update", key, gen, spec})
	if g := f.gens[key.GetAttachmentUid()]; gen < g {
		return nil, reasonErr(codes.Aborted, workerv1alpha1.ReasonStaleGeneration)
	}
	f.gens[key.GetAttachmentUid()] = gen
	return &workerv1alpha1.ClaimStatus{Key: key, Generation: gen}, nil
}

func (f *fakeWorker) Release(_ context.Context, key *workerv1alpha1.ClaimKey, gen uint64) (
	*workerv1alpha1.ClaimStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"Release", key, gen, nil})
	delete(f.gens, key.GetAttachmentUid())
	return &workerv1alpha1.ClaimStatus{Key: key, Released: true}, nil
}

func (f *fakeWorker) Observe(context.Context, *workerv1alpha1.ClaimKey) (StatusStream, error) {
	return nil, nil
}

func (f *fakeWorker) Close() error { return nil }

func (f *fakeWorker) callsOf(method string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

func newTestManager() (*Manager, *fakeWorker, *fakeTable, *int) {
	fw, ft := newFakeWorker(), newFakeTable()
	changes := 0
	m := New(testNode, func(context.Context) (ClaimAPI, error) { return fw, nil }, ft, func() { changes++ })
	m.sessionUp = true
	return m, fw, ft, &changes
}

// readyStatus is Worker's snapshot of uid-a's claim with every slot in ready
// state and the TAP at tap.
func readyStatus(m *Manager, tap int32, ready map[uint16]bool, reason string) *workerv1alpha1.ClaimStatus {
	cl := m.claims[uidA]
	st := &workerv1alpha1.ClaimStatus{Key: cl.key, Generation: cl.gen, ObservedGeneration: cl.gen, Revision: 1}
	if tap > 0 {
		st.HandoffInterfaces = []*workerv1alpha1.HandoffInterface{{Role: workerv1alpha1.HandoffRoleTap,
			Name: "tap0", Ifindex: tap}}
	}
	for slot, ok := range ready {
		ds := &workerv1alpha1.DestinationStatus{Destination: &workerv1alpha1.Destination{
			Target: &workerv1alpha1.Destination_Backend{Backend: &workerv1alpha1.BackendRef{Node: testNode,
				Slot: uint32(slot)}}}, Resolved: true, Programmed: ok, Ready: ok}
		if !ok {
			ds.Reason = reason
		}
		st.Destinations = append(st.Destinations, ds)
	}
	return st
}

// TestSetBackendsWritesNoTAPRowsAtOnce: a Local backend's flows are dropped,
// never encapsulated, until Worker reports its handoff ready.
func TestSetBackendsWritesNoTAPRowsAtOnce(t *testing.T) {
	m, _, ft, _ := newTestManager()
	m.SetBackends([]Backend{
		{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1},
		{AttachmentUID: uidA, VPC: vpcA, Slot: 2, USID: sidA2},
	})
	for _, sid := range []netip.Addr{sidA1, sidA2} {
		if tap, ok := ft.get(sid); !ok || tap != 0 {
			t.Fatalf("row %s = %d, %v; want a no-TAP row", sid, tap, ok)
		}
	}
	snap := m.Snapshot()
	if len(snap.Attachments) != 1 || snap.Attachments[0].Ready {
		t.Fatalf("attachments = %+v, want one not ready", snap.Attachments)
	}
}

// TestClaimOnePerAttachmentWithEverySlot: the claim is local.tap, mode
// local, keyed by the backend attachment, naming each slot.
func TestClaimOnePerAttachmentWithEverySlot(t *testing.T) {
	m, fw, _, _ := newTestManager()
	m.SetBackends([]Backend{
		{AttachmentUID: uidA, VPC: vpcA, Slot: 2, USID: sidA2},
		{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1},
		{AttachmentUID: uidB, VPC: vpcA, Slot: 3, USID: sidB1},
	})
	m.reconcile(context.Background(), fw)
	reqs := fw.callsOf("Request")
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	r := reqs[0]
	if r.key.GetAttachmentUid() != uidA || r.key.GetNode() != testNode || r.key.GetVpc() != vpcA {
		t.Errorf("key = %v", r.key)
	}
	if r.spec.GetHandoff() != workerv1alpha1.Handoff_HANDOFF_TAP || r.spec.GetMode() != workerv1alpha1.Mode_MODE_LOCAL {
		t.Errorf("spec = %v", r.spec)
	}
	d := r.spec.GetDestinations()
	if len(d) != 2 || d[0].GetBackend().GetSlot() != 1 || d[1].GetBackend().GetSlot() != 2 ||
		d[0].GetBackend().GetNode() != testNode {
		t.Errorf("destinations = %v", d)
	}
}

// TestReadyStatusProgramsTAPAndNotReadyClearsIt follows one slot's handoff
// through ready and back, and checks the other slot stays independent.
func TestReadyStatusProgramsTAPAndNotReadyClearsIt(t *testing.T) {
	m, fw, ft, changes := newTestManager()
	m.SetBackends([]Backend{
		{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1},
		{AttachmentUID: uidA, VPC: vpcA, Slot: 2, USID: sidA2},
	})
	m.reconcile(context.Background(), fw)
	before := *changes

	m.handleStatus(readyStatus(m, 7, map[uint16]bool{1: true, 2: false},
		workerv1alpha1.ReasonDispatcherSlotUnclaimed))
	if tap, _ := ft.get(sidA1); tap != 7 {
		t.Errorf("slot 1 row = %d, want 7", tap)
	}
	if tap, _ := ft.get(sidA2); tap != 0 {
		t.Errorf("slot 2 row = %d, want 0", tap)
	}
	if s := m.Snapshot().Attachments[0]; s.Ready || s.Reason != workerv1alpha1.ReasonDispatcherSlotUnclaimed {
		t.Errorf("attachment = %+v, want not ready, DispatcherSlotUnclaimed", s)
	}

	st := readyStatus(m, 7, map[uint16]bool{1: true, 2: true}, "")
	st.Revision = 2
	m.handleStatus(st)
	if tap, _ := ft.get(sidA2); tap != 7 {
		t.Errorf("slot 2 row = %d, want 7", tap)
	}
	if s := m.Snapshot().Attachments[0]; !s.Ready || s.Reason != bgpv1alpha1.LocalBackendReasonReady {
		t.Errorf("attachment = %+v, want ready", s)
	}
	if *changes == before {
		t.Error("onChange was not called on a readiness change")
	}

	// The hook goes: Worker reports the handoff not ready.
	st = readyStatus(m, 7, map[uint16]bool{1: false, 2: false}, workerv1alpha1.ReasonHandoffHookMissing)
	st.Revision = 3
	m.handleStatus(st)
	for _, sid := range []netip.Addr{sidA1, sidA2} {
		if tap, _ := ft.get(sid); tap != 0 {
			t.Errorf("row %s = %d after the hook went, want 0", sid, tap)
		}
	}
}

// TestReadyWithoutTAPIsNotReady: a status with no tap interface cannot be
// delivered to.
func TestReadyWithoutTAPIsNotReady(t *testing.T) {
	m, fw, ft, _ := newTestManager()
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.reconcile(context.Background(), fw)
	m.handleStatus(readyStatus(m, 0, map[uint16]bool{1: true}, ""))
	if tap, _ := ft.get(sidA1); tap != 0 {
		t.Errorf("row = %d, want 0", tap)
	}
}

// TestStaleStatusGenerationIsNotReady: a status describing an older spec
// says nothing about a slot just added.
func TestStaleStatusGenerationIsNotReady(t *testing.T) {
	m, fw, ft, _ := newTestManager()
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.reconcile(context.Background(), fw)
	st := readyStatus(m, 7, map[uint16]bool{1: true}, "")
	st.ObservedGeneration--
	m.handleStatus(st)
	if tap, _ := ft.get(sidA1); tap != 0 {
		t.Errorf("row = %d, want 0", tap)
	}
}

// TestSlotChangeUpdatesWithNewerGeneration and removal releases the claim
// and deletes its rows.
func TestSlotChangeUpdatesAndRemovalReleases(t *testing.T) {
	m, fw, ft, _ := newTestManager()
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.reconcile(context.Background(), fw)
	gen := m.claims[uidA].gen

	m.SetBackends([]Backend{
		{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1},
		{AttachmentUID: uidA, VPC: vpcA, Slot: 2, USID: sidA2},
	})
	m.reconcile(context.Background(), fw)
	ups := fw.callsOf("Update")
	if len(ups) != 1 || ups[0].gen <= gen || len(ups[0].spec.GetDestinations()) != 2 {
		t.Fatalf("updates = %+v, want one at a newer generation with two slots", ups)
	}

	m.SetBackends(nil)
	if _, ok := ft.get(sidA1); ok {
		t.Error("row of a removed backend survives")
	}
	m.reconcile(context.Background(), fw)
	if rel := fw.callsOf("Release"); len(rel) != 1 || rel[0].gen != ups[0].gen {
		t.Fatalf("releases = %+v, want one at the current generation", rel)
	}
	if len(m.claims) != 0 {
		t.Errorf("claims = %v, want none", m.claims)
	}
}

// TestRestartAdoptsAndReleasesEarlierClaims: a claim an earlier process made
// for a wanted attachment is updated to a newer generation, and one for an
// attachment no longer served is released at Worker's generation.
func TestRestartAdoptsAndReleasesEarlierClaims(t *testing.T) {
	m, fw, _, _ := newTestManager()
	fw.gens[uidA] = 5
	fw.gens[uidB] = 9
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.handleStatus(&workerv1alpha1.ClaimStatus{Key: &workerv1alpha1.ClaimKey{Node: testNode, Vpc: vpcA,
		AttachmentUid: uidB}, Generation: 9, ObservedGeneration: 9})
	m.handleStatus(&workerv1alpha1.ClaimStatus{Key: &workerv1alpha1.ClaimKey{Node: testNode, Vpc: vpcA,
		AttachmentUid: uidA}, Generation: 5, ObservedGeneration: 5})
	m.reconcile(context.Background(), fw)
	if rel := fw.callsOf("Release"); len(rel) != 1 || rel[0].key.GetAttachmentUid() != uidB || rel[0].gen != 9 {
		t.Errorf("releases = %+v, want uid-b at 9", rel)
	}
	if ups := fw.callsOf("Update"); len(ups) != 1 || ups[0].key.GetAttachmentUid() != uidA || ups[0].gen <= 5 {
		t.Errorf("updates = %+v, want uid-a past 5", ups)
	}
}

// TestNoWorkerReportsWorkerUnavailable: without any Worker session the
// backends are reported not ready, so health takes them out of selection.
func TestNoWorkerReportsWorkerUnavailable(t *testing.T) {
	m, _, _, _ := newTestManager()
	m.sessionUp = false
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	if s := m.Snapshot().Attachments[0]; s.Ready || s.Reason != bgpv1alpha1.LocalBackendReasonWorkerUnavailable {
		t.Errorf("attachment = %+v, want WorkerUnavailable", s)
	}
}

// TestRefusalIsReported: a refused claim reports Worker's reason.
func TestRefusalIsReported(t *testing.T) {
	m, fw, _, _ := newTestManager()
	m.everStatus = true
	fw.refuse = reasonErr(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.reconcile(context.Background(), fw)
	if s := m.Snapshot().Attachments[0]; s.Ready || s.Reason != workerv1alpha1.ReasonCapabilityNotAllowed {
		t.Errorf("attachment = %+v, want CapabilityNotAllowed", s)
	}
}

// TestUnusableBackendsAreIgnored: a backend without a slot, VPC or uSID
// gets no row and no claim.
func TestUnusableBackendsAreIgnored(t *testing.T) {
	m, fw, ft, _ := newTestManager()
	m.SetBackends([]Backend{
		{AttachmentUID: uidA, VPC: vpcA, Slot: 0, USID: sidA1},
		{AttachmentUID: uidA, VPC: "", Slot: 1, USID: sidA2},
		{AttachmentUID: uidB, VPC: vpcA, Slot: 1},
	})
	m.reconcile(context.Background(), fw)
	if rows, _ := ft.List(); len(rows) != 0 {
		t.Errorf("rows = %v, want none", rows)
	}
	if len(fw.callsOf("Request")) != 0 {
		t.Error("an unusable backend was claimed")
	}
}

// TestUplinkMissingDropsAndReportsLocalBackends: while public_uplink_table
// has no next hop, a ready backend's row drops and it is reported
// PublicUplinkMissing; once the row is back it is served again.
func TestUplinkMissingDropsAndReportsLocalBackends(t *testing.T) {
	m, fw, ft, _ := newTestManager()
	m.SetBackends([]Backend{{AttachmentUID: uidA, VPC: vpcA, Slot: 1, USID: sidA1}})
	m.reconcile(context.Background(), fw)
	m.handleStatus(readyStatus(m, 7, map[uint16]bool{1: true}, ""))

	m.SetUplinkMissing(true)
	if tap, _ := ft.get(sidA1); tap != 0 {
		t.Errorf("row = %d, want 0 while the uplink is missing", tap)
	}
	if s := m.Snapshot().Attachments[0]; s.Ready || s.Reason != ReasonPublicUplinkMissing {
		t.Errorf("attachment = %+v, want PublicUplinkMissing", s)
	}
	m.SetUplinkMissing(false)
	if tap, _ := ft.get(sidA1); tap != 7 {
		t.Errorf("row = %d, want 7 once the uplink is back", tap)
	}
}
