// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/internal/worker/sources"
)

// TestLifecycleResolvesLocalAndFabric requests a claim with a destination
// on this node and one on another, checks each reaches its module, then
// releases it and checks every row and the record are gone.
func TestLifecycleResolvesLocalAndFabric(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a2")))
	st := e.waitReady(k, 1)
	modes := map[string]workerv1alpha1.Mode{}
	for _, d := range st.GetDestinations() {
		modes[module.DestinationID(d.GetDestination())] = d.GetMode()
	}
	if modes["attachment/guest-a1"] != workerv1alpha1.Mode_MODE_LOCAL ||
		modes["attachment/guest-a2"] != workerv1alpha1.Mode_MODE_FABRIC {
		t.Fatalf("modes = %v, want guest-a1 Local and guest-a2 Fabric", modes)
	}
	if got := rowIDs(e.host.Rows(vpcA)); !slices.Equal(got,
		[]string{"svc-a→attachment/guest-a1", "svc-a→attachment/guest-a2"}) {
		t.Fatalf("rows = %v", got)
	}

	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
	e.waitGone(k)
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after release = %v", rowIDs(rows))
	}
	if recs, _ := e.store.List(); len(recs) != 0 {
		t.Fatalf("records after release = %v", recs)
	}
	// A retried release of a claim that no longer exists succeeds.
	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
}

// TestDuplicateRequestChangesNothing repeats a request whose response was
// lost: the same generation and spec returns the current status and writes
// nothing to the store, the fence or the host.
func TestDuplicateRequestChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 4, veth("guest-a1")))
	e.waitReady(k, 4)
	e.idle()
	before, rows := e.persisted(), e.host.Rows(vpcA)
	writes, plans := e.local.Writes.Load(), e.local.PlanCalls.Load()

	resp, err := e.api.Request(e.ctx(natSA), &workerv1alpha1.RequestRequest{Key: key(vpcA, "svc-a"),
		Generation: 4, Spec: veth("guest-a1")})
	e.mustOK(err)
	if !isTrue(resp.GetStatus(), workerv1alpha1.ConditionReady) || resp.GetStatus().GetObservedGeneration() != 4 {
		t.Fatalf("duplicate returned %v, want the current Ready status", resp.GetStatus())
	}
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a"), 4, veth("guest-a3")),
		codes.FailedPrecondition, workerv1alpha1.ReasonGenerationConflict)
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a"), 5, veth("guest-a1")),
		codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists)
	e.idle()

	if after := e.persisted(); !maps.Equal(before, after) {
		t.Fatalf("store or fence changed:\nbefore %v\nafter  %v", before, after)
	}
	if !slices.Equal(rows, e.host.Rows(vpcA)) || e.local.Writes.Load() != writes || e.local.PlanCalls.Load() != plans {
		t.Fatal("host state changed or a reconcile ran for a duplicate")
	}
}

// TestOutOfOrderRequests delivers delayed calls after newer ones: each is
// refused with the current generation and changes nothing.
func TestOutOfOrderRequests(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.mustOK(e.update(natSA, key(vpcA, "svc-a"), 3, veth("guest-a1", "guest-a3")))
	e.waitReady(k, 3)
	e.idle()
	before := e.persisted()

	err := e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1"))
	wantRefusal(t, err, codes.Aborted, workerv1alpha1.ReasonStaleGeneration)
	if md := errorMD(err); md[workerv1alpha1.MetadataCurrentGeneration] != "3" {
		t.Fatalf("stale update metadata = %v, want current generation 3", md)
	}
	wantRefusal(t, e.release(natSA, key(vpcA, "svc-a"), 2), codes.Aborted, workerv1alpha1.ReasonStaleGeneration)
	wantRefusal(t, e.release(natSA, key(vpcA, "svc-a"), 4), codes.FailedPrecondition,
		workerv1alpha1.ReasonGenerationConflict)
	wantRefusal(t, e.update(natSA, key(vpcA, "svc-a"), 3, veth("guest-a1")), codes.FailedPrecondition,
		workerv1alpha1.ReasonGenerationConflict)
	e.mustOK(e.update(natSA, key(vpcA, "svc-a"), 3, veth("guest-a1", "guest-a3")))
	e.idle()
	if !maps.Equal(before, e.persisted()) {
		t.Fatal("an out-of-order call changed durable state")
	}
	if got := rowIDs(e.host.Rows(vpcA)); len(got) != 2 {
		t.Fatalf("rows = %v, want generation 3's two destinations", got)
	}
}

func errorMD(err error) map[string]string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(interface{ GetMetadata() map[string]string }); ok {
			return info.GetMetadata()
		}
	}
	return nil
}

// TestConcurrentClients runs several callers at once, each with its own
// claims, and two callers racing for one attachment. Exactly one of the
// racers wins and every claim converges.
func TestConcurrentClients(t *testing.T) {
	e := newEnv(t)
	for i := range 8 {
		e.src.SetAttachment(srcAttachment(fmt.Sprintf("svc-%d", i), vpcA))
	}
	e.start()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 8 {
		caller := natSA
		if i%2 == 1 {
			caller = otherSA
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := key(vpcA, fmt.Sprintf("svc-%d", i))
			for gen := uint64(1); gen <= 3; gen++ {
				var err error
				if gen == 1 {
					err = e.request(caller, k, gen, veth("guest-a1"))
				} else {
					err = e.update(caller, k, gen, veth("guest-a1", "guest-a2"))
				}
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	results := make(chan error, 2)
	for _, caller := range []string{natSA, otherSA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- e.request(caller, key(vpcA, "svc-a"), 1, veth("guest-a3"))
		}()
	}
	wg.Wait()
	close(errs)
	close(results)
	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
	var won, lost int
	for err := range results {
		switch {
		case err == nil:
			won++
		case refusal.Is(err, codes.PermissionDenied, workerv1alpha1.ReasonAttachmentClaimedByAnotherCaller):
			lost++
		default:
			t.Errorf("racing request: %v", err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("racing requests: %d won, %d refused; want exactly one of each", won, lost)
	}
	for i := range 8 {
		e.waitReady(mkey(vpcA, fmt.Sprintf("svc-%d", i)), 3)
	}
	e.waitReady(mkey(vpcA, "svc-a"), 1)
	if got := len(e.host.Rows(vpcA)); got != 8*2+1 {
		t.Fatalf("rows = %d, want %d", got, 8*2+1)
	}
}

// TestCrossVPCRefusedWithoutMutation is the unprivileged twin of the
// zero-mutation root test: a destination in another VPC is refused before
// anything is recorded, fenced or planned.
func TestCrossVPCRefusedWithoutMutation(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	e.idle()
	before, rows, st := e.persisted(), e.host.Rows(vpcA), e.status(k)
	plans, applies := e.local.PlanCalls.Load(), e.local.ApplyCalls.Load()

	// guest-b1 has the same guest addresses as guest-a1 in another VPC.
	wantRefusal(t, e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1", "guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a2"), 1, veth("guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// A claim key naming VPC B on an attachment in VPC A is refused too.
	wantRefusal(t, e.request(natSA, key(vpcB, "svc-a2"), 1, veth("guest-b1")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	e.idle()

	if !maps.Equal(before, e.persisted()) {
		t.Fatal("a refused cross-VPC claim changed the store or the fence")
	}
	if !slices.Equal(rows, e.host.Rows(vpcA)) || len(e.host.Rows(vpcB)) != 0 {
		t.Fatal("a refused cross-VPC claim changed host state")
	}
	if e.local.PlanCalls.Load() != plans || e.local.ApplyCalls.Load() != applies {
		t.Fatal("a refused cross-VPC claim reached a module")
	}
	if !proto.Equal(st, e.status(k)) {
		t.Fatal("the existing generation's status changed")
	}
}

// TestNonOwnerRefused checks that only the owner may release or update a
// claim, and that a second caller cannot claim the same attachment.
func TestNonOwnerRefused(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	e.idle()
	before, rows := e.persisted(), e.host.Rows(vpcA)

	wantRefusal(t, e.release(otherSA, key(vpcA, "svc-a"), 1), codes.PermissionDenied, workerv1alpha1.ReasonNotOwner)
	wantRefusal(t, e.update(otherSA, key(vpcA, "svc-a"), 2, veth("guest-a1")), codes.PermissionDenied,
		workerv1alpha1.ReasonNotOwner)
	wantRefusal(t, e.request(otherSA, key(vpcA, "svc-a"), 1, veth("guest-a1")), codes.PermissionDenied,
		workerv1alpha1.ReasonAttachmentClaimedByAnotherCaller)
	e.idle()
	if !maps.Equal(before, e.persisted()) || !slices.Equal(rows, e.host.Rows(vpcA)) {
		t.Fatal("a non-owner call changed state")
	}
	if st := e.status(k); !isTrue(st, workerv1alpha1.ConditionReady) {
		t.Fatalf("claim status after non-owner calls = %v", st)
	}
}

// TestObserveDeliversCompleteSnapshots follows one claim over a stream and
// checks snapshots arrive in revision order and end with the release.
func TestObserveDeliversCompleteSnapshots(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	stream, err := e.api.Observe(e.ctx(natSA), &workerv1alpha1.ObserveRequest{Key: key(vpcA, "svc-a")})
	e.mustOK(err)
	var last uint64
	sawReady := false
	for {
		r, err := stream.Recv()
		e.mustOK(err)
		st := r.GetStatus()
		if st.GetRevision() <= last {
			t.Fatalf("revision %d after %d", st.GetRevision(), last)
		}
		last = st.GetRevision()
		if len(st.GetConditions()) != 5 {
			t.Fatalf("snapshot is not complete: %v", st)
		}
		if isTrue(st, workerv1alpha1.ConditionReady) && !sawReady {
			sawReady = true
			e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
		}
		if st.GetReleased() {
			break
		}
	}
	if !sawReady {
		t.Fatal("never observed Ready")
	}
	// Another caller's stream of all its claims receives nothing of this
	// claim, and a stream naming it is refused.
	ctx, cancel := context.WithTimeout(e.ctx(otherSA), 300*time.Millisecond)
	defer cancel()
	all, err := e.api.Observe(ctx, &workerv1alpha1.ObserveRequest{})
	e.mustOK(err)
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1")))
	// When the deadline passes, the server ends the stream cleanly. That end
	// can reach the client before its own deadline error does, and before
	// ctx's timer runs, so a clean end at the deadline is correct as long as
	// nothing was sent. The margin covers the deadline's encoding on the
	// wire; an early end still fails.
	r, err := all.Recv()
	dl, _ := ctx.Deadline()
	deadlineEnd := status.Code(err) == codes.DeadlineExceeded ||
		(errors.Is(err, io.EOF) && time.Until(dl) < 50*time.Millisecond)
	if r != nil || !deadlineEnd {
		t.Fatalf("another caller's stream got %v, %v; want nothing until the deadline", r, err)
	}
	named, err := e.api.Observe(e.ctx(otherSA), &workerv1alpha1.ObserveRequest{Key: key(vpcA, "svc-a")})
	e.mustOK(err)
	if _, err := named.Recv(); !refusal.Is(err, codes.PermissionDenied, workerv1alpha1.ReasonNotOwner) {
		t.Fatalf("observing another caller's claim: %v, want NotOwner", err)
	}
}

// TestObservePublishBeforeFirstSnapshot publishes a status after Observe
// registers its subscriber and before it queues the first snapshot. The
// stream still delivers the claim instead of blocking on its own wake-up.
func TestObservePublishBeforeFirstSnapshot(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	e.w.subscribed = func() {
		e.w.mu.Lock()
		defer e.w.mu.Unlock()
		e.w.publish(e.w.claims[k])
	}
	ctx, cancel := context.WithTimeout(e.ctx(natSA), 5*time.Second)
	defer cancel()
	stream, err := e.api.Observe(ctx, &workerv1alpha1.ObserveRequest{Key: key(vpcA, "svc-a")})
	e.mustOK(err)
	r, err := stream.Recv()
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if !isTrue(r.GetStatus(), workerv1alpha1.ConditionReady) {
		t.Fatalf("first snapshot = %v, want the Ready claim", r.GetStatus())
	}
}

// TestSessionsAndValidation covers the refusals that need no claim state.
func TestSessionsAndValidation(t *testing.T) {
	e := newEnv(t)
	e.start()
	noSession := metadata.AppendToOutgoingContext(t.Context(), callerMD, natSA)
	_, err := e.api.Request(noSession, &workerv1alpha1.RequestRequest{Key: key(vpcA, "svc-a"), Generation: 1,
		Spec: veth("guest-a1")})
	wantRefusal(t, err, codes.FailedPrecondition, workerv1alpha1.ReasonNoSession)

	_, err = e.api.GetCapabilities(noSession, &workerv1alpha1.GetCapabilitiesRequest{Versions: []string{"v9"}})
	wantRefusal(t, err, codes.FailedPrecondition, workerv1alpha1.ReasonUnsupportedVersion)

	_, err = e.api.GetCapabilities(t.Context(), versions())
	wantRefusal(t, err, codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity)

	wrong := &workerv1alpha1.ClaimKey{Node: otherNode, Vpc: vpcA, AttachmentUid: "svc-a"}
	wantRefusal(t, e.request(natSA, wrong, 1, veth("guest-a1")), codes.InvalidArgument, workerv1alpha1.ReasonWrongNode)
	for name, s := range map[string]*workerv1alpha1.ClaimSpec{
		"no handoff":      spec(workerv1alpha1.Handoff_HANDOFF_UNSPECIFIED, "guest-a1"),
		"no destinations": veth(),
		"duplicate":       veth("guest-a1", "guest-a1"),
		"empty target": {Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
			Destinations: []*workerv1alpha1.Destination{{}}},
	} {
		err := e.request(natSA, key(vpcA, "svc-a"), 1, s)
		if !refusal.Is(err, codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec) {
			t.Errorf("%s: got %v, want MalformedSpec", name, err)
		}
	}
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a"), 0, veth("guest-a1")), codes.InvalidArgument,
		workerv1alpha1.ReasonMalformedSpec)
	wantRefusal(t, e.update(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")), codes.FailedPrecondition,
		workerv1alpha1.ReasonClaimNotFound)
	// The gateway may use tap only; a veth pair claim is refused.
	wantRefusal(t, e.request(gwSA, key(vpcA, "svc-a"), 1, veth("guest-a1")), codes.PermissionDenied,
		workerv1alpha1.ReasonCapabilityNotAllowed)
	// A tap claim with a remote destination needs fabric.srv6, which the
	// gateway lacks.
	wantRefusal(t, e.request(gwSA, key(vpcA, "svc-a"), 1, spec(workerv1alpha1.Handoff_HANDOFF_TAP, "guest-a2")),
		codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
	if recs, _ := e.store.List(); len(recs) != 0 {
		t.Fatalf("refused calls recorded %v", recs)
	}

	// A GetCapabilities that carries a live session renews it.
	ctx := e.ctx(natSA)
	resp, err := e.api.GetCapabilities(ctx, versions())
	e.mustOK(err)
	e.mu.Lock()
	same := resp.GetSessionId() == e.sessions[natSA]
	e.mu.Unlock()
	if !same {
		t.Fatal("GetCapabilities with a live session started a new one")
	}
}

// TestDestinationResolution covers destinations that do not resolve: a
// backend no ServiceVIPBinding binds, and a mode preference the
// destination cannot meet. None falls back to the other mode.
func TestDestinationResolution(t *testing.T) {
	e := newEnv(t)
	e.start()
	s := veth("guest-a1")
	s.Destinations = append(s.Destinations,
		&workerv1alpha1.Destination{Target: &workerv1alpha1.Destination_Backend{
			Backend: &workerv1alpha1.BackendRef{Node: otherNode, Slot: 2}}})
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, s))
	st := e.waitObserved(mkey(vpcA, "svc-a"))
	if c := condOf(st, workerv1alpha1.ConditionResolved); c.GetStatus() != condFalse ||
		c.GetReason() != workerv1alpha1.ReasonBackendNotBound {
		t.Fatalf("Resolved = %v, want False/BackendNotBound", c)
	}
	if !isTrue(st, workerv1alpha1.ConditionProgrammed) || isTrue(st, workerv1alpha1.ConditionReady) {
		t.Fatalf("status = %v, want the resolved destination programmed and the claim not Ready", st)
	}

	local := veth("guest-a2")
	local.Mode = workerv1alpha1.Mode_MODE_LOCAL
	e.mustOK(e.request(natSA, key(vpcA, "svc-a2"), 1, local))
	st = e.waitObserved(mkey(vpcA, "svc-a2"))
	if c := condOf(st, workerv1alpha1.ConditionResolved); c.GetReason() != workerv1alpha1.ReasonModeUnavailable {
		t.Fatalf("Resolved = %v, want ModeUnavailable", c)
	}
	for _, r := range e.host.Rows(vpcA) {
		if r.Key.AttachmentUID == "svc-a2" {
			t.Fatalf("a destination that cannot meet its mode was programmed: %v", r)
		}
	}
}

// TestUnavailableModuleReportsReason accepts claims that need a module
// that is not running or a capability the platform excludes, and reports
// Programmed=False with the capability's reason.
func TestUnavailableModuleReportsReason(t *testing.T) {
	e := newEnv(t)
	var local *fake.Module
	e.modules = func(h *fake.Host) []module.Module {
		local = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
		local.SetCapability(module.Capability{Name: workerv1alpha1.CapabilityLocalTap,
			Reason: workerv1alpha1.ReasonHookUnsupported, Message: "XDP mode excluded"})
		return []module.Module{local}
	}
	e.start()
	resp, err := e.api.GetCapabilities(metadata.AppendToOutgoingContext(t.Context(), callerMD, natSA),
		versions())
	e.mustOK(err)
	got := map[string]string{}
	for _, c := range resp.GetCapabilities() {
		got[c.GetName()] = c.GetState().String() + "/" + c.GetReason()
	}
	if got[workerv1alpha1.CapabilityFabricSRv6] != "CAPABILITY_STATE_UNAVAILABLE/ModuleNotRunning" ||
		got[workerv1alpha1.CapabilityLocalTap] != "CAPABILITY_STATE_UNAVAILABLE/HookUnsupported" ||
		got[workerv1alpha1.CapabilityLocalVethPair] != "CAPABILITY_STATE_AVAILABLE/" {
		t.Fatalf("capabilities = %v", got)
	}

	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a2")))
	st := e.waitObserved(mkey(vpcA, "svc-a"))
	if c := condOf(st, workerv1alpha1.ConditionProgrammed); c.GetStatus() != condFalse ||
		c.GetReason() != workerv1alpha1.ReasonModuleNotRunning {
		t.Fatalf("Programmed = %v, want False/ModuleNotRunning", c)
	}
	if got := rowIDs(e.host.Rows(vpcA)); !slices.Equal(got, []string{"svc-a→attachment/guest-a1"}) {
		t.Fatalf("rows = %v, want only the Local destination", got)
	}

	e.mustOK(e.request(gwSA, key(vpcA, "svc-a2"), 1, spec(workerv1alpha1.Handoff_HANDOFF_TAP, "guest-a1")))
	st = e.waitObserved(mkey(vpcA, "svc-a2"))
	if c := condOf(st, workerv1alpha1.ConditionProgrammed); c.GetReason() != workerv1alpha1.ReasonHookUnsupported {
		t.Fatalf("Programmed = %v, want HookUnsupported", c)
	}
}

// TestObservedReadinessSeparateFromProgrammed keeps a programmed
// destination not Ready while the module observes its handoff missing.
func TestObservedReadinessSeparateFromProgrammed(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.local.SetReady(func(module.ClaimKey, string) (bool, string) {
		return false, workerv1alpha1.ReasonHandoffInterfaceMissing
	})
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	st := e.waitObserved(k)
	if !isTrue(st, workerv1alpha1.ConditionProgrammed) {
		t.Fatalf("Programmed = %v, want True", condOf(st, workerv1alpha1.ConditionProgrammed))
	}
	if c := condOf(st, workerv1alpha1.ConditionReady); c.GetStatus() != condFalse ||
		c.GetReason() != workerv1alpha1.ReasonHandoffInterfaceMissing {
		t.Fatalf("Ready = %v, want False/HandoffInterfaceMissing", c)
	}
	e.local.SetReady(nil)
	e.w.Changed(vpcA)
	e.waitReady(k, 1)
}

// TestClaimLimit refuses a caller's claim beyond the limit.
func TestClaimLimit(t *testing.T) {
	e := newEnv(t)
	e.cfg.ClaimLimit = 1
	e.start()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a2"), 1, veth("guest-a1")), codes.ResourceExhausted,
		workerv1alpha1.ReasonClaimLimit)
	// Another caller has its own limit.
	e.mustOK(e.request(otherSA, key(vpcA, "svc-a2"), 1, veth("guest-a1")))
}

func versions() *workerv1alpha1.GetCapabilitiesRequest {
	return &workerv1alpha1.GetCapabilitiesRequest{Versions: []string{workerv1alpha1.Version}}
}

func srcAttachment(uid, vpc string) sources.Attachment {
	return sources.Attachment{UID: uid, VPC: vpc, Node: node, Kind: sources.KindVPCAttachment, Admitted: true}
}

// TestFabricCapabilityFailsClosed refuses a remote destination to a caller
// without fabric.srv6 while the destination's locator is still unknown, and
// leaves unprogrammed a destination that only becomes remote after
// admission.
func TestFabricCapabilityFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.src.SetLocator(otherNode, netip.Prefix{})
	e.start()
	tap := func(uids ...string) *workerv1alpha1.ClaimSpec {
		return spec(workerv1alpha1.Handoff_HANDOFF_TAP, uids...)
	}
	wantRefusal(t, e.request(gwSA, key(vpcA, "svc-a"), 1, tap("guest-a2")), codes.PermissionDenied,
		workerv1alpha1.ReasonCapabilityNotAllowed)

	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(gwSA, key(vpcA, "svc-a"), 1, tap("guest-a3")))
	e.waitReady(k, 1)
	moved := srcAttachment("guest-a3", vpcA)
	moved.Node = otherNode
	e.src.SetAttachment(moved)
	e.src.SetLocator(otherNode, locB)
	e.w.Changed(vpcA)
	e.eventually("remote destination refused at reconcile", func() bool {
		return condOf(e.status(k), workerv1alpha1.ConditionProgrammed).GetReason() ==
			workerv1alpha1.ReasonCapabilityNotAllowed
	})
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v, want the destination the owner may not reach unprogrammed", rowIDs(rows))
	}
}
