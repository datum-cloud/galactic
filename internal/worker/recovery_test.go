// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
)

// TestRestartWithPersistedState restarts Worker over programmed state.
// The new incarnation fences and adopts the scope, commits a snapshot that
// writes nothing because the host already matches, and a client that
// repeats its last request gets a duplicate answer.
func TestRestartWithPersistedState(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1", "guest-a2")))
	e.waitReady(k, 2)
	rows := e.host.Rows(vpcA)
	oldOwner := e.w.Owner()

	e.crash()
	e.start()
	e.waitReady(k, 2)
	if got := e.local.Writes.Load() + e.fabric.Writes.Load(); got != 0 {
		t.Fatalf("restart rewrote %d rows of matching host state", got)
	}
	if !slices.Equal(rows, e.host.Rows(vpcA)) {
		t.Fatal("restart changed host state")
	}
	rec, err := e.fence.Read(module.Scope{VPC: vpcA}.Name())
	e.mustOK(err)
	if rec.Owner != e.w.Owner() || rec.Owner == oldOwner || rec.Pending {
		t.Fatalf("fence record = %+v, want adopted by the new incarnation", rec)
	}
	// The client restarts too and repeats its last request.
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1", "guest-a2")))
}

// TestCrashBeforeProgramming crashes after the claim is recorded and while
// reconciliation holds a ticket but has written nothing. The restart
// programs the claim from the persisted desired state.
func TestCrashBeforeProgramming(t *testing.T) {
	e := newEnv(t)
	e.start()
	entered := e.local.PausePlan()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	<-entered
	e.crash()
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows before restart = %v", rowIDs(rows))
	}
	e.start()
	e.waitReady(mkey(vpcA, "svc-a"), 1)
}

// TestCrashMidApply leaves a partly applied commit behind. The fence marks
// the scope resync-required, and the next incarnation's snapshot finishes
// the change instead of assuming it either done or undone.
func TestCrashMidApply(t *testing.T) {
	e := newEnv(t)
	e.cfg.RetryMin, e.cfg.RetryMax = time.Hour, time.Hour
	e.start()
	e.local.FailApply(1, 1)
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a3")))
	e.eventually("partial commit", func() bool {
		return condOf(e.status(k), workerv1alpha1.ConditionProgrammed).GetReason() == workerv1alpha1.ReasonProgrammingFailed
	})
	if rows := e.host.Rows(vpcA); len(rows) != 1 {
		t.Fatalf("rows after the failed commit = %v, want one of two", rowIDs(rows))
	}
	rec, err := e.fence.Read(module.Scope{VPC: vpcA}.Name())
	e.mustOK(err)
	if !rec.Pending {
		t.Fatal("a failed commit did not leave the scope resync-required")
	}

	e.crash()
	e.cfg.RetryMin, e.cfg.RetryMax = 5*time.Millisecond, 50*time.Millisecond
	e.start()
	e.waitReady(k, 1)
	if got := rowIDs(e.host.Rows(vpcA)); len(got) != 2 {
		t.Fatalf("rows after repair = %v", got)
	}
}

// TestCrashBeforeReleaseRecorded removes a released claim's programmed
// state, then crashes before the record is deleted. The restart confirms the
// removal from the host and finishes the release.
func TestCrashBeforeReleaseRecorded(t *testing.T) {
	e := newEnv(t)
	e.cfg.RetryMin, e.cfg.RetryMax = time.Hour, time.Hour
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	e.store.failDelete.Store(1)
	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
	e.eventually("rows removed", func() bool { return len(e.host.Rows(vpcA)) == 0 })
	e.idle()
	if recs, _ := e.store.List(); len(recs) != 1 || !recs[0].Releasing {
		t.Fatalf("records = %+v, want the releasing record kept", recs)
	}

	e.crash()
	e.cfg.RetryMin, e.cfg.RetryMax = 5*time.Millisecond, 50*time.Millisecond
	e.start()
	if st := e.status(k); st == nil || condOf(st, workerv1alpha1.ConditionWithdrawing).GetStatus() != condTrue {
		t.Fatalf("restored status = %v, want Withdrawing", st)
	}
	e.waitGone(k)
	if recs, _ := e.store.List(); len(recs) != 0 {
		t.Fatalf("records after restart = %+v", recs)
	}
}

// TestStoreFailureRefusesWithoutChange fails the durable write: the call
// returns UNAVAILABLE and Worker holds nothing it did not record.
func TestStoreFailureRefusesWithoutChange(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.store.failPut.Store(1)
	wantRefusal(t, e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")), codes.Unavailable,
		workerv1alpha1.ReasonResyncing)
	if st := e.status(mkey(vpcA, "svc-a")); st != nil {
		t.Fatalf("an unrecorded claim is held: %v", st)
	}
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(mkey(vpcA, "svc-a"), 1)
}

// TestResyncingRefusesChanges refuses claim changes for a scope until the
// restart's snapshot commits, but still answers duplicates.
func TestResyncingRefusesChanges(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	e.crash()

	e.pauseOnStart = true
	e.start()
	<-e.startPaused
	if !e.isResyncing(vpcA) {
		t.Fatal("scope is not resyncing before the restart's snapshot")
	}
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	wantRefusal(t, e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a3")), codes.Unavailable,
		workerv1alpha1.ReasonResyncing)
	wantRefusal(t, e.release(natSA, key(vpcA, "svc-a"), 1), codes.Unavailable, workerv1alpha1.ReasonResyncing)
	e.local.ResumePlan()
	e.waitReady(k, 1)
	e.mustOK(e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a3")))
	e.waitReady(k, 2)
}

func (e *env) isResyncing(vpc string) bool {
	e.w.mu.Lock()
	defer e.w.mu.Unlock()
	s := e.w.scopes[vpc]
	return s != nil && s.resyncing
}

// TestDuplicateWatchEvents floods the queue with change events. They
// coalesce, and a scope that already matches is neither committed nor
// written again.
func TestDuplicateWatchEvents(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a2")))
	e.waitReady(k, 1)
	e.idle()
	before := e.persisted()
	writes := e.local.Writes.Load() + e.fabric.Writes.Load()
	applies := e.local.ApplyCalls.Load() + e.fabric.ApplyCalls.Load()
	for range 200 {
		e.w.Changed(vpcA)
		e.w.Changed("")
	}
	e.idle()
	if e.local.Writes.Load()+e.fabric.Writes.Load() != writes ||
		e.local.ApplyCalls.Load()+e.fabric.ApplyCalls.Load() != applies {
		t.Fatal("duplicate events wrote host state")
	}
	// Plan and Read run, but no commit advances the fence revision.
	after := e.persisted()
	for name, b := range before {
		if strings.HasPrefix(name, "ownership/") && after[name] != b {
			t.Fatalf("duplicate events changed %s", name)
		}
	}
	e.waitReady(k, 1)
}

// TestLeaseExpiryWithdrawsCallerClaims lets a caller's sessions lapse: every
// claim of that caller is withdrawn with scope "every claim of the caller",
// and other callers' claims stay.
func TestLeaseExpiryWithdrawsCallerClaims(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.mustOK(e.request(natSA, key(vpcB, "svc-b"), 1, veth("guest-b1")))
	e.mustOK(e.request(otherSA, key(vpcA, "svc-a2"), 1, veth("guest-a1")))
	e.waitReady(mkey(vpcA, "svc-a"), 1)
	e.waitReady(mkey(vpcB, "svc-b"), 1)
	e.waitReady(mkey(vpcA, "svc-a2"), 1)

	e.clock.Advance(e.cfg.Lease / 2)
	e.ctx(otherSA) // otherSA's session is live.
	e.mustOK(e.update(otherSA, key(vpcA, "svc-a2"), 2, veth("guest-a1")))
	e.clock.Advance(e.cfg.Lease/2 + time.Second)
	e.w.ExpireLeases()

	for _, k := range []module.ClaimKey{mkey(vpcA, "svc-a"), mkey(vpcB, "svc-b")} {
		if st := e.status(k); st != nil && st.GetWithdrawalScope() != workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_CALLER {
			t.Fatalf("withdrawal scope = %v, want every claim of the caller", st.GetWithdrawalScope())
		}
		e.waitGone(k)
	}
	e.waitReady(mkey(vpcA, "svc-a2"), 2)
	if got := rowIDs(e.host.Rows(vpcA)); !slices.Equal(got, []string{"svc-a2→attachment/guest-a1"}) {
		t.Fatalf("rows = %v, want only the live caller's claim", got)
	}
	if len(e.host.Rows(vpcB)) != 0 {
		t.Fatal("expired caller's rows remain in VPC B")
	}
}

// TestAuthorizationRevoked withdraws a claim whose attachment loses its
// authority, reporting Admitted=False with AuthorizationRevoked.
func TestAuthorizationRevoked(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	stream, err := e.api.Observe(e.ctx(natSA), &workerv1alpha1.ObserveRequest{Key: key(vpcA, "svc-a")})
	e.mustOK(err)

	a, _, _ := e.src.Attachment(t.Context(), "svc-a")
	a.Admitted = false
	e.src.SetAttachment(a)
	e.w.Changed(vpcA)

	sawRevoked := false
	for {
		r, err := stream.Recv()
		e.mustOK(err)
		st := r.GetStatus()
		if c := condOf(st, workerv1alpha1.ConditionAdmitted); c.GetStatus() == condFalse &&
			c.GetReason() == workerv1alpha1.ReasonAuthorizationRevoked {
			sawRevoked = true
		}
		if st.GetReleased() {
			break
		}
	}
	if !sawRevoked {
		t.Fatal("never observed Admitted=False/AuthorizationRevoked")
	}
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after revocation = %v", rowIDs(rows))
	}
}

// TestWithdrawalDuringRepair is the contract's worked transition: a commit
// failed part-way, the repair holds a ticket while it prepares a snapshot,
// and the owner releases the claim. The release fences the scope, the
// repair's late commit is dropped, and the snapshot that lands holds no row
// of the released claim while other claims of the scope stay programmed.
func TestWithdrawalDuringRepair(t *testing.T) {
	e := newEnv(t)
	e.start()
	keep := mkey(vpcA, "svc-a2")
	e.mustOK(e.request(otherSA, key(vpcA, "svc-a2"), 1, veth("guest-a3")))
	e.waitReady(keep, 1)

	e.local.FailApply(1, 0)
	k := mkey(vpcA, "svc-a")
	entered := e.local.PausePlan()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	// The first pass pauses at Plan; let it fail at Apply.
	<-entered
	entered = e.local.RepausePlan()
	// The retry is the repair: it holds a ticket while it prepares.
	<-entered
	if !e.isRepairing(vpcA) {
		t.Fatal("scope is not in repair after the failed commit")
	}
	before, err := e.fence.Read(module.Scope{VPC: vpcA}.Name())
	e.mustOK(err)

	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
	if st := e.status(k); st.GetWithdrawalScope() != workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_CLAIM {
		t.Fatalf("withdrawal scope = %v, want one claim", st.GetWithdrawalScope())
	}
	fenced, err := e.fence.Read(module.Scope{VPC: vpcA}.Name())
	e.mustOK(err)
	if fenced.Transitioning || !fenced.Pending || fenced.Generation <= before.Generation ||
		fenced.Owner != e.w.Owner() {
		t.Fatalf("release during repair did not take the scope over again: %+v", fenced)
	}
	e.local.ResumePlan()

	e.waitGone(k)
	e.waitReady(keep, 1)
	if got := rowIDs(e.host.Rows(vpcA)); !slices.Equal(got, []string{"svc-a2→attachment/guest-a3"}) {
		t.Fatalf("rows = %v, want only the kept claim", got)
	}
	rec, err := e.fence.Read(module.Scope{VPC: vpcA}.Name())
	e.mustOK(err)
	if rec.Transitioning || rec.Pending || rec.Owner != e.w.Owner() {
		t.Fatalf("fence record after repair = %+v", rec)
	}
}

func (e *env) isRepairing(vpc string) bool {
	e.w.mu.Lock()
	defer e.w.mu.Unlock()
	s := e.w.scopes[vpc]
	return s != nil && s.repair
}

// TestScopeOwnedElsewhere leaves a scope another writer owns alone and
// reports why its claims are not programmed.
func TestScopeOwnedElsewhere(t *testing.T) {
	e := newEnv(t)
	if _, err := e.fence.Claim(module.Scope{VPC: vpcA}.Name(), "galactic-edge:node-a:1"); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	st := e.waitObserved(mkey(vpcA, "svc-a"))
	if c := condOf(st, workerv1alpha1.ConditionProgrammed); c.GetReason() != workerv1alpha1.ReasonScopeOwnedElsewhere {
		t.Fatalf("Programmed = %v, want ScopeOwnedElsewhere", c)
	}
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v, want none in a scope another writer owns", rowIDs(rows))
	}
}
