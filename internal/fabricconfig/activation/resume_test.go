// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCrashAtEveryBoundary kills an activation at each journaled boundary,
// restarts the agent over the same state directory and FRR, and redelivers
// the activation: it must finish exactly once, on the revision promoted,
// with a checkpoint that matches the journal.
func TestCrashAtEveryBoundary(t *testing.T) {
	for _, point := range []string{FaultAfterAccepted, FaultAfterReload, FaultAfterApplied, FaultAfterCommitted} {
		t.Run(point, func(t *testing.T) {
			r1, r2, _ := revisions(t)
			dir := t.TempDir()
			frr := &fakeFRR{}
			a := newActivator(t, dir, frr, nil)
			committed(t, a, r1)

			req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1),
				RecoveryRevision: r1,
				Settings:         Settings{BootLifetime: time.Hour}}
			a.Fault = func(p string) error {
				if p == point {
					return errCrash
				}
				return nil
			}
			if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
				t.Fatalf("activation did not stop at %s: %v", point, err)
			}

			restarted := newActivator(t, dir, frr, nil)
			res, err := restarted.Activate(context.Background(), req)
			if err != nil || res.Outcome != OutcomeCommitted {
				t.Fatalf("resume = %+v, %v", res, err)
			}
			if frr.get() != rendered(t, r2) {
				t.Error("FRR does not run the promoted revision")
			}
			if rec, _ := restarted.Journal().LastForEpoch(testDeployment, 2); rec.Type != RecordCommitted {
				t.Errorf("epoch 2 ends %s", rec.Type)
			}
			if restarted.Journal().Failed(testDeployment, 2) {
				t.Error("a crash was journaled as a failure")
			}
			cp, err := ReadCheckpoint(dir)
			if err != nil || cp.Activation != req.Activation {
				t.Errorf("checkpoint = %s, %v; want %s", cp.Activation.Revision, err, r2.Name)
			}
			commits := 0
			for _, rec := range restarted.Journal().Records() {
				if rec.Type == RecordCommitted && rec.Activation.Epoch == 2 {
					commits++
				}
			}
			if commits != 1 {
				t.Errorf("epoch 2 committed %d times", commits)
			}
		})
	}
}

// TestCrashDuringRecovery: a crash after a failure was journaled, before the
// recovery target was restored, resumes into recovery, not a retry.
func TestCrashDuringRecovery(t *testing.T) {
	r1, r2, _ := revisions(t)
	dir := t.TempDir()
	frr := &fakeFRR{reloadErr: func(path string) error {
		if strings.HasSuffix(path, "active.conf") {
			return errors.New("bgpd refused the change")
		}
		return nil
	}}
	a := newActivator(t, dir, &fakeFRR{}, nil)
	committed(t, a, r1)
	a.FRR = frr
	frr.set(rendered(t, r1))
	a.Fault = func(p string) error {
		if p == FaultDuringRecovery {
			return errCrash
		}
		return nil
	}
	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
		t.Fatalf("activation did not stop during recovery: %v", err)
	}
	reloads := frr.reloads

	restarted := newActivator(t, dir, frr, nil)
	if !restarted.Journal().NeedsRecovery(testDeployment, 2) {
		t.Fatal("the unfinished recovery is not reported")
	}
	res, err := restarted.Activate(context.Background(), req)
	if err != nil || res.Outcome != OutcomeRecovered {
		t.Fatalf("redelivery of an unrecovered failed epoch = %+v, %v; want Recovered", res, err)
	}
	if frr.reloads != reloads+1 || frr.get() != rendered(t, r1) {
		t.Error("redelivery did not restore the recovery target, once")
	}
	if _, err := restarted.Activate(context.Background(), req); !errors.Is(err, ErrFailedEpoch) {
		t.Errorf("redelivery after recovery = %v, want ErrFailedEpoch", err)
	}
}

// TestCrashMidReload: a crash after the reload changed some of FRR leaves a
// configuration that is neither side; resume fails the epoch and recovers
// rather than guessing.
func TestCrashMidReload(t *testing.T) {
	r1, r2, _ := revisions(t)
	dir := t.TempDir()
	frr := &fakeFRR{}
	a := newActivator(t, dir, frr, nil)
	committed(t, a, r1)
	a.Fault = func(p string) error {
		if p == FaultAfterAccepted {
			return errCrash
		}
		return nil
	}
	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	frr.set(strings.Replace(rendered(t, r1), "advertisement-interval 30", "advertisement-interval 25", 1))

	restarted := newActivator(t, dir, frr, nil)
	res, err := restarted.Activate(context.Background(), req)
	if err != nil || res.Outcome != OutcomeRecovered {
		t.Fatalf("resume = %+v, %v", res, err)
	}
	if !restarted.Journal().Failed(testDeployment, 2) || frr.get() != rendered(t, r1) {
		t.Error("the epoch was not failed and recovered")
	}
}

func TestBoot(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	offline := Identity{MachineID: testMachine}
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, a *Activator, c *clock)
		id      Identity
		restore bool
		reason  string
	}{
		{name: "within its authorization", id: offline, restore: true, reason: "restoring committed"},
		{name: "with the API", id: testIdentity(), restore: true, reason: "restoring committed"},
		{name: "on another machine", id: Identity{MachineID: otherID}, reason: anotherNode},
		{name: "on a replacement Node", id: Identity{MachineID: testMachine, NodeUID: otherID}, reason: anotherNode},
		{name: "in another cluster", id: Identity{MachineID: testMachine, ClusterID: otherID}, reason: anotherNode},
		{name: "authorization expired", id: offline, reason: "expired",
			prepare: func(_ *testing.T, _ *Activator, c *clock) { c.set(start.Add(2 * time.Hour)) }},
		{name: "clock behind the journal", id: offline, reason: "clock is behind",
			prepare: func(_ *testing.T, _ *Activator, c *clock) { c.set(start.Add(-time.Minute)) }},
		{name: "no checkpoint", id: offline, reason: "no checkpoint",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				if err := removeCheckpoint(a.Dir); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "checkpoint needs the API", id: offline, reason: "credentials from the API",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				rewriteCheckpoint(t, a.Dir, func(cp *Checkpoint) { cp.RequiresAPI = true })
			}},
		{name: "checkpoint for another Node", id: offline, reason: "another Node",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				rewriteCheckpoint(t, a.Dir, func(cp *Checkpoint) { cp.Activation.NodeUID = otherID })
			}},
		{name: "checkpoint copied from another state directory", id: offline, reason: "another Node",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				rewriteCheckpoint(t, a.Dir, func(cp *Checkpoint) { cp.Nonce = "0123" })
			}},
		{name: "checkpoint from another FRR version", id: offline, reason: "another compiler or FRR version",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				rewriteCheckpoint(t, a.Dir, func(cp *Checkpoint) { cp.FRRVersion = "9.1" })
			}},
		{name: "prefix revoked after the checkpoint", id: offline, reason: originatesRevoked + " " + testPrefix,
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				acceptLater(t, a, Recovery{RevokedPrefixes: []string{testPrefix}})
			}},
		{name: "covering prefix revoked after the checkpoint", id: offline, reason: originatesRevoked,
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				acceptLater(t, a, Recovery{RevokedPrefixes: []string{"192.0.0.0/16"}})
			}},
		{name: "retired after the checkpoint", id: offline, reason: "the router is retired",
			prepare: func(t *testing.T, a *Activator, _ *clock) { acceptLater(t, a, Recovery{Retired: true}) }},
		{name: "corrupt journal", id: offline, reason: "journal is unreadable",
			prepare: func(t *testing.T, a *Activator, _ *clock) {
				acceptLater(t, a, Recovery{})
				acceptLater(t, a, Recovery{})
				corruptFirstLine(t, a.Dir)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r1, _, _ := revisions(t)
			c := &clock{t: start}
			dir := t.TempDir()
			a := newActivator(t, dir, &fakeFRR{}, c.Now)
			committed(t, a, r1)
			if tc.prepare != nil {
				tc.prepare(t, a, c)
			}
			booted := &Activator{Dir: dir, FRR: &fakeFRR{}, Now: c.Now}
			if err := booted.Open(); err != nil && !errors.Is(err, ErrRecoveryConflict) {
				t.Fatal(err)
			}
			got := booted.Boot(tc.id)
			if (got.Apply != "") != tc.restore || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("Boot = restore %v, %q; want restore %v, %q", got.Apply != "", got.Reason, tc.restore, tc.reason)
			}
			if tc.restore && got.Apply != rendered(t, r1) {
				t.Error("boot restores something other than the checkpoint")
			}
		})
	}
}

func rewriteCheckpoint(t *testing.T, dir string, edit func(*Checkpoint)) {
	t.Helper()
	cp, err := ReadCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	edit(&cp)
	if err := WriteCheckpoint(dir, cp); err != nil {
		t.Fatal(err)
	}
}

func corruptFirstLine(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "journal.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("x"), data...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// acceptLater journals a later epoch's acceptance with rec, as an agent
// that crashed before applying it would have.
func acceptLater(t *testing.T, a *Activator, rec Recovery) {
	t.Helper()
	if _, err := a.Journal().Append(Record{
		Type:       RecordAccepted,
		Activation: Activation{DeploymentUID: testDeployment, Epoch: nextEpoch(a), Revision: "later"},
		Recovery:   &rec,
	}); err != nil {
		t.Fatal(err)
	}
}

func nextEpoch(a *Activator) int64 {
	high, _ := a.Journal().HighWater(testDeployment)
	return high + 1
}

// TestShutdownIsNotFailure: an agent stopped mid-lock, mid-reload or
// mid-observation journals nothing as failed; after restart the same epoch
// finishes.
func TestShutdownIsNotFailure(t *testing.T) {
	for _, stage := range []string{"lock", "reload", "health"} {
		t.Run(stage, func(t *testing.T) {
			r1, r2, _ := revisions(t)
			dir := t.TempDir()
			frr := &fakeFRR{}
			a := newActivator(t, dir, frr, nil)
			committed(t, a, r1)

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			switch stage {
			case "lock":
				a.Lock = lockFunc(func(ctx context.Context) (func(), error) {
					cancel()
					return nil, ctx.Err()
				})
			case "reload":
				frr.reloadErr = func(string) error {
					cancel()
					return context.Canceled
				}
			case "health":
				a.Health = func(ctx context.Context, _ string) error {
					cancel()
					return ctx.Err()
				}
			}
			req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
				Settings: Settings{ApplyTimeout: time.Minute, BootLifetime: time.Hour}}
			if _, err := a.Activate(ctx, req); !errors.Is(err, context.Canceled) {
				t.Fatalf("activate during shutdown = %v", err)
			}
			if a.Journal().Failed(testDeployment, 2) {
				t.Fatal("shutdown burned the epoch")
			}
			frr.reloadErr = nil
			restarted := newActivator(t, dir, frr, nil)
			if res, err := restarted.Activate(context.Background(), req); err != nil || res.Outcome != OutcomeCommitted {
				t.Fatalf("after restart = %+v, %v", res, err)
			}
		})
	}
}

type lockFunc func(context.Context) (func(), error)

func (f lockFunc) Lock(ctx context.Context) (func(), error) { return f(ctx) }

// TestCrashAfterRecoveryCheckpoint: a crash after the recovery target was
// checkpointed but before Recovered was journaled resumes into the same
// recovery, once.
func TestCrashAfterRecoveryCheckpoint(t *testing.T) {
	r1, r2, _ := revisions(t)
	dir := t.TempDir()
	frr := &fakeFRR{}
	a := newActivator(t, dir, frr, nil)
	committed(t, a, r1)
	frr.reloadErr = func(path string) error {
		if strings.HasSuffix(path, "active.conf") {
			return errors.New("bgpd refused the change")
		}
		return nil
	}
	a.Fault = func(p string) error {
		if p == FaultAfterRecovery {
			return errCrash
		}
		return nil
	}
	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	if cp, err := ReadCheckpoint(dir); err != nil || cp.Activation.Revision != r1.Name {
		t.Fatalf("checkpoint before the Recovered record = %s, %v", cp.Activation.Revision, err)
	}
	restarted := newActivator(t, dir, frr, nil)
	if res, err := restarted.Resume(context.Background(), req); err != nil || res.Outcome != OutcomeRecovered {
		t.Fatalf("resume = %+v, %v", res, err)
	}
	recovered := 0
	for _, rec := range restarted.Journal().Records() {
		if rec.Type == RecordRecovered {
			recovered++
		}
	}
	if recovered != 1 {
		t.Errorf("journaled %d recoveries", recovered)
	}
}

// TestResumeUsesJournaledRecovery: a redelivery cannot widen what a failed
// epoch may recover to.
func TestResumeUsesJournaledRecovery(t *testing.T) {
	r1, r2, _ := revisions(t)
	dir := t.TempDir()
	frr := &fakeFRR{}
	a := newActivator(t, dir, frr, nil)
	committed(t, a, r1)
	a.Fault = func(p string) error {
		if p == FaultAfterReload {
			return errCrash
		}
		return nil
	}
	revoked := recoveryTo(r1)
	revoked.RevokedPrefixes = []string{testPrefix}
	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: revoked, RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	restarted := newActivator(t, dir, frr, nil)
	restarted.Health = func(context.Context, string) error { return errors.New("peer down") }
	looser := req
	looser.Recovery = recoveryTo(r1)
	res, err := restarted.Activate(context.Background(), looser)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeDegraded || !strings.Contains(res.Detail, "originates revoked") {
		t.Fatalf("resume with a looser recovery = %+v, want Degraded by the journaled revocation", res)
	}
}

// TestResumeRefusesSuperseded: Resume applies the same replay rules as
// Activate, so it cannot roll the checkpoint back to an older epoch or run
// another revision under a journaled epoch.
func TestResumeRefusesSuperseded(t *testing.T) {
	r1, r2, r3 := revisions(t)
	dir := t.TempDir()
	a := newActivator(t, dir, &fakeFRR{}, nil)
	committed(t, a, r1)
	if res, err := a.Activate(context.Background(), Request{Activation: activationOf(r2, 2), Revision: r2}); err != nil ||
		res.Outcome != OutcomeCommitted {
		t.Fatalf("epoch 2 = %+v, %v", res, err)
	}
	old := Request{Activation: activationOf(r1, 1), Revision: r1}
	if _, err := a.Resume(context.Background(), old); !errors.Is(err, ErrStale) {
		t.Errorf("Resume of a superseded epoch = %v, want ErrStale", err)
	}
	other := Request{Activation: activationOf(r3, 2), Revision: r3}
	if _, err := a.Resume(context.Background(), other); !errors.Is(err, ErrStale) {
		t.Errorf("Resume of another revision under epoch 2 = %v, want ErrStale", err)
	}
	mismatched := Request{Activation: activationOf(r2, 2), Revision: r3}
	if _, err := a.Resume(context.Background(), mismatched); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Resume with a revision other than the activation's = %v, want ErrDigestMismatch", err)
	}
	if cp, err := ReadCheckpoint(dir); err != nil || cp.Activation != activationOf(r2, 2) {
		t.Errorf("checkpoint = %s, %v; want epoch 2", cp.Activation.Revision, err)
	}
}

// TestActivateNeedsBoundIdentity: nothing is applied before the state
// directory is bound to this Node and cluster.
func TestActivateNeedsBoundIdentity(t *testing.T) {
	r1, _, _ := revisions(t)
	frr := &fakeFRR{}
	a := &Activator{Dir: t.TempDir(), FRR: frr}
	if err := a.Open(); err != nil {
		t.Fatal(err)
	}
	_, err := a.Activate(context.Background(), Request{Activation: activationOf(r1, 1), Revision: r1})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Activate without an identity = %v, want ErrIdentityMismatch", err)
	}
	if frr.reloads != 0 || len(a.Journal().Records()) != 0 {
		t.Error("an unbound activation reached FRR or the journal")
	}
}

// TestResumeAddsLaterRevocations: a revocation asked for after the epoch
// was accepted still binds its recovery.
func TestResumeAddsLaterRevocations(t *testing.T) {
	r1, r2, _ := revisions(t)
	dir := t.TempDir()
	frr := &fakeFRR{}
	a := newActivator(t, dir, frr, nil)
	committed(t, a, r1)
	a.Fault = func(p string) error {
		if p == FaultAfterReload {
			return errCrash
		}
		return nil
	}
	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	if _, err := a.Activate(context.Background(), req); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	restarted := newActivator(t, dir, frr, nil)
	restarted.Health = func(context.Context, string) error { return errors.New("peer down") }
	later := req
	later.Recovery.RevokedPrefixes = []string{testPrefix}
	res, err := restarted.Activate(context.Background(), later)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeDegraded || !strings.Contains(res.Detail, originatesRevoked) {
		t.Fatalf("resume with a later revocation = %+v, want Degraded by it", res)
	}
}
