// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ownership

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

const scope = "vpc-a"

func newAuthority(t *testing.T) *Authority {
	t.Helper()
	a, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// owned returns an authority whose scope is owned by "cni" with its initial
// snapshot committed.
func owned(t *testing.T) (*Authority, Ticket) {
	t.Helper()
	a := newAuthority(t)
	tk, err := a.Claim(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("first claim did not require a snapshot")
	}
	tk, err = a.CommitSnapshot(tk, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return a, tk
}

// noCheck is an Exclusive check that always lets the write go ahead.
func noCheck() error { return nil }

func mustNotRun(t *testing.T) func() error {
	return func() error {
		t.Error("mutation ran for a refused commit")
		return nil
	}
}

func TestCommitAdvancesRevision(t *testing.T) {
	a, tk := owned(t)
	next, err := a.Commit(tk, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != tk.Revision+1 || next.Generation != tk.Generation {
		t.Fatalf("next ticket %+v after %+v", next, tk)
	}
}

func TestStaleSnapshotCannotCommit(t *testing.T) {
	a, _ := owned(t)
	refresh, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	withdraw, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(withdraw, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// The refresh prepared its snapshot before the withdrawal committed.
	if _, err := a.Commit(refresh, mustNotRun(t)); !errors.Is(err, ErrStale) {
		t.Fatalf("commit of a snapshot taken before a later write = %v, want ErrStale", err)
	}
}

func TestPausedWriterIsFencedByTransfer(t *testing.T) {
	a, _ := owned(t)
	paused, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Begin(scope, "cni"); !errors.Is(err, ErrTransitioning) {
		t.Fatalf("begin during transfer = %v, want ErrTransitioning", err)
	}
	if _, err := a.Commit(paused, mustNotRun(t)); !errors.Is(err, ErrTransitioning) {
		t.Fatalf("paused commit during transfer = %v, want ErrTransitioning", err)
	}
	adopted, err := a.Adopt(scope, "attachment-authority", gen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(paused, mustNotRun(t)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("paused commit after adoption = %v, want ErrNotOwner", err)
	}
	if _, err := a.Commit(adopted, mustNotRun(t)); !errors.Is(err, ErrResyncRequired) {
		t.Fatalf("incremental commit before the adopter's snapshot = %v, want ErrResyncRequired", err)
	}
	if _, err := a.CommitSnapshot(adopted, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Begin(scope, "cni"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("old owner begin after adoption = %v, want ErrNotOwner", err)
	}
}

func TestHandbackUsesTheSameBarrier(t *testing.T) {
	a, _ := owned(t)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Adopt(scope, "attachment-authority", gen); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Adopt(scope, "cni", gen); !errors.Is(err, ErrStale) {
		t.Fatalf("second adoption of one fence = %v, want ErrStale", err)
	}
	gen, err = a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	back, err := a.Adopt(scope, "cni", gen)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Resync {
		t.Fatal("handback did not require the old owner's complete snapshot")
	}
}

func TestFenceWaitsForCommitInProgress(t *testing.T) {
	a, tk := owned(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var mutationDone atomic.Bool
	go func() {
		_, _ = a.Commit(tk, func() error {
			close(entered)
			<-release
			mutationDone.Store(true)
			return nil
		})
	}()
	<-entered
	fenced := make(chan bool)
	go func() {
		_, err := a.Fence(scope)
		fenced <- err == nil && mutationDone.Load()
	}()
	select {
	case <-fenced:
		t.Fatal("fence returned while a commit's mutation was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if ok := <-fenced; !ok {
		t.Fatal("fence did not observe the finished mutation")
	}
}

func TestFailedMutationRequiresSnapshot(t *testing.T) {
	a, tk := owned(t)
	if _, err := a.Commit(tk, func() error { return errors.New("netlink: partial") }); err == nil {
		t.Fatal("failed mutation reported success")
	}
	tk, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("scope does not require a snapshot after a failed mutation")
	}
	if _, err := a.Commit(tk, mustNotRun(t)); !errors.Is(err, ErrResyncRequired) {
		t.Fatalf("incremental commit after failure = %v, want ErrResyncRequired", err)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveWriteStalesOwnerTickets(t *testing.T) {
	a, tk := owned(t)
	ran := false
	if err := a.Exclusive(scope, noCheck, func() error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("exclusive mutation did not run")
	}
	// The owner prepared this change before the maintenance write landed.
	if _, err := a.Commit(tk, mustNotRun(t)); !errors.Is(err, ErrStale) {
		t.Fatalf("commit of a ticket issued before an exclusive write = %v, want ErrStale", err)
	}
	rec, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Owner != "cni" || rec.Transitioning || rec.Pending {
		t.Fatalf("record after exclusive write = %+v, want owner kept, not transitioning or pending", rec)
	}
	next, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(next, func() error { return nil }); err != nil {
		t.Fatalf("owner commit from a fresh ticket = %v", err)
	}
}

func TestExclusiveWriteLeavesScopeUnowned(t *testing.T) {
	a := newAuthority(t)
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	tk, err := a.Claim(scope, "edge")
	if err != nil {
		t.Fatalf("claim after an exclusive write = %v", err)
	}
	if !tk.Resync {
		t.Fatal("first claim did not require a snapshot")
	}
}

func TestFailedExclusiveWriteRequiresSnapshot(t *testing.T) {
	a, _ := owned(t)
	if err := a.Exclusive(scope, noCheck, func() error { return errors.New("netlink: partial") }); err == nil {
		t.Fatal("failed exclusive mutation reported success")
	}
	tk, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("scope does not require a snapshot after a failed exclusive mutation")
	}
	if _, err := a.Commit(tk, mustNotRun(t)); !errors.Is(err, ErrResyncRequired) {
		t.Fatalf("incremental commit after failure = %v, want ErrResyncRequired", err)
	}
}

func TestExclusiveWriteWaitsForCommitInProgress(t *testing.T) {
	a, tk := owned(t)
	inside, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := a.Commit(tk, func() error {
			close(inside)
			<-release
			return nil
		})
		done <- err
	}()
	<-inside
	var finished atomic.Bool
	excl := make(chan error, 1)
	go func() {
		excl <- a.Exclusive(scope, noCheck, func() error {
			if !finished.Load() {
				return errors.New("exclusive write ran during the owner's commit")
			}
			return nil
		})
	}()
	time.Sleep(50 * time.Millisecond)
	finished.Store(true)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-excl; err != nil {
		t.Fatal(err)
	}
}

func TestRefusedCheckLeavesRecord(t *testing.T) {
	a, tk := owned(t)
	refused := errors.New("in use")
	if err := a.Exclusive(scope, func() error { return refused }, mustNotRun(t)); !errors.Is(err, refused) {
		t.Fatalf("exclusive write with a failed check = %v, want the check's error", err)
	}
	// Nothing was written, so the owner's ticket is still current.
	if _, err := a.Commit(tk, func() error { return nil }); err != nil {
		t.Fatalf("owner commit after a refused exclusive write = %v", err)
	}
}

func TestExclusiveWriteWaitsForAdopt(t *testing.T) {
	a, _ := owned(t)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	checked := func() error {
		t.Error("check ran while ownership moved")
		return nil
	}
	if err := a.Exclusive(scope, checked, mustNotRun(t)); !errors.Is(err, ErrTransitioning) {
		t.Fatalf("exclusive write during a transfer = %v, want ErrTransitioning", err)
	}
	if _, err := a.Adopt(scope, "edge", gen); err != nil {
		t.Fatal(err)
	}
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatalf("exclusive write after Adopt = %v", err)
	}
}

func TestOpenRequiresExistingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := Open(missing); err == nil {
		t.Fatal("open of a missing directory succeeded")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open created %s", missing)
	}
	dir := t.TempDir()
	owner, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := owner.Claim(scope, "edge")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CommitSnapshot(tk, mustNotRun(t)); !errors.Is(err, ErrStale) {
		t.Fatalf("owner commit after another authority's exclusive write = %v, want ErrStale", err)
	}
}

func TestVPCScopeIgnoresPadding(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"00000000a", "a"},
		{"000", "0"},
	} {
		if VPCScope(tc.a) != VPCScope(tc.b) {
			t.Errorf("VPCScope(%q) = %q, VPCScope(%q) = %q; want one scope", tc.a, VPCScope(tc.a), tc.b, VPCScope(tc.b))
		}
	}
	if VPCScope("a") == VPCScope("0a0") {
		t.Error("distinct VPCs share a scope")
	}
}

func TestOnlyTheOwnerBegins(t *testing.T) {
	a, _ := owned(t)
	if _, err := a.Begin(scope, "router"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("begin by another writer = %v, want ErrNotOwner", err)
	}
	if _, err := a.Claim(scope, "router"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("claim of an owned scope = %v, want ErrNotOwner", err)
	}
	if _, err := a.Begin("../escape", "cni"); err == nil {
		t.Fatal("invalid scope name accepted")
	}
}

const helperEnv = "OWNERSHIP_TEST_HELPER"

// TestHelperProcess is the body of another writer process, run by the
// cross-process tests through the test binary.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	a, err := New(os.Getenv("OWNERSHIP_TEST_DIR"))
	if err != nil {
		os.Exit(2)
	}
	tk, err := a.Begin(scope, "cni")
	if err != nil {
		os.Exit(3)
	}
	marker := os.Getenv("OWNERSHIP_TEST_MARKER")
	_, _ = a.Commit(tk, func() error {
		_ = os.WriteFile(marker, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
		if mode == "crash" {
			os.Exit(1)
		}
		time.Sleep(300 * time.Millisecond)
		return nil
	})
	os.Exit(0)
}

func startHelper(t *testing.T, dir, mode, marker string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, "OWNERSHIP_TEST_DIR="+dir, "OWNERSHIP_TEST_MARKER="+marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCommitsExcludeAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := a.Claim(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "helper-entered")
	helper := startHelper(t, dir, "hold", marker)
	waitFor(t, marker)
	// The helper holds the scope for 300ms inside its mutation.
	start := time.Now()
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Fatalf("fence returned after %v while another process was mid-mutation", waited)
	}
	if err := helper.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	r, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation != gen || !r.Transitioning || r.Revision != 2 {
		t.Fatalf("record after cross-process commit and fence = %+v", r)
	}
}

func TestProcessDeathMidMutationRequiresSnapshot(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := a.Claim(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "helper-entered")
	helper := startHelper(t, dir, "crash", marker)
	if err := helper.Wait(); err == nil {
		t.Fatal("helper did not die mid-mutation")
	}
	tk, err = a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("scope does not require a snapshot after a writer died mid-mutation")
	}
}

func TestEmptyOwnerIsRefused(t *testing.T) {
	a, _ := owned(t)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Adopt(scope, "", gen); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("adopt with no owner = %v, want ErrNoOwner", err)
	}
	if _, err := a.Claim("vpc-b", ""); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("claim with no owner = %v, want ErrNoOwner", err)
	}
	if _, err := a.Begin(scope, ""); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("begin with no owner = %v, want ErrNoOwner", err)
	}
	r, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Transitioning || r.Owner != "cni" {
		t.Fatalf("record after refused adoption = %+v, want still transitioning from cni", r)
	}
}

func TestZeroOwnerTicketCannotCommitUnclaimedScope(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("snapshot=%t", snapshot), func(t *testing.T) {
			a, err := New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.commit(Ticket{Scope: "unclaimed"}, snapshot, mustNotRun(t))
			if !errors.Is(err, ErrNoOwner) {
				t.Fatalf("zero owner commit = %v, want ErrNoOwner", err)
			}
			record, err := a.Read("unclaimed")
			if err != nil {
				t.Fatal(err)
			}
			if record != (Record{}) {
				t.Fatalf("rejected commit changed record: %+v", record)
			}
		})
	}
}
