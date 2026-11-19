// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package handback

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/module"
)

const (
	deadWorker = ownership.WorkerOwnerPrefix + "node-a:0123456789abcdef"
	cniOwner   = "galactic-cni"
)

// fakeLocal records the scopes it released and can fail one.
type fakeLocal struct {
	released []string
	fail     string
}

func (f *fakeLocal) Release(_ context.Context, s module.Scope) error {
	if s.VPC == f.fail {
		return errors.New("release failed")
	}
	f.released = append(f.released, s.VPC)
	return nil
}

// fenceWith returns a fence holding the given owner for each VPC; an empty
// owner leaves the VPC's scope unowned.
func fenceWith(t *testing.T, owners map[string]string) (*ownership.Authority, string) {
	t.Helper()
	dir := t.TempDir()
	fence, err := ownership.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for vpc, owner := range owners {
		scope := ownership.VPCScope(vpc)
		if owner == "" {
			if err := fence.Exclusive(scope, func() error { return nil }, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			continue
		}
		tk, err := fence.Claim(scope, owner)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fence.CommitSnapshot(tk, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return fence, dir
}

func owner(t *testing.T, fence *ownership.Authority, vpc string) ownership.Record {
	t.Helper()
	r, err := fence.Read(ownership.VPCScope(vpc))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func noSocket(t *testing.T) string { return filepath.Join(t.TempDir(), "worker.sock") }

var fixedNow = func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }

func TestRunHandsBackOnlyWorkerScopes(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker, "11": cniOwner, "12": "", "13": deadWorker})
	claims := t.TempDir()
	if err := os.WriteFile(filepath.Join(claims, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(status, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(t.TempDir(), "galactic-local")
	if err := os.MkdirAll(filepath.Join(pins, "maps"), 0o700); err != nil {
		t.Fatal(err)
	}
	loc := &fakeLocal{}
	res, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t), Local: loc, ClaimsDir: claims,
		Remove: []string{status}, RemoveAll: []string{pins}, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	wantOwner := ownership.HandbackOwnerPrefix + "20261119T120000Z"
	if res.Owner != wantOwner {
		t.Fatalf("owner %q, want %q", res.Owner, wantOwner)
	}
	if want := []string{"vpc-10", "vpc-13"}; !slices.Equal(res.HandedBack, want) || !slices.Equal(res.Released, want) {
		t.Fatalf("handed back %v and released %v, want %v", res.HandedBack, res.Released, want)
	}
	if want := []string{"10", "13"}; !slices.Equal(loc.released, want) {
		t.Fatalf("Local released %v, want %v", loc.released, want)
	}
	for _, vpc := range []string{"10", "13"} {
		r := owner(t, fence, vpc)
		if r.Owner != wantOwner || !r.Pending || r.Transitioning {
			t.Fatalf("VPC %s record %+v: want the handback label with a resync pending", vpc, r)
		}
	}
	if r := owner(t, fence, "11"); r.Owner != cniOwner {
		t.Fatalf("another writer's scope moved: %+v", r)
	}
	if r := owner(t, fence, "12"); r.Owner != "" {
		t.Fatalf("an unowned scope gained an owner: %+v", r)
	}
	if entries, _ := os.ReadDir(claims); len(entries) != 0 {
		t.Fatalf("claims left: %v", entries)
	}
	if _, err := os.Stat(status); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status snapshot left (%v)", err)
	}
	if _, err := os.Stat(pins); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Local pins left (%v)", err)
	}
}

func TestRunRefusesWhileWorkerAnswers(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker})
	sock := filepath.Join(t.TempDir(), "worker.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	loc := &fakeLocal{}
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: sock, Local: loc}); !errors.Is(err,
		ErrWorkerRunning) {
		t.Fatalf("Run with a live Worker: %v, want ErrWorkerRunning", err)
	}
	if r := owner(t, fence, "10"); r.Owner != deadWorker || len(loc.released) != 0 {
		t.Fatalf("Run changed state while a Worker answered: %+v, released %v", r, loc.released)
	}

	// A socket file nothing listens on is a stopped Worker's.
	_ = l.Close()
	stale := filepath.Join(t.TempDir(), "worker.sock")
	sl, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	sl.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = sl.Close()
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: stale, Local: loc}); err != nil {
		t.Fatalf("Run with a stale socket: %v", err)
	}
}

// TestRunRepeatsAfterInterruption checks that a scope a failed Run left
// labelled has its Local state removed by the next Run, and that a Run
// that fails leaves the claims.
func TestRunRepeatsAfterInterruption(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker, "11": deadWorker})
	claims := t.TempDir()
	if err := os.WriteFile(filepath.Join(claims, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	loc := &fakeLocal{fail: "11"}
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t), Local: loc,
		ClaimsDir: claims}); err == nil {
		t.Fatal("Run succeeded although Local failed")
	}
	if entries, _ := os.ReadDir(claims); len(entries) != 1 {
		t.Fatalf("a failed Run removed the claims: %v", entries)
	}
	loc.fail = ""
	res, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t), Local: loc, ClaimsDir: claims})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HandedBack) != 0 || !slices.Equal(res.Released, []string{"vpc-10", "vpc-11"}) {
		t.Fatalf("second Run handed back %v and released %v", res.HandedBack, res.Released)
	}
}

// TestRunLeavesScopeAnotherWriterTook checks that Local state stays when a
// legacy writer took the scope after it was handed back.
func TestRunLeavesScopeAnotherWriterTook(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker})
	scope := ownership.VPCScope("10")
	if _, err := fence.Relinquish(scope, func(r ownership.Record) bool { return ownership.WorkerOwned(r.Owner) },
		ownership.HandbackOwnerPrefix+"earlier"); err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Takeover(scope, "galactic-edge", func(r ownership.Record) bool {
		return ownership.HandedBack(r.Owner)
	}); err != nil {
		t.Fatal(err)
	}
	loc := &fakeLocal{}
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t), Local: loc}); err != nil {
		t.Fatal(err)
	}
	if len(loc.released) != 0 {
		t.Fatalf("Run removed Local state of a scope galactic-edge owns: %v", loc.released)
	}
}

// TestGCReclaimsOnlyAfterHandback checks that garbage collection's guard
// leaves a dead Worker incarnation's scope alone, and reclaims it once
// handed back: the handback is the only way the scope becomes reclaimable.
func TestGCReclaimsOnlyAfterHandback(t *testing.T) {
	fence, dir := fenceWith(t, map[string]string{"10": deadWorker})
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	g, err := maintenance.NewGuard(fake.NewClientBuilder().WithScheme(scheme).Build(), "node-a", dir)
	if err != nil {
		t.Fatal(err)
	}
	g.HostLinks = func() ([]hostattach.ObservedAttachment, error) { return nil, nil }
	reclaimed := 0
	reclaim := func() error { reclaimed++; return nil }

	// The Worker is gone, but its incarnation still owns the scope.
	if err := g.Reclaim(context.Background(), "10", reclaim); !errors.Is(err, ownership.ErrWorkerOwned) ||
		reclaimed != 0 {
		t.Fatalf("GC before handback: %v, reclaimed %d; want ErrWorkerOwned and nothing", err, reclaimed)
	}
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t)}); err != nil {
		t.Fatal(err)
	}
	if err := g.Reclaim(context.Background(), "10", reclaim); err != nil || reclaimed != 1 {
		t.Fatalf("GC after handback: %v, reclaimed %d; want it reclaimed", err, reclaimed)
	}
}

// restartingLocal plays a Worker pod that comes back during a handback: while
// the handback releases one scope, a new Worker incarnation takes another.
type restartingLocal struct {
	fence *ownership.Authority
	take  string
}

func (r *restartingLocal) Release(context.Context, module.Scope) error {
	if r.take == "" {
		return nil
	}
	_, err := r.fence.Takeover(ownership.VPCScope(r.take), ownership.WorkerOwnerPrefix+"node-a:new",
		func(ownership.Record) bool { return true })
	r.take = ""
	return err
}

// TestRunKeepsStateOfReturningWorker checks that a handback during which a
// Worker comes back leaves that Worker's claims and pins.
func TestRunKeepsStateOfReturningWorker(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker, "11": cniOwner})
	claims := t.TempDir()
	if err := os.WriteFile(filepath.Join(claims, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t),
		Local: &restartingLocal{fence: fence, take: "11"}, ClaimsDir: claims})
	if !errors.Is(err, ErrWorkerRunning) {
		t.Fatalf("Run with a Worker back: %v, want ErrWorkerRunning", err)
	}
	if entries, _ := os.ReadDir(claims); len(entries) != 1 {
		t.Fatalf("the returning Worker's claims went: %v", entries)
	}
}

// TestRunLeavesTransitioningScope checks that a Worker-owned scope moving to
// another writer is left to that transfer and reported.
func TestRunLeavesTransitioningScope(t *testing.T) {
	fence, _ := fenceWith(t, map[string]string{"10": deadWorker})
	if _, err := fence.Fence(ownership.VPCScope("10")); err != nil {
		t.Fatal(err)
	}
	loc := &fakeLocal{}
	if _, err := Run(context.Background(), Config{Fence: fence, Socket: noSocket(t), Local: loc}); !errors.Is(err,
		ownership.ErrNotOwner) {
		t.Fatalf("Run over a transitioning scope: %v, want ErrNotOwner", err)
	}
	if r := owner(t, fence, "10"); r.Owner != deadWorker || !r.Transitioning || len(loc.released) != 0 {
		t.Fatalf("the transfer was disturbed: %+v, released %v", r, loc.released)
	}
}
