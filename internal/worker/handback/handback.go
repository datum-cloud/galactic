// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handback returns the VPC scopes a stopped galactic-worker owned on
// this node to the writers it took them from (docs/worker/ownership.md,
// "Handing scopes back").
//
// Garbage collection, galactic-router and the installer leave a scope a
// galactic-worker incarnation owns to that Worker, even one that no longer
// runs, so removing Worker without a handback leaves those scopes' host
// state unreclaimed and their tenant routes unwritten. Run removes what only
// Worker's Local module wrote and leaves everything else, including the
// tenant routes Worker's Fabric module wrote, which galactic-router writes
// again once it restarts.
package handback

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/module"
)

// errTaken is a scope another writer took after Run relinquished it.
var errTaken = errors.New("handback: another writer took the scope")

// ErrWorkerRunning is returned while a Worker answers on the socket.
var ErrWorkerRunning = errors.New("handback: a galactic-worker answers on the socket; stop it first")

// Releaser removes what a Worker module programmed for a scope.
type Releaser interface {
	Release(ctx context.Context, scope module.Scope) error
}

// Config configures Run.
type Config struct {
	// Fence is the node's VPC write fence.
	Fence *ownership.Authority
	// Socket is the Worker API socket. Run refuses while a process accepts
	// connections on it.
	Socket string
	// Local removes Worker's Local state from a scope. Nil when the Local
	// module never ran on the node, so there is nothing to remove.
	Local Releaser
	// ClaimsDir holds Worker's durable desired state. Run empties it once
	// every scope is handed back, so a Worker installed later starts with
	// no claims. Empty leaves it.
	ClaimsDir string
	// Remove are files Run deletes at the end, such as the status snapshot.
	Remove []string
	// RemoveAll are directories Run deletes at the end with their contents,
	// such as the Local module's bpffs pins, which nothing uses once every
	// scope's Local state is gone.
	RemoveAll []string
	// Now is the clock, time.Now when nil. The handback label carries the
	// time.
	Now func() time.Time
	Log *slog.Logger
}

// Result is what Run did.
type Result struct {
	// Owner is the handback label Run left on the scopes it handed back.
	Owner string
	// HandedBack are the scopes Run relinquished from a Worker incarnation.
	HandedBack []string
	// Released are the scopes whose Local state Run removed, including ones
	// an earlier, interrupted handback had relinquished.
	Released []string
}

// dialTimeout bounds the check for a running Worker.
const dialTimeout = 2 * time.Second

// Run hands back every VPC scope a galactic-worker incarnation owns. For
// each, it first relinquishes the scope to a handback label with a pending
// resync, so no Worker commit lands afterwards, and then removes Worker's
// Local state under the fence. A scope an earlier handback left labelled has
// its Local state removed again, so an interrupted Run can be repeated.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Fence == nil {
		return Result{}, errors.New("handback: the ownership fence is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if err := checkStopped(ctx, cfg.Socket); err != nil {
		return Result{}, err
	}
	res := Result{Owner: ownership.HandbackOwnerPrefix + cfg.Now().UTC().Format("20060102T150405Z")}
	scopes, err := cfg.Fence.Scopes()
	if err != nil {
		return res, err
	}
	slices.Sort(scopes)
	// The incarnations that own scopes now are the stopped Worker's. A
	// scope that another incarnation takes during the run belongs to a
	// Worker that came back, and stays its own.
	stopped, err := workerOwners(cfg.Fence, scopes)
	if err != nil {
		return res, err
	}
	var errs []error
	for _, scope := range scopes {
		vpc, ok := strings.CutPrefix(scope, "vpc-")
		if !ok {
			continue
		}
		rec, err := cfg.Fence.Read(scope)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ownership.WorkerOwned(rec.Owner) {
			if !stopped[rec.Owner] {
				errs = append(errs, fmt.Errorf("%w: %q took %s during the handback", ErrWorkerRunning, rec.Owner, scope))
				continue
			}
			// A scope moving to another writer is left to that transfer;
			// Relinquish would cancel it.
			gen, err := cfg.Fence.Relinquish(scope, func(r ownership.Record) bool {
				return stopped[r.Owner] && !r.Transitioning
			}, res.Owner)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			cfg.Log.Info("handed a VPC scope back", "scope", scope, "from", rec.Owner, "owner", res.Owner,
				"generation", gen)
			res.HandedBack = append(res.HandedBack, scope)
		} else if !ownership.HandedBack(rec.Owner) {
			continue
		}
		if cfg.Local == nil {
			continue
		}
		// The scope is no longer Worker's, so its Local state goes as any
		// non-owner's write does, under the fence and only while the
		// handback label still holds it: a writer that has taken the scope
		// since keeps it.
		err = cfg.Fence.ExclusiveIf(scope, func(r ownership.Record) error {
			if !ownership.HandedBack(r.Owner) {
				return fmt.Errorf("%w: %q", errTaken, r.Owner)
			}
			return nil
		}, func() error {
			return cfg.Local.Release(ctx, module.Scope{VPC: vpc})
		})
		if errors.Is(err, errTaken) {
			// The new owner keeps what is there; a Worker that took it back
			// fails the run below, before its claims or pins are touched.
			cfg.Log.Info("left a scope another writer took after the handback", "scope", scope, "error", err)
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("handback: remove Local state of %s: %w", scope, err))
			continue
		}
		res.Released = append(res.Released, scope)
	}
	if err := errors.Join(errs...); err != nil {
		return res, err
	}
	// The claims, pins and snapshot belong to whichever Worker runs next, so
	// they go only while none has started and taken a scope back since.
	if err := checkStopped(ctx, cfg.Socket); err != nil {
		return res, err
	}
	if err := noWorkerScopes(cfg.Fence); err != nil {
		return res, err
	}
	if cfg.ClaimsDir != "" {
		if err := clearDir(cfg.ClaimsDir); err != nil {
			return res, err
		}
	}
	for _, f := range cfg.Remove {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return res, fmt.Errorf("handback: %w", err)
		}
	}
	for _, d := range cfg.RemoveAll {
		if err := os.RemoveAll(d); err != nil {
			return res, fmt.Errorf("handback: %w", err)
		}
	}
	return res, nil
}

// checkStopped refuses while a process accepts connections on socket. A
// missing socket, or one nothing listens on, means Worker has stopped.
func checkStopped(ctx context.Context, socket string) error {
	if socket == "" {
		return errors.New("handback: the Worker socket path is required")
	}
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "unix", socket)
	switch {
	case err == nil:
		_ = conn.Close()
		return ErrWorkerRunning
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		return nil
	default:
		return fmt.Errorf("handback: cannot tell whether a Worker runs on %s: %w", socket, err)
	}
}

// workerOwners returns the Worker incarnations that own any of scopes.
func workerOwners(fence *ownership.Authority, scopes []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, scope := range scopes {
		rec, err := fence.Read(scope)
		if err != nil {
			return nil, err
		}
		if ownership.WorkerOwned(rec.Owner) {
			out[rec.Owner] = true
		}
	}
	return out, nil
}

// noWorkerScopes fails when a Worker incarnation owns any VPC scope.
func noWorkerScopes(fence *ownership.Authority) error {
	scopes, err := fence.Scopes()
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		rec, err := fence.Read(scope)
		if err != nil {
			return err
		}
		if ownership.WorkerOwned(rec.Owner) {
			return fmt.Errorf("%w: %q owns %s; leaving its claims and pins", ErrWorkerRunning, rec.Owner, scope)
		}
	}
	return nil
}

// clearDir removes every regular file in dir, which must exist or be
// missing.
func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("handback: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("handback: %w", err)
		}
	}
	return nil
}
