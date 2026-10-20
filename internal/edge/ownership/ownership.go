// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ownership serializes and fences every write to a node's shared
// datapath state for one scope, typically one VPC's canonical host table and
// SID, across all the processes that write it.
//
// Each scope has a durable record: its owner, an ownership generation and a
// revision. A writer obtains a Ticket, prepares its change without holding
// anything, then commits through Commit, which takes the scope's exclusive
// file lock, checks the ticket against the record and runs the mutation while
// still holding the lock. A ticket from an earlier generation or revision is
// refused at that point, so work paused between preparing and committing, a
// maintenance snapshot taken before another write, or a writer that lost
// ownership, can never land. Checking a generation before a netlink or map
// call outside the lock would not fence that call; holding the lock through
// it does.
//
// Ownership moves through a barrier. Fence marks the scope transitioning and
// advances the generation, invalidating every outstanding ticket at once.
// Adopt then names the new owner, who must reconcile its complete desired
// state with CommitSnapshot before incremental commits are accepted again.
// A commit whose mutation fails, or whose process dies mid-mutation, leaves
// the scope in the same resync-required state, because a partly applied
// change cannot be assumed either done or undone.
package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

var (
	// ErrStale is returned when a ticket's generation, owner or revision no
	// longer matches the scope's record.
	ErrStale = errors.New("ownership: stale ticket")
	// ErrNotOwner is returned when the caller does not own the scope.
	ErrNotOwner = errors.New("ownership: caller does not own the scope")
	// ErrTransitioning is returned while ownership of the scope is moving.
	ErrTransitioning = errors.New("ownership: scope is transitioning between owners")
	// ErrResyncRequired is returned for an incremental commit while the scope
	// needs its complete desired state reconciled first.
	ErrResyncRequired = errors.New("ownership: scope requires a complete snapshot commit")
	// ErrNoOwner is returned when a caller names no owner. An unowned
	// scope may be claimed by anyone, so an empty owner would open the
	// barrier.
	ErrNoOwner = errors.New("ownership: owner must not be empty")
)

var scopeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Record is a scope's durable ownership state.
type Record struct {
	Owner         string `json:"owner"`
	Generation    uint64 `json:"generation"`
	Revision      uint64 `json:"revision"`
	Transitioning bool   `json:"transitioning"`
	// Pending is set while a commit's mutation runs and cleared when it
	// succeeds. Finding it set means a mutation may be partly applied.
	Pending bool `json:"pending"`
}

func (r Record) resync() bool { return r.Pending }

// Ticket authorizes one commit against the scope state it was issued for.
type Ticket struct {
	Scope      string
	Owner      string
	Generation uint64
	Revision   uint64
	// Resync reports that only CommitSnapshot is accepted with this ticket.
	Resync bool
}

// Authority keeps the records of every scope under one directory, which every
// writer process on the node must share.
type Authority struct {
	dir string
}

// New returns an authority over dir, creating it if needed.
func New(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ownership: create %s: %w", dir, err)
	}
	return &Authority{dir: dir}, nil
}

// Claim makes owner the owner of an unowned scope and returns its first
// ticket, which requires a snapshot commit: state may already exist in the
// kernel from before the scope had a record. Claiming a scope owner already holds returns a current ticket; a
// scope owned by anyone else is ErrNotOwner, which only Fence and Adopt can
// change.
func (a *Authority) Claim(scope, owner string) (Ticket, error) {
	if owner == "" {
		return Ticket{}, ErrNoOwner
	}
	var t Ticket
	err := a.locked(scope, func(r *Record) (bool, error) {
		switch {
		case r.Owner == "" && !r.Transitioning:
			r.Owner, r.Generation, r.Pending = owner, r.Generation+1, true
			t = ticket(scope, *r)
			return true, nil
		case r.Owner == owner && !r.Transitioning:
			t = ticket(scope, *r)
			return false, nil
		case r.Transitioning:
			return false, ErrTransitioning
		default:
			return false, fmt.Errorf("%w: %q owns %q", ErrNotOwner, r.Owner, scope)
		}
	})
	return t, err
}

// Begin returns a ticket for owner's next commit to scope.
func (a *Authority) Begin(scope, owner string) (Ticket, error) {
	if owner == "" {
		return Ticket{}, ErrNoOwner
	}
	var t Ticket
	err := a.locked(scope, func(r *Record) (bool, error) {
		if err := checkOwner(scope, owner, *r); err != nil {
			return false, err
		}
		t = ticket(scope, *r)
		return false, nil
	})
	return t, err
}

// Commit runs mutate with the scope's lock held, provided t still matches the
// record, and returns the ticket for the next commit. If mutate fails the
// scope requires a snapshot commit before any further incremental one.
//
// mutate must not call the authority for the same scope: the lock is a file
// lock, which conflicts across open files even within one process, so such a
// call deadlocks.
func (a *Authority) Commit(t Ticket, mutate func() error) (Ticket, error) {
	return a.commit(t, false, mutate)
}

// CommitSnapshot is Commit for a mutation that reconciles the scope's
// complete desired state, replacing whatever is there. It is accepted whether
// or not the scope requires a resync, and clears that requirement on success.
func (a *Authority) CommitSnapshot(t Ticket, mutate func() error) (Ticket, error) {
	return a.commit(t, true, mutate)
}

func (a *Authority) commit(t Ticket, snapshot bool, mutate func() error) (Ticket, error) {
	var next Ticket
	err := a.lockedStaged(t.Scope, func(r *Record, persist func() error) error {
		if err := checkOwner(t.Scope, t.Owner, *r); err != nil {
			return err
		}
		if r.Generation != t.Generation || r.Revision != t.Revision {
			return fmt.Errorf("%w: ticket generation %d revision %d, scope at generation %d revision %d",
				ErrStale, t.Generation, t.Revision, r.Generation, r.Revision)
		}
		if r.resync() && !snapshot {
			return ErrResyncRequired
		}
		r.Pending = true
		if err := persist(); err != nil {
			return err
		}
		if err := mutate(); err != nil {
			return err
		}
		r.Pending = false
		r.Revision++
		if err := persist(); err != nil {
			return err
		}
		next = ticket(t.Scope, *r)
		return nil
	})
	return next, err
}

// Fence starts a transfer: it marks the scope transitioning and advances its
// generation, so no ticket issued before it can commit, and no writer can
// begin, until Adopt. It returns the new generation, which Adopt requires.
// Fence returns only after any commit in progress has finished, because that
// commit holds the lock Fence waits for.
func (a *Authority) Fence(scope string) (uint64, error) {
	var gen uint64
	err := a.locked(scope, func(r *Record) (bool, error) {
		r.Transitioning = true
		r.Generation++
		gen = r.Generation
		return true, nil
	})
	return gen, err
}

// Adopt completes the transfer Fence started at generation, naming owner. The
// returned ticket requires a snapshot commit, since the new owner must
// reconcile the complete state before writing incrementally.
func (a *Authority) Adopt(scope, owner string, generation uint64) (Ticket, error) {
	if owner == "" {
		return Ticket{}, ErrNoOwner
	}
	var t Ticket
	err := a.locked(scope, func(r *Record) (bool, error) {
		if !r.Transitioning || r.Generation != generation {
			return false, fmt.Errorf("%w: no transfer at generation %d (scope at %d, transitioning %t)",
				ErrStale, generation, r.Generation, r.Transitioning)
		}
		r.Owner, r.Transitioning, r.Pending = owner, false, true
		t = ticket(scope, *r)
		return true, nil
	})
	return t, err
}

// Read returns the scope's record.
func (a *Authority) Read(scope string) (Record, error) {
	var out Record
	err := a.locked(scope, func(r *Record) (bool, error) {
		out = *r
		return false, nil
	})
	return out, err
}

func ticket(scope string, r Record) Ticket {
	return Ticket{Scope: scope, Owner: r.Owner, Generation: r.Generation, Revision: r.Revision, Resync: r.resync()}
}

func checkOwner(scope, owner string, r Record) error {
	if r.Transitioning {
		return ErrTransitioning
	}
	if r.Owner != owner {
		return fmt.Errorf("%w: %q owns %q, not %q", ErrNotOwner, r.Owner, scope, owner)
	}
	return nil
}

// locked runs fn with the scope's exclusive lock held and writes the record
// back when fn reports a change.
func (a *Authority) locked(scope string, fn func(r *Record) (bool, error)) error {
	return a.lockedStaged(scope, func(r *Record, persist func() error) error {
		changed, err := fn(r)
		if err != nil || !changed {
			return err
		}
		return persist()
	})
}

// lockedStaged runs fn with the scope's exclusive lock held, giving it a
// persist function that durably writes the record as it stands.
func (a *Authority) lockedStaged(scope string, fn func(r *Record, persist func() error) error) error {
	if !scopeName.MatchString(scope) {
		return fmt.Errorf("ownership: invalid scope name %q", scope)
	}
	lockPath := filepath.Join(a.dir, scope+".lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("ownership: open %s: %w", lockPath, err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("ownership: lock %s: %w", lockPath, err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()

	statePath := filepath.Join(a.dir, scope+".json")
	var r Record
	switch b, err := os.ReadFile(statePath); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("ownership: read %s: %w", statePath, err)
	default:
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("ownership: decode %s: %w", statePath, err)
		}
	}
	return fn(&r, func() error { return writeRecord(statePath, r) })
}

// writeRecord replaces the record file atomically and durably.
func writeRecord(path string, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ownership: write %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("ownership: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("ownership: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ownership: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ownership: replace %s: %w", path, err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("ownership: open %s: %w", filepath.Dir(path), err)
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
