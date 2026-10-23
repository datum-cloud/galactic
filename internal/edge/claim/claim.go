// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package claim implements finite-validity forwarding claims: the authority
// one service instance holds to forward traffic for one attachment, fenced by
// an owner epoch.
//
// A claim is a record in a store that supports compare-and-swap, such as a
// Kubernetes object updated with its resourceVersion. The holder renews it by
// bumping its sequence; each renewal grants Duration of validity, measured on
// the holder's own monotonic clock from the moment before the renewal was
// sent. Measuring from before the request means a slow or delayed write can
// only shorten the holder's validity, never extend it.
//
// A replacement never trusts the holder's clock or the store's timestamps. It
// takes over in one of two ways. Either the holder released the claim, which
// it does only after it has stopped forwarding (acknowledged fencing), or the
// replacement watched the record stay unchanged for TakeoverWait on its own
// monotonic clock. TakeoverWait is Duration stretched by the worst relative
// clock-rate error between the two nodes, MaxDrift, so by the time it elapses
// the holder's last deadline has passed in real time however fast or slow
// either clock ran. Takeover is a compare-and-swap on the observed version
// that advances the epoch, so a renewal that lands first defeats it.
//
// The guarantee assumes only bounded clock-rate drift, not synchronized wall
// clocks. Wall time enters only through an optional authorization ceiling,
// such as a credential's expiry, which caps a lease's deadline after
// subtracting MaxSkew.
//
// Missing records do not establish that an old holder stopped forwarding. Acquire
// creates an unheld quarantine record and waits TakeoverWait on that record
// before granting authority. Deletion and recreation restart this wait. Record
// incarnations distinguish epochs across deletion; the fencing identity includes
// both incarnation and epoch.
//
// Callers must stop forwarding at the deadline independently of API progress.
// An API outage longer than Duration therefore stops service traffic. Renew
// cannot revive an expired lease; reacquisition follows the takeover protocol.
// Every participant must use the same Duration, MaxDrift and Margin: a
// Galactic Edge cell's are internal/edge/timing.Params.
package claim

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrNotFound is returned by a Store for a key with no record.
	ErrNotFound = errors.New("claim: no record")
	// ErrConflict is returned by a Store when the record changed since the
	// version the caller presented, or already exists on create.
	ErrConflict = errors.New("claim: record changed concurrently")
	// ErrHeld is returned when another instance may still hold the claim.
	ErrHeld = errors.New("claim: held by another instance")
	// ErrLost is returned when the caller's epoch is no longer current: the
	// claim was released or taken over, and the caller must stop forwarding.
	ErrLost = errors.New("claim: lease lost")
	// ErrCeiling is returned when the authorization ceiling leaves no
	// validity to grant.
	ErrCeiling = errors.New("claim: authorization ceiling reached")
)

// Record is a claim as the store holds it.
type Record struct {
	// Key identifies the claimed attachment.
	Key string
	// Holder identifies the service instance holding the claim.
	Holder string
	// Incarnation uniquely identifies this record across deletion/recreation.
	Incarnation string
	// Epoch advances within an incarnation, never on renewal.
	Epoch uint64
	// Sequence advances on every renewal, so a live holder always changes
	// the record within one Duration.
	Sequence uint64
	// RenewStart is the holder's Clock reading taken before it sent the
	// acquisition or renewal that wrote the record. A reader on the same
	// clock, such as an agent on the holder's node, can bound the holder's
	// validity from it without trusting the holder's deadline.
	RenewStart time.Duration
	// Released reports that the holder of Epoch stopped forwarding and gave
	// the claim up.
	Released bool
	// Version is the store's concurrency token for this record.
	Version string
}

// Store persists claim records with linearizable compare-and-swap semantics.
// Versions must not be reused across deletion/recreation. Updates must never
// recreate missing records; production adapters should also enforce object UID
// preconditions. Callers must use incarnation plus epoch as the fencing identity.
type Store interface {
	Get(ctx context.Context, key string) (Record, error)
	// Create stores a new record, failing with ErrConflict if one exists.
	Create(ctx context.Context, r Record) (Record, error)
	// Update replaces the record if its version is still r.Version, failing
	// with ErrConflict otherwise, and returns it with its new version.
	Update(ctx context.Context, r Record) (Record, error)
}

// Clock returns a monotonic instant, such as CLOCK_BOOTTIME, that never
// steps with wall-clock changes.
type Clock func() time.Duration

// Params are the claim timing contract. Every holder and replacement of the
// same claims must use the same values.
type Params struct {
	// Duration is the validity one renewal grants, on the holder's clock.
	Duration time.Duration
	// MaxDrift bounds the relative rate error between any two nodes'
	// monotonic clocks, for example 0.001 for 1000 ppm.
	MaxDrift float64
	// Margin is added to TakeoverWait to absorb scheduling delay between a
	// deadline passing and forwarding actually stopping.
	Margin time.Duration
	// MaxSkew bounds the wall-clock error of any node, used only to convert
	// an authorization ceiling into a local deadline.
	MaxSkew time.Duration
}

// Validate reports whether the parameters can provide the guarantee.
func (p Params) Validate() error {
	switch {
	case p.Duration <= 0:
		return errors.New("claim: duration must be positive")
	case p.MaxDrift < 0 || p.MaxDrift >= 0.5:
		return fmt.Errorf("claim: max drift %v must be in [0, 0.5)", p.MaxDrift)
	case p.Margin < 0 || p.MaxSkew < 0:
		return errors.New("claim: margin and max skew must not be negative")
	}
	return nil
}

func (in *Instance) validate() error {
	if err := in.Params.Validate(); err != nil {
		return err
	}
	if !in.Ceiling.IsZero() && in.Wall == nil {
		return errors.New("claim: a ceiling needs a wall clock")
	}
	return nil
}

// TakeoverWait is how long a replacement must observe an unchanged record
// before taking it over: long enough that the holder's deadline has passed in
// real time even if the holder's clock ran slowest and the replacement's
// fastest.
func (p Params) TakeoverWait() time.Duration {
	return time.Duration(float64(p.Duration)*(1+p.MaxDrift)/(1-p.MaxDrift)) + p.Margin
}

// Lease is an instance's local view of a claim it holds.
type Lease struct {
	Key         string
	Holder      string
	Epoch       uint64
	Incarnation string
	// Deadline is the instant on the holder's clock after which it must not
	// forward under this lease.
	Deadline time.Duration
	version  string
	sequence uint64
}

// Valid reports whether the lease authorizes forwarding at now.
func (l Lease) Valid(now time.Duration) bool { return now < l.Deadline }

// Instance acquires, renews and releases claims for one service instance.
// Methods are serialized per instance. Configuration is immutable after first
// use; Store and Clock must be safe for concurrent use by different instances.
type Instance struct {
	ID     string
	Store  Store
	Clock  Clock
	Params Params
	// Wall returns wall-clock time; it is only needed with a ceiling.
	Wall func() time.Time
	// Ceiling, when non-zero, is the wall-clock instant after which no
	// lease may be valid, such as the expiry of the credential that
	// authorized the claim.
	Ceiling time.Time

	mu       sync.Mutex
	observed map[string]observation
}

type observation struct {
	version string
	at      time.Duration
}

// deadline is the lease deadline for a grant that began at start, capped by
// the ceiling.
func (in *Instance) deadline(start time.Duration) (time.Duration, error) {
	d := start + in.Params.Duration
	if in.Ceiling.IsZero() {
		return d, nil
	}
	remaining := in.Ceiling.Sub(in.Wall()) - in.Params.MaxSkew
	if remaining <= 0 {
		return 0, ErrCeiling
	}
	if c := in.Clock() + remaining; c < d {
		d = c
	}
	return d, nil
}

func (in *Instance) lease(r Record, start time.Duration) (Lease, error) {
	d, err := in.deadline(start)
	if err != nil {
		return Lease{}, err
	}
	return Lease{Key: r.Key, Holder: r.Holder, Epoch: r.Epoch, Incarnation: r.Incarnation,
		Deadline: d, version: r.Version, sequence: r.Sequence}, nil
}

// Acquire takes the claim after an acknowledged release or a quarantine wait.
// A missing record is created unheld and returns ErrHeld on the first call.
// If another instance may hold it, Acquire records what it observed and
// returns ErrHeld; calling it again after Params.TakeoverWait with the record
// unchanged takes the claim over. A record naming this instance's own ID is
// treated like any other holder's, so a restarted instance cannot revive
// authority from state it did not renew.
func (in *Instance) Acquire(ctx context.Context, key string) (Lease, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := in.validate(); err != nil {
		return Lease{}, err
	}
	start := in.Clock()
	if _, err := in.deadline(start); err != nil {
		return Lease{}, err
	}
	r, err := in.Store.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		// Persist a new observation identity before waiting. Merely remembering an
		// absent key can miss an intervening creation/deletion and permit overlap.
		created, createErr := in.Store.Create(ctx, Record{Key: key, Incarnation: rand.Text()})
		delete(in.observed, key)
		if createErr != nil {
			return Lease{}, createErr
		}
		in.waited(created, in.Clock())
		return Lease{}, ErrHeld
	}

	if err != nil {
		return Lease{}, err
	}
	// The observation is timestamped when the read returns, not when it was
	// sent: a renewal can land while the read is in flight, and the wait
	// must not start before the record this instance saw was written.
	if !r.Released && !in.waited(r, in.Clock()) {
		return Lease{}, fmt.Errorf("%w: %q holds epoch %d", ErrHeld, r.Holder, r.Epoch)
	}
	next := Record{Key: key, Holder: in.ID, Epoch: r.Epoch + 1, Incarnation: r.Incarnation,
		RenewStart: start, Version: r.Version}
	updated, err := in.Store.Update(ctx, next)
	if err != nil {
		return Lease{}, err
	}
	delete(in.observed, key)
	return in.lease(updated, start)
}

// waited reports whether this instance has seen r's exact version for at
// least TakeoverWait, recording the observation if it is new.
func (in *Instance) waited(r Record, now time.Duration) bool {
	if in.observed == nil {
		in.observed = map[string]observation{}
	}
	o, ok := in.observed[r.Key]
	if !ok || o.version != r.Version {
		in.observed[r.Key] = observation{version: r.Version, at: now}
		return false
	}
	return now-o.at >= in.Params.TakeoverWait()
}

// Renew extends an unexpired l. An expired lease returns ErrLost and must be
// reacquired. On a store error other than ErrLost the caller keeps its
// existing lease, which stays valid until its deadline; it must not forward
// past that deadline without a successful renewal.
//
// A renewal the store applied but whose reply was lost leaves the caller
// holding a stale version. Renew recovers from that: when the record still
// names the same holder and epoch, it renews again against the current
// version. Validity always runs from the start of this call, so the lost
// renewal grants nothing extra.
func (in *Instance) Renew(ctx context.Context, l Lease) (Lease, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := in.validate(); err != nil {
		return l, err
	}
	start := in.Clock()
	if !l.Valid(start) || l.Holder != in.ID {
		return Lease{}, ErrLost
	}
	if _, err := in.deadline(start); err != nil {
		return Lease{}, err
	}
	next := Record{Key: l.Key, Holder: l.Holder, Epoch: l.Epoch, Incarnation: l.Incarnation,
		Sequence: l.sequence + 1, RenewStart: start, Version: l.version}
	updated, err := in.Store.Update(ctx, next)
	if errors.Is(err, ErrConflict) {
		current, getErr := in.Store.Get(ctx, l.Key)
		if getErr != nil {
			return l, err
		}
		if current.Incarnation != l.Incarnation || current.Epoch != l.Epoch ||
			current.Holder != l.Holder || current.Released {
			return Lease{}, fmt.Errorf("%w: claim %q is at epoch %d held by %q", ErrLost, l.Key, current.Epoch, current.Holder)
		}
		next.Sequence, next.Version = current.Sequence+1, current.Version
		updated, err = in.Store.Update(ctx, next)
	}
	if err != nil {
		return l, err
	}
	return in.lease(updated, start)
}

// Release gives up l. The caller must already have stopped forwarding under
// it: a replacement may take over as soon as the release is stored. Releasing
// a lease whose epoch is no longer current changes nothing.
func (in *Instance) Release(ctx context.Context, l Lease) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	r, err := in.Store.Get(ctx, l.Key)
	if err != nil {
		return err
	}
	if r.Incarnation != l.Incarnation || r.Epoch != l.Epoch || r.Holder != l.Holder {
		return nil
	}
	r.Released = true
	if _, err := in.Store.Update(ctx, r); err != nil {
		return err
	}
	return nil
}
