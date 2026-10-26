// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"context"
	"errors"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/fabric/errcode"
)

const (
	// RecoveryHold is how long the authority admits nothing after it starts,
	// acquires the election, or regains certainty about it. It exceeds the
	// 120 s request lifetime plus the 2 s skew and scheduling allowance, and
	// every bucket's burst/rate, so no prior-epoch work or token debt
	// survives it.
	RecoveryHold = 125 * time.Second
	// LeaseReadTimeout bounds each uncached election Lease read.
	LeaseReadTimeout = time.Second
)

// Epoch identifies one term of the election: the Lease object's UID and
// the complete holder identity. Recreating the Lease or acquiring it again
// with a new process identity yields a new epoch.
type Epoch struct {
	UID    string
	Holder string
}

// String renders the epoch as "<uid>/<holder>", the form a probe permit
// carries.
func (e Epoch) String() string { return e.UID + "/" + e.Holder }

// ReadEpoch reads the election Lease uncached and returns its epoch when it
// has a holder whose term has not expired at now. The read is bounded by
// LeaseReadTimeout; every failure is OwnershipLost.
func ReadEpoch(ctx context.Context, r client.Reader, namespace, name string, now time.Time) (Epoch, error) {
	ctx, cancel := context.WithTimeout(ctx, LeaseReadTimeout)
	defer cancel()
	var lease coordinationv1.Lease
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &lease); err != nil {
		return Epoch{}, errcode.Status(errcode.OwnershipLost, "the election lease could not be read")
	}
	s := lease.Spec
	if s.HolderIdentity == nil || *s.HolderIdentity == "" || s.RenewTime == nil || s.LeaseDurationSeconds == nil {
		return Epoch{}, errcode.Status(errcode.OwnershipLost, "the election lease has no holder")
	}
	if !now.Before(s.RenewTime.Add(time.Duration(*s.LeaseDurationSeconds) * time.Second)) {
		return Epoch{}, errcode.Status(errcode.OwnershipLost, "the election lease has expired")
	}
	return Epoch{UID: string(lease.UID), Holder: *s.HolderIdentity}, nil
}

// Authority decides whether this gateway may admit and dispatch aggregate
// work. Every Check reads the election Lease uncached and requires this
// process's own unexpired holder identity. The first valid read of a new
// epoch, the first after start, and the first after any failed read begin a
// RecoveryHold, during which Check refuses with LimiterUnavailable and the
// remaining delay; the first valid read after the hold empties the buckets
// and admits from that instant. A failed read, another holder or an expired
// term refuses with OwnershipLost and cancels the context of the epoch's
// work.
type Authority struct {
	// Reader must read uncached.
	Reader    client.Reader
	Namespace string
	Name      string
	// Identity is this process's election holder identity, unique to it.
	Identity string
	// Buckets are emptied when a hold ends.
	Buckets *Buckets
	// Hold overrides RecoveryHold; tests only.
	Hold time.Duration
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time

	mu       sync.Mutex
	epoch    Epoch
	active   bool
	until    time.Time
	epochCtx context.Context
	cancel   context.CancelFunc
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Check confirms ownership and returns the current epoch and a context that
// ends when ownership is lost. Work admitted under the epoch should run
// within that context. The Lease read is not cut short by ctx, only by
// LeaseReadTimeout, so a caller that gives up mid-read is refused with
// Cancelled or DeadlineExceeded and leaves the authority's state alone.
func (a *Authority) Check(ctx context.Context) (Epoch, context.Context, error) {
	epoch, err := ReadEpoch(context.WithoutCancel(ctx), a.Reader, a.Namespace, a.Name, a.now())
	if cerr := ctx.Err(); cerr != nil {
		if errors.Is(cerr, context.DeadlineExceeded) {
			return Epoch{}, nil, errcode.Status(errcode.DeadlineExceeded, "the caller's deadline passed")
		}
		return Epoch{}, nil, errcode.Status(errcode.Cancelled, "the caller cancelled")
	}
	now := a.now()
	if err == nil && epoch.Holder != a.Identity {
		err = errcode.Status(errcode.OwnershipLost, "this gateway does not hold the election lease")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.loseLocked()
		return Epoch{}, nil, err
	}
	if epoch != a.epoch || a.epochCtx == nil {
		a.loseLocked()
		a.epoch, a.until = epoch, now.Add(a.hold())
		a.epochCtx, a.cancel = context.WithCancel(context.Background())
	}
	if !a.active {
		if now.Before(a.until) {
			return Epoch{}, nil, errcode.Retry(errcode.LimiterUnavailable, "the cell's limiter is in its recovery hold",
				string(ScopeCell), a.until.Sub(now))
		}
		a.Buckets.Reset(now)
		a.active = true
	}
	return a.epoch, a.epochCtx, nil
}

// WatchInterval is how often Watch confirms ownership.
const WatchInterval = time.Second

// Watch calls Check every interval until ctx ends, so a lost or unreadable
// Lease cancels the epoch's work within an interval even when no admission
// or dispatch would check it, and the recovery hold starts when this
// process starts or acquires the election rather than at its first
// request.
func (a *Authority) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		_, _, _ = a.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Authority) hold() time.Duration {
	if a.Hold > 0 {
		return a.Hold
	}
	return RecoveryHold
}

// loseLocked ends the current epoch: its work is cancelled and the next
// valid read starts a new hold.
func (a *Authority) loseLocked() {
	if a.cancel != nil {
		a.cancel()
	}
	a.epoch, a.active, a.epochCtx, a.cancel = Epoch{}, false, nil, nil
}
