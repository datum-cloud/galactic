// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lease holds an EdgeInstance's liveness lease, the
// coordination.k8s.io/v1 Lease named after the instance that the Galactic
// Edge contract keys every forwarding claim to.
//
// A process acquires the lease once its previous holder released it, or
// after it has seen the Lease unchanged for the takeover wait on its own
// CLOCK_BOOTTIME. It renews the lease every renewal interval; each renewal
// grants the lease duration measured from the clock reading taken before the
// write was sent, and that reading is written to the Lease so the node agent
// on the same node can time the lease without trusting this process. Every
// write is a compare-and-swap on the Lease's resourceVersion.
package lease

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

var (
	// ErrWaiting is returned by Acquire while another holder may still hold
	// the lease. Call Acquire again; it succeeds once the takeover wait has
	// passed with the Lease unchanged.
	ErrWaiting = errors.New("lease: another holder may still hold it")
	// ErrLost is returned when this process no longer holds the lease. It
	// must stop forwarding and acquire again.
	ErrLost = errors.New("lease: lost")
	// ErrNameTaken is returned when the instance's Lease name is held by a
	// Lease that is not bound to the instance. Retrying cannot succeed
	// until that Lease is deleted.
	ErrNameTaken = errors.New("lease: name held by a Lease bound to something else")
)

// Params are the contract's lease timings. Every participant in a cell uses
// the same values.
type Params struct {
	// Duration is the validity one renewal grants.
	Duration time.Duration
	// Renew is how often the holder renews.
	Renew time.Duration
	// MaxDrift bounds the relative rate error of any two nodes' clocks.
	MaxDrift float64
	// Margin absorbs the delay between a deadline and forwarding stopping.
	Margin time.Duration
}

// Contract is the timing the Galactic Edge contract fixes.
var Contract = Params{
	Duration: 15 * time.Second, Renew: 5 * time.Second, MaxDrift: 0.001, Margin: 500 * time.Millisecond,
}

// TakeoverWait is how long a Lease must stay unchanged before a new holder
// may take it over: Duration × (1 + MaxDrift) / (1 − MaxDrift) + Margin.
func (p Params) TakeoverWait() time.Duration {
	return time.Duration(float64(p.Duration)*(1+p.MaxDrift)/(1-p.MaxDrift)) + p.Margin
}

// Clock returns a monotonic instant that keeps counting across suspend.
type Clock func() time.Duration

// BootTime reads CLOCK_BOOTTIME, the clock the contract times leases on.
func BootTime() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		panic(fmt.Sprintf("read CLOCK_BOOTTIME: %v", err))
	}
	return time.Duration(ts.Nano())
}

// Lease is this process's hold on the instance lease at one epoch.
type Lease struct {
	// Name is the Lease's and the instance's name.
	Name string
	// Incarnation is the Lease's metadata.uid.
	Incarnation string
	// Epoch is the Lease's spec.leaseTransitions while this process holds it.
	Epoch int32
	// RenewStart is the clock reading taken before the last write was sent.
	RenewStart time.Duration
	// Deadline is when this process must stop forwarding unless it renews.
	Deadline time.Duration

	sequence uint64
	stored   *coordinationv1.Lease
}

// Valid reports whether the lease allows forwarding at now.
func (l Lease) Valid(now time.Duration) bool { return now < l.Deadline }

// Holder acquires, renews and releases one instance's lease. It is not safe
// for concurrent use.
type Holder struct {
	// Client must read from the API server, never a cache.
	Client client.Client
	// Instance is the EdgeInstance as stored, with its UID.
	Instance *galacticv1alpha1.EdgeInstance
	// ID identifies this process. It must be new for every process start,
	// so a restarted process never continues its predecessor's lease.
	ID     string
	Clock  Clock
	Params Params

	observedVersion string
	observedAt      time.Duration
}

// NewID returns a fresh holder ID.
func NewID() string { return rand.Text() }

// Acquire takes the instance's lease. A missing Lease is created unheld and
// counts as held until the takeover wait has passed, since a deleted Lease
// does not prove its holder stopped. A Lease its holder released is taken at
// once.
func (h *Holder) Acquire(ctx context.Context) (Lease, error) {
	start := h.Clock()
	cur, err := h.get(ctx)
	if apierrors.IsNotFound(err) {
		return Lease{}, h.createUnheld(ctx)
	}
	if err != nil {
		return Lease{}, err
	}
	released := cur.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] == "true"
	if !released && !h.waited(cur.ResourceVersion, h.Clock()) {
		return Lease{}, fmt.Errorf("%w: held by %q at epoch %d", ErrWaiting,
			ptr.Deref(cur.Spec.HolderIdentity, ""), ptr.Deref(cur.Spec.LeaseTransitions, 0))
	}
	epoch := ptr.Deref(cur.Spec.LeaseTransitions, 0)
	if epoch == math.MaxInt32 {
		return Lease{}, errors.New("lease: epoch exhausted")
	}
	next := cur.DeepCopy()
	h.stamp(next, start, 0, false)
	next.Spec.HolderIdentity = ptr.To(h.ID)
	next.Spec.LeaseTransitions = ptr.To(epoch + 1)
	if err := h.Client.Update(ctx, next); err != nil {
		if apierrors.IsConflict(err) {
			return Lease{}, fmt.Errorf("%w: the Lease changed while taking it over", ErrWaiting)
		}
		return Lease{}, err
	}
	h.observedVersion = ""
	return h.lease(next, start, 0), nil
}

// Renew extends l. It returns ErrLost once l's deadline has passed or
// another writer took the lease; on any other error l stays valid until its
// deadline and the caller retries.
func (h *Holder) Renew(ctx context.Context, l Lease) (Lease, error) {
	start := h.Clock()
	if !l.Valid(start) {
		return Lease{}, fmt.Errorf("%w: deadline passed before renewal", ErrLost)
	}
	next := l.stored.DeepCopy()
	h.stamp(next, start, l.sequence+1, false)
	err := h.Client.Update(ctx, next)
	if apierrors.IsConflict(err) {
		// A renewal whose reply was lost leaves a newer version behind:
		// renew again from it while it still names this holder and epoch.
		cur, getErr := h.get(ctx)
		if getErr != nil {
			return l, err
		}
		if !h.holds(cur, l) {
			return Lease{}, fmt.Errorf("%w: now held by %q at epoch %d", ErrLost,
				ptr.Deref(cur.Spec.HolderIdentity, ""), ptr.Deref(cur.Spec.LeaseTransitions, 0))
		}
		seq, _ := strconv.ParseUint(cur.Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation], 10, 64)
		next = cur.DeepCopy()
		h.stamp(next, start, seq+1, false)
		err = h.Client.Update(ctx, next)
	}
	switch {
	case apierrors.IsNotFound(err):
		return Lease{}, fmt.Errorf("%w: the Lease was deleted", ErrLost)
	case apierrors.IsInvalid(err), apierrors.IsForbidden(err):
		// An admission policy refuses the write once the Lease no
		// longer belongs to this pod.
		return Lease{}, fmt.Errorf("%w: renewal refused: %w", ErrLost, err)
	case err != nil:
		return l, err
	}
	seq, _ := strconv.ParseUint(next.Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation], 10, 64)
	return h.lease(next, start, seq), nil
}

// Release marks l released. The caller must already have stopped
// forwarding: another process may take the lease as soon as this is stored.
func (h *Holder) Release(ctx context.Context, l Lease) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur, err := h.get(ctx)
		if err != nil {
			return err
		}
		if !h.holds(cur, l) {
			return nil
		}
		seq, _ := strconv.ParseUint(cur.Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation], 10, 64)
		start, _ := strconv.ParseInt(cur.Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation], 10, 64)
		next := cur.DeepCopy()
		h.stamp(next, time.Duration(start), seq, true)
		return h.Client.Update(ctx, next)
	})
}

// holds reports whether cur is still l: same incarnation, epoch and holder,
// not released.
func (h *Holder) holds(cur *coordinationv1.Lease, l Lease) bool {
	return string(cur.UID) == l.Incarnation && ptr.Deref(cur.Spec.LeaseTransitions, 0) == l.Epoch &&
		ptr.Deref(cur.Spec.HolderIdentity, "") == h.ID &&
		cur.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] != "true"
}

// get reads the Lease and checks it is bound to the instance: owned by it,
// labeled with its provider and annotated with its pod.
func (h *Holder) get(ctx context.Context) (*coordinationv1.Lease, error) {
	var l coordinationv1.Lease
	key := client.ObjectKey{Namespace: h.Instance.Namespace, Name: h.Instance.Name}
	if err := h.Client.Get(ctx, key, &l); err != nil {
		return nil, err
	}
	owned := slices.ContainsFunc(l.OwnerReferences, func(o metav1.OwnerReference) bool {
		return o.UID == h.Instance.UID
	})
	if !owned || l.Labels[galacticv1alpha1.EdgeLeaseProviderLabel] != h.Instance.Spec.ProviderRef.Name ||
		l.Annotations[galacticv1alpha1.EdgeLeasePodUIDAnnotation] != h.Instance.Spec.PodUID {
		if l.Annotations[galacticv1alpha1.EdgeLeasePodUIDAnnotation] == h.Instance.Spec.PodUID && !owned {
			// An earlier instance of this pod's: the garbage collector
			// deletes it with its owner.
			return nil, fmt.Errorf("%w: the Lease belongs to an earlier instance and awaits deletion", ErrWaiting)
		}
		return nil, fmt.Errorf("%w: Lease %s/%s", ErrNameTaken, l.Namespace, l.Name)
	}
	for _, a := range []string{galacticv1alpha1.EdgeLeaseRenewStartAnnotation,
		galacticv1alpha1.EdgeLeaseSequenceAnnotation, galacticv1alpha1.EdgeLeaseReleasedAnnotation} {
		if _, ok := l.Annotations[a]; !ok {
			return nil, fmt.Errorf("lease %s/%s: missing annotation %s", l.Namespace, l.Name, a)
		}
	}
	return &l, nil
}

// createUnheld creates the instance's first Lease with no holder at epoch 0,
// and starts the takeover wait on it.
func (h *Holder) createUnheld(ctx context.Context) error {
	l := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: h.Instance.Namespace, Name: h.Instance.Name,
			Labels:      map[string]string{galacticv1alpha1.EdgeLeaseProviderLabel: h.Instance.Spec.ProviderRef.Name},
			Annotations: map[string]string{galacticv1alpha1.EdgeLeasePodUIDAnnotation: h.Instance.Spec.PodUID},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: galacticv1alpha1.GroupVersion.String(), Kind: "EdgeInstance",
				Name: h.Instance.Name, UID: h.Instance.UID, Controller: ptr.To(true),
			}},
		},
		Spec: coordinationv1.LeaseSpec{LeaseTransitions: ptr.To[int32](0)},
	}
	h.stamp(l, 0, 0, false)
	l.Spec.HolderIdentity = nil
	err := h.Client.Create(ctx, l)
	switch {
	case apierrors.IsAlreadyExists(err):
		return fmt.Errorf("%w: the Lease was created concurrently", ErrWaiting)
	case err != nil:
		return err
	}
	h.waited(l.ResourceVersion, h.Clock())
	return fmt.Errorf("%w: created the Lease unheld", ErrWaiting)
}

// waited reports whether the Lease has stayed at version for the takeover
// wait, starting the wait if version is new. The observation is stamped when
// the read returned, so a write that landed while it was in flight cannot
// start the wait early.
func (h *Holder) waited(version string, now time.Duration) bool {
	if h.observedVersion != version {
		h.observedVersion, h.observedAt = version, now
		return false
	}
	return now-h.observedAt >= h.Params.TakeoverWait()
}

// stamp writes the protocol annotations and the display-only spec fields.
func (h *Holder) stamp(l *coordinationv1.Lease, start time.Duration, seq uint64, released bool) {
	if l.Annotations == nil {
		l.Annotations = map[string]string{}
	}
	l.Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation] = strconv.FormatInt(int64(start), 10)
	l.Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation] = strconv.FormatUint(seq, 10)
	l.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] = strconv.FormatBool(released)
	l.Spec.LeaseDurationSeconds = ptr.To(int32(math.Ceil(h.Params.Duration.Seconds())))
	l.Spec.RenewTime = ptr.To(metav1.NewMicroTime(time.Now()))
}

func (h *Holder) lease(stored *coordinationv1.Lease, start time.Duration, seq uint64) Lease {
	return Lease{
		Name: stored.Name, Incarnation: string(stored.UID), Epoch: ptr.Deref(stored.Spec.LeaseTransitions, 0),
		RenewStart: start, Deadline: start + h.Params.Duration, sequence: seq, stored: stored,
	}
}
