// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

// Reasons an index entry is being removed.
const (
	RemovingDeleted  = "RouteDeleted"
	RemovingRevoked  = "Revoked"
	RemovingReleased = "Released"
	// RemovingAbandoned is an entry committed for a claim whose status
	// write never landed and that is no longer pending: released, replaced
	// or refused since.
	RemovingAbandoned = "Abandoned"
)

// IndexReconciler removes EdgeRouteIndex entries once their holder is fenced
// and ends a rebuilt index's quiet period.
//
// An entry whose route was deleted, or whose accepted holder was revoked or
// released, is first marked Removing; it still blocks every overlapping claim. It leaves
// when the holder's node confirms the gate closed (the route's closedEpoch),
// or when this leader has waited the takeover interval since it saw the mark
// and a final read from the API server still finds the route gone or
// revoked or released at that epoch. galactic-edge extends a gate only after
// reading the route accepted and unreleased, and only from a renewal it read
// before that, so the gate closes within the lease duration of the mark.
type IndexReconciler struct {
	Client    client.Client
	APIReader client.Reader
	Params    claim.Params
	Clock     claim.Clock

	mu sync.Mutex
	// marks holds when this leader first saw each pending removal and each
	// rebuilt index.
	marks map[string]time.Duration
}

// Reconcile implements reconcile.Reconciler for EdgeRouteIndexes.
func (r *IndexReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var idx galacticv1alpha1.EdgeRouteIndex
	if err := r.APIReader.Get(ctx, req.NamespacedName, &idx); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	wait := r.Params.TakeoverWait()
	var after time.Duration
	later := func(d time.Duration) {
		if after == 0 || d < after {
			after = d
		}
	}
	changed := false
	if idx.Spec.Rebuilt {
		if elapsed := r.mark("rebuilt/" + string(idx.UID)); elapsed >= wait {
			idx.Spec.Rebuilt = false
			changed = true
		} else {
			later(wait - elapsed)
		}
	}

	kept := idx.Spec.Routes[:0:0]
	for _, e := range idx.Spec.Routes {
		reason, closed, err := r.removal(ctx, e)
		if err != nil {
			return ctrl.Result{}, err
		}
		key := "entry/" + string(idx.UID) + "/" + e.RouteUID + "/" + strconv.FormatInt(e.Epoch, 10)
		switch {
		case reason == "":
			kept = append(kept, e)
			continue
		case e.Removing == "":
			// Marked first, so a new leader also waits from a mark it
			// can see.
			e.Removing = reason
			changed = true
			kept = append(kept, e)
			later(wait)
			continue
		case closed:
			r.unmark(key)
			changed = true
			continue
		}
		elapsed := r.mark(key)
		if elapsed < wait {
			kept = append(kept, e)
			later(wait - elapsed)
			continue
		}
		// The final read: a route recreated or re-accepted since keeps
		// its entry.
		if again, _, err := r.removal(ctx, e); err != nil || again == "" {
			if err != nil {
				return ctrl.Result{}, err
			}
			kept = append(kept, e)
			continue
		}
		r.unmark(key)
		changed = true
	}
	if !changed {
		return ctrl.Result{RequeueAfter: after}, nil
	}
	idx.Spec.Routes = kept
	if err := r.Client.Update(ctx, &idx); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update route index %s: %w", req.NamespacedName, err)
	}
	if after == 0 {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: after}, nil
}

// removal reports why e's entry should leave the index, or empty when its
// holder is still accepted, and whether the holder's node confirmed its
// gate closed at e's epoch.
func (r *IndexReconciler) removal(ctx context.Context, e galacticv1alpha1.EdgeRouteIndexEntry) (string, bool, error) {
	ns, name, _ := strings.Cut(e.Route, "/")
	var rt galacticv1alpha1.EdgeRoute
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &rt); {
	case apierrors.IsNotFound(err):
		return RemovingDeleted, false, nil
	case err != nil:
		return "", false, err
	case string(rt.UID) != e.RouteUID:
		return RemovingDeleted, false, nil
	}
	acc := rt.Status.Accepted
	if acc == nil || acc.Epoch != e.Epoch {
		// Committed here and not yet in the route's status. It stays while
		// its claim is still pending, so the status write can land, and
		// while the route's earlier accepted holder may still forward,
		// since the entry is what keeps overlapping claims out.
		c := rt.Spec.Claim
		pending := c != nil && c.Epoch == e.Epoch && !c.Released
		live := acc != nil && meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) &&
			rt.Status.ClosedEpoch < acc.Epoch
		if pending || live {
			return "", false, nil
		}
		return RemovingAbandoned, false, nil
	}
	closed := rt.Status.ClosedEpoch >= e.Epoch
	if !meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		return RemovingRevoked, closed, nil
	}
	if c := rt.Spec.Claim; c != nil && c.Epoch == e.Epoch && c.Released {
		return RemovingReleased, closed, nil
	}
	return "", false, nil
}

// mark returns how long ago this leader first saw key, recording now if it
// had not.
func (r *IndexReconciler) mark(key string) time.Duration {
	now := r.Clock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.marks == nil {
		r.marks = map[string]time.Duration{}
	}
	at, ok := r.marks[key]
	if !ok {
		r.marks[key] = now
		return 0
	}
	return now - at
}

func (r *IndexReconciler) unmark(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.marks, key)
}
