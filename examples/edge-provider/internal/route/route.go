// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package route claims EdgeRoutes, one per prefix this provider serves in a
// VPC. A claim names the attachment that forwards the prefix and the
// instance lease, at one epoch, that keeps it forwarding. It grants nothing
// until galactic-controller accepts it into the route's status.
package route

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Name is the EdgeRoute name for prefix in the VPC with vpcUID. Every
// instance of a provider derives the same name, so they contend for a prefix
// through one object: "er-" and the first 16 bytes, in hex, of the SHA-256
// of the VPC UID, a slash and the masked prefix.
func Name(vpcUID string, prefix netip.Prefix) string {
	sum := sha256.Sum256([]byte(vpcUID + "/" + prefix.Masked().String()))
	return "er-" + hex.EncodeToString(sum[:16])
}

// Holder is the claim this instance makes.
type Holder struct {
	Attachment    string
	PodUID        string
	Instance      string
	InstanceEpoch int64
}

// Next returns the claim holder h should write over cur, and whether it
// differs from cur. A claim already naming h unreleased, at an epoch that can
// still forward, is kept; anything else moves to the next epoch, which is how
// a holder takes over a route, re-claims it after its instance epoch changed,
// or replaces a claim whose gate closed. While core holds h as the accepted
// holder, another instance's claim is left alone: h keeps forwarding, and
// core accepts the other claim only once h is fenced, so taking it back
// would only churn epochs.
func Next(cur *galacticv1alpha1.EdgeRouteClaim, status galacticv1alpha1.EdgeRouteStatus, h Holder,
) (galacticv1alpha1.EdgeRouteClaim, bool) {
	next := galacticv1alpha1.EdgeRouteClaim{Attachment: h.Attachment, HolderPodUID: h.PodUID,
		HolderInstance: h.Instance, InstanceEpoch: h.InstanceEpoch, Epoch: 1}
	if cur == nil {
		return next, true
	}
	if a := status.Accepted; a != nil && a.Attachment == h.Attachment && a.Instance == h.Instance &&
		a.InstanceEpoch == h.InstanceEpoch && !ended(status, a.Epoch) &&
		meta.IsStatusConditionTrue(status.Conditions, galacticv1alpha1.EdgeRouteAccepted) &&
		cur.HolderInstance != h.Instance {
		return *cur, false
	}
	next.Epoch = cur.Epoch
	if *cur == next && !ended(status, cur.Epoch) {
		return next, false
	}
	next.Epoch = cur.Epoch + 1
	return next, true
}

// ended reports whether a claim at epoch can never forward again: its node
// confirmed its gate closed, or core revoked it.
func ended(s galacticv1alpha1.EdgeRouteStatus, epoch int64) bool {
	if s.ClosedEpoch >= epoch {
		return true
	}
	return s.Accepted != nil && s.Accepted.Epoch == epoch &&
		meta.IsStatusConditionFalse(s.Conditions, galacticv1alpha1.EdgeRouteAccepted)
}

// Claim makes h the claimed holder of prefix's route in namespace, creating
// the route if it does not exist. A concurrent change returns an apierrors
// Conflict or AlreadyExists, and the caller tries again.
func Claim(ctx context.Context, c client.Client, namespace, provider, vpcUID string, prefix netip.Prefix,
	h Holder) (*galacticv1alpha1.EdgeRoute, error) {
	var r galacticv1alpha1.EdgeRoute
	err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: Name(vpcUID, prefix)}, &r)
	if apierrors.IsNotFound(err) {
		claim, _ := Next(nil, galacticv1alpha1.EdgeRouteStatus{}, h)
		r = galacticv1alpha1.EdgeRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: Name(vpcUID, prefix)},
			Spec: galacticv1alpha1.EdgeRouteSpec{
				ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
				VPCUID:      vpcUID, Prefix: prefix.Masked().String(), Incarnation: rand.Text(), Claim: &claim,
			},
		}
		return &r, c.Create(ctx, &r)
	}
	if err != nil {
		return nil, err
	}
	if r.Spec.ProviderRef.Name != provider || r.Spec.VPCUID != vpcUID || r.Spec.Prefix != prefix.Masked().String() {
		return nil, fmt.Errorf("route %s/%s is for %s %s %s, not this provider's prefix", namespace, r.Name,
			r.Spec.ProviderRef.Name, r.Spec.VPCUID, r.Spec.Prefix)
	}
	claim, changed := Next(r.Spec.Claim, r.Status, h)
	if !changed {
		return &r, nil
	}
	r.Spec.Claim = &claim
	return &r, c.Update(ctx, &r)
}

// Release marks h's claim on the route released. The caller must already
// have stopped forwarding the prefix. A route claimed by anyone else is left
// alone.
func Release(ctx context.Context, c client.Client, namespace, vpcUID string, prefix netip.Prefix, h Holder) error {
	// Core writes the route's status concurrently, so a conflict is read
	// again rather than given up on: a lost release makes a successor wait
	// out the takeover interval.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var r galacticv1alpha1.EdgeRoute
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: Name(vpcUID, prefix)}, &r); err != nil {
			return client.IgnoreNotFound(err)
		}
		cl := r.Spec.Claim
		if cl == nil || cl.Released || cl.HolderPodUID != h.PodUID || cl.HolderInstance != h.Instance ||
			cl.InstanceEpoch != h.InstanceEpoch {
			return nil
		}
		cl.Released = true
		return c.Update(ctx, &r)
	})
}

// Accepted reports whether core accepted h's current claim on r and has not
// revoked it.
func Accepted(r *galacticv1alpha1.EdgeRoute, h Holder) bool {
	a, cl := r.Status.Accepted, r.Spec.Claim
	return a != nil && cl != nil && a.Epoch == cl.Epoch && a.Attachment == h.Attachment &&
		a.Instance == h.Instance && a.InstanceEpoch == h.InstanceEpoch &&
		meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
}
