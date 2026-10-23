// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

// InstanceReaper deletes an EdgeInstance whose pod no longer exists, or
// exists with another UID, once this leader has seen it and its Lease
// unchanged for the takeover interval: no process can still renew it, so no
// gate it held can still be open. Deleting the instance deletes its Lease,
// which the instance owns.
type InstanceReaper struct {
	Client    client.Client
	APIReader client.Reader
	Params    claim.Params
	Clock     claim.Clock

	mu       sync.Mutex
	observed map[string]observation
}

// Reconcile implements reconcile.Reconciler for EdgeInstances.
func (r *InstanceReaper) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var inst galacticv1alpha1.EdgeInstance
	if err := r.APIReader.Get(ctx, req.NamespacedName, &inst); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	key := req.String()
	var pod corev1.Pod
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: inst.Namespace, Name: inst.Spec.PodName}, &pod)
	switch {
	case err == nil && string(pod.UID) == inst.Spec.PodUID:
		r.forget(key)
		return ctrl.Result{}, nil
	case err != nil && !apierrors.IsNotFound(err):
		return ctrl.Result{}, err
	}
	// Any write to the Lease, a renewal above all, restarts the wait.
	leaseVersion := "none"
	var l coordinationv1.Lease
	switch err := r.APIReader.Get(ctx, req.NamespacedName, &l); {
	case err == nil:
		leaseVersion = string(l.UID) + "/" + l.ResourceVersion
	case !apierrors.IsNotFound(err):
		return ctrl.Result{}, err
	}
	version := string(inst.UID) + "/" + inst.ResourceVersion + " " + leaseVersion
	now := r.Clock()
	wait := r.Params.TakeoverWait()
	r.mu.Lock()
	if r.observed == nil {
		r.observed = map[string]observation{}
	}
	o, ok := r.observed[key]
	if !ok || o.version != version {
		r.observed[key] = observation{version: version, at: now}
		r.mu.Unlock()
		return ctrl.Result{RequeueAfter: wait}, nil
	}
	r.mu.Unlock()
	if elapsed := now - o.at; elapsed < wait {
		return ctrl.Result{RequeueAfter: wait - elapsed + time.Millisecond}, nil
	}
	uid, rv := inst.UID, inst.ResourceVersion
	err = r.Client.Delete(ctx, &inst, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	switch {
	case apierrors.IsConflict(err):
		return ctrl.Result{Requeue: true}, nil
	case err != nil && !apierrors.IsNotFound(err):
		return ctrl.Result{}, err
	}
	r.forget(key)
	return ctrl.Result{}, nil
}

func (r *InstanceReaper) forget(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.observed, key)
}
