// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/reconcile"
)

func (r *BGPRouterReconciler) prepareCoordinatedAdvertisements(ctx context.Context, router *api.BGPRouter) error {
	if router.Spec.TargetRef.Name != r.NodeName {
		return nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	advertisements := &api.BGPAdvertisementList{}
	if err := reader.List(ctx, advertisements, client.InNamespace(router.Namespace)); err != nil {
		return err
	}
	for i := range advertisements.Items {
		advertisement := &advertisements.Items[i]
		if advertisement.Spec.RouterRef.Name != router.Name || advertisement.Labels[serviceAddressLabel] == "" {
			continue
		}
		guarded := controllerutil.ContainsFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
		if advertisement.DeletionTimestamp.IsZero() {
			if guarded {
				continue
			}
			base := advertisement.DeepCopy()
			controllerutil.AddFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
			patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
			if err := r.Patch(ctx, advertisement, patch); err != nil {
				return err
			}
			continue
		}
		if !guarded {
			continue
		}
		status, err := r.RuntimeManager.Status(ctx, client.ObjectKeyFromObject(router))
		if err != nil {
			return err
		}
		installed := false
		for _, owner := range status.Advertisements {
			if owner.Name == advertisement.Name {
				installed = true
				break
			}
		}
		if installed {
			continue
		}
		base := advertisement.DeepCopy()
		controllerutil.RemoveFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
		patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
		if err := r.Patch(ctx, advertisement, patch); err != nil {
			return err
		}
	}
	return nil
}

func (r *BGPRouterReconciler) releaseStoppedRouterAdvertisements(ctx context.Context, key types.NamespacedName) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	advertisements := &api.BGPAdvertisementList{}
	if err := reader.List(ctx, advertisements, client.InNamespace(key.Namespace)); err != nil {
		return err
	}
	for i := range advertisements.Items {
		advertisement := &advertisements.Items[i]
		if advertisement.Spec.RouterRef.Name != key.Name || advertisement.Labels[serviceAddressLabel] == "" ||
			advertisement.Labels[gatewayNodeLabel] != gatewayNodeLabelValue(r.NodeName) {
			continue
		}
		if err := r.Delete(ctx, advertisement, client.Preconditions{UID: &advertisement.UID}); client.IgnoreNotFound(
			err,
		) != nil {
			return err
		}
		current := &api.BGPAdvertisement{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(advertisement), current); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		if current.UID != advertisement.UID {
			continue
		}
		base := current.DeepCopy()
		controllerutil.RemoveFinalizer(current, reconcile.CoordinatedAdvertisementFinalizer)
		if err := r.Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
	}
	return nil
}
