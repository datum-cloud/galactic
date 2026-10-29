// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/reconcile"
)

func (r *BGPRouterReconciler) prepareCoordinatedAdvertisements(
	ctx context.Context, router *api.BGPRouter,
) (map[string]bool, error) {
	if router.Spec.TargetRef.Name != r.NodeName {
		return nil, nil
	}
	advertisements := &api.BGPAdvertisementList{}
	if err := r.List(ctx, advertisements, client.InNamespace(router.Namespace),
		client.MatchingFields{BGPAdvByRouterName: router.Name}); err != nil {
		return nil, err
	}
	fenced := make(map[string]bool)
	for i := range advertisements.Items {
		advertisement := &advertisements.Items[i]
		if advertisement.Labels[serviceAddressLabel] == "" {
			continue
		}
		if err := r.prepareCoordinatedAdvertisement(ctx, router, advertisement); err != nil {
			fenced[advertisement.Name] = true
			log.FromContext(ctx).Error(err, "fence coordinated advertisement after preparation failure",
				"advertisement", client.ObjectKeyFromObject(advertisement))
		}
	}
	return fenced, nil
}

func (r *BGPRouterReconciler) prepareCoordinatedAdvertisement(
	ctx context.Context, router *api.BGPRouter, candidate *api.BGPAdvertisement,
) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	advertisement := &api.BGPAdvertisement{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(candidate), advertisement); err != nil {
		return err
	}
	if advertisement.UID != candidate.UID || advertisement.Spec.RouterRef.Name != router.Name ||
		advertisement.Labels[serviceAddressLabel] == "" {
		return errors.New("advertisement identity changed during preparation")
	}
	guarded := controllerutil.ContainsFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
	if advertisement.DeletionTimestamp.IsZero() {
		if guarded {
			return nil
		}
		base := advertisement.DeepCopy()
		controllerutil.AddFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
		return r.Patch(ctx, advertisement, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	}
	if !guarded {
		return nil
	}
	status, err := r.RuntimeManager.Status(ctx, client.ObjectKeyFromObject(router))
	if err != nil {
		return err
	}
	for _, owner := range status.Advertisements {
		if owner.Name == advertisement.Name {
			return nil
		}
	}
	base := advertisement.DeepCopy()
	controllerutil.RemoveFinalizer(advertisement, reconcile.CoordinatedAdvertisementFinalizer)
	return r.Patch(ctx, advertisement, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
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
