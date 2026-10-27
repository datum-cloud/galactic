// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

// CoordinatedAdvertisementFinalizer holds advertisement identity until its runtime owner is withdrawn.
const CoordinatedAdvertisementFinalizer = "galactic.datum.net/address-route-withdrawal"
const serviceAddressLabel = "galactic.datum.net/service-address"
const serviceAddressNamespaceLabel = "galactic.datum.net/service-address-namespace"
const serviceAddressUIDLabel = "galactic.datum.net/service-address-uid"

// SetAPIReader selects authoritative reads for terminal allocation and advertisement authority.
func (r *Reconciler) SetAPIReader(reader client.Reader) { r.apiReader = reader }

func (r *Reconciler) coordinatedAdvertisement(
	ctx context.Context,
	advertisement *api.BGPAdvertisement,
) (*api.BGPAdvertisement, bool, error) {
	if advertisement.Labels[serviceAddressLabel] == "" {
		return advertisement, true, nil
	}
	reader := r.apiReader
	if reader == nil {
		reader = r.client
	}
	current := &api.BGPAdvertisement{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(advertisement), current); err != nil {
		return nil, false, client.IgnoreNotFound(err)
	}
	if current.UID != advertisement.UID || current.Spec.RouterRef != advertisement.Spec.RouterRef ||
		!current.DeletionTimestamp.IsZero() ||
		!slices.Contains(current.Finalizers, CoordinatedAdvertisementFinalizer) {
		return current, false, nil
	}
	namespace := current.Labels[serviceAddressNamespaceLabel]
	if namespace == "" {
		namespace = current.Namespace
	}
	name := current.Annotations[serviceAddressLabel]
	if name == "" {
		name = current.Labels[serviceAddressLabel]
	}
	anchor := &api.NetworkServiceAddress{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, anchor); err != nil {
		return nil, false, client.IgnoreNotFound(fmt.Errorf("read advertisement allocation: %w", err))
	}
	allowed := current.Labels[serviceAddressUIDLabel] != "" &&
		current.Labels[serviceAddressUIDLabel] == string(anchor.UID) &&
		!anchor.Spec.Retired &&
		anchor.DeletionTimestamp.IsZero()
	return current, allowed, nil
}
