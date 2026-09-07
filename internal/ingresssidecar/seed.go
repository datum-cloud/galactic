// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
)

// SeedFromAPI lists every EndpointSlice this sidecar selects on, directly from
// reader, and applies each one's desired route to store synchronously, through
// the same path the reconciler uses.
//
// Call it once at startup, before the store's inventory pass, passing the
// manager's uncached reader: that talks straight to the API server and is safe
// to use before the manager starts.
//
// That is what removes the dependency on cache and workqueue timing. Waiting for
// the cache to sync is not enough on its own: it guarantees the informer's
// initial list landed in the cache, and says nothing about whether the workqueue
// that list fed has been drained by the reconcile loop. On a busy node at boot
// those race, and inventory can see a live pod's kernel route as orphaned,
// seeding it under a synthetic key with its own grace period, independently of
// the real key the delayed reconcile eventually creates. Once that synthetic
// entry's grace elapses, the sweep deletes the underlying route, addressed by
// prefix and table rather than by store key, out from under the live pod.
//
// Seeding first closes that race. Applying desired state is idempotent, so the
// reconciler's later, now-redundant pass over the same objects is harmless.
func SeedFromAPI(ctx context.Context, reader client.Reader, store *Store) error {
	req, err := labels.NewRequirement(crdnames.LabelTenantID, selection.Exists, nil)
	if err != nil {
		return fmt.Errorf("build tenant-label selector: %w", err)
	}
	sel := labels.NewSelector().Add(*req)

	var list discoveryv1.EndpointSliceList
	if err := reader.List(ctx, &list, client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return fmt.Errorf("list EndpointSlices: %w", err)
	}

	for i := range list.Items {
		slice := &list.Items[i]
		desired, err := BuildDesiredRoute(slice)
		if err != nil {
			// Same handling as Reconciler.Reconcile: malformed-but-selected
			// is worth logging, not worth failing startup over.
			ctrl.LoggerFrom(ctx).Error(err, "skipping malformed EndpointSlice",
				"endpointslice", fmt.Sprintf("%s/%s", slice.Namespace, slice.Name))
			continue
		}
		if desired == nil {
			continue // not yet ready (no SID annotation) -- nothing to seed
		}
		key := fmt.Sprintf("%s/%s", slice.Namespace, slice.Name)
		if err := store.SetDesired(ctx, key, desired); err != nil {
			return fmt.Errorf("seed EndpointSlice %s: %w", key, err)
		}
	}
	return nil
}
