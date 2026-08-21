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

// SeedFromAPI lists every EndpointSlice this sidecar selects on directly
// from reader and applies each one's desired route to store synchronously,
// via the same SetDesired path Reconciler itself uses.
//
// Call this once at startup, before Store.Inventory, passing
// mgr.GetAPIReader() as reader — the manager's uncached reader, which talks
// straight to the API server and is safe to use before mgr.Start. That
// matters because it's what lets this run without depending on the
// manager's informer cache or controller workqueue at all: Store.Inventory
// used to be gated on mgr.GetCache().WaitForCacheSync(ctx) alone, on the
// assumption that a synced cache implied every pre-existing EndpointSlice
// had already gone through the controller's own Reconcile (and therefore
// SetDesired). That assumption is false — WaitForCacheSync only guarantees
// the informer's initial List landed in the cache; it says nothing about
// whether the workqueue that same initial List fed into has been drained
// by the controller's Reconcile loop yet. On a busy node at boot those two
// things race: Inventory could observe a live pod's kernel route as
// orphaned (routeKnownLocked found no tracked state for it yet) and seed it
// under a synthetic "boot/..." key with its own grace period, independently
// of the real key the delayed Reconcile eventually creates -- and once that
// synthetic entry's grace elapsed, Sweep would delete the underlying kernel
// route (routes are addressed by prefix+table, not by Store's map key) out
// from under the still-live pod. SeedFromAPI closes that race by making
// every live EndpointSlice's desired route visible to Store before
// Inventory ever runs, independent of cache/queue timing entirely.
// SetDesired is idempotent (EnsureVRF/EnsureRoute no-op once installed), so
// the controller's own later, now-redundant Reconcile of the same objects
// is harmless.
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
