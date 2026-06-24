// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// enqueueRoutersForTarget returns reconcile.Requests for BGPRouters in namespace
// that match either a direct routerRef or a routerSelector. resource names the
// calling resource kind and name for log context.
func enqueueRoutersForTarget(
	ctx context.Context,
	c client.Client,
	namespace string,
	routerRef *bgpv1alpha1.RouterRef,
	routerSelector *bgpv1alpha1.RouterSelector,
	resource string,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	if routerRef != nil {
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{
				Namespace: namespace,
				Name:      routerRef.Name,
			},
		}}
	}

	if routerSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
			MatchLabels:      routerSelector.MatchLabels,
			MatchExpressions: routerSelector.MatchExpressions,
		})
		if err != nil {
			logger.Error(err, "invalid routerSelector", "resource", resource)
			return nil
		}
		routerList := &bgpv1alpha1.BGPRouterList{}
		if err := c.List(ctx, routerList,
			client.InNamespace(namespace),
			client.MatchingLabelsSelector{Selector: sel},
		); err != nil {
			logger.Error(err, "list BGPRouters for selector", "resource", resource)
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(routerList.Items))
		for _, router := range routerList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: router.Namespace,
					Name:      router.Name,
				},
			})
		}
		return reqs
	}

	return nil
}
