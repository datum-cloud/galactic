// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Field index names used across controllers.
const (
	// BGPPeerBySecretName indexes BGPPeers by the name of their authSecretRef.
	BGPPeerBySecretName = ".spec.authSecretRef.name"

	// BGPPeerByRouterName indexes BGPPeers by their routerRef.name.
	BGPPeerByRouterName = ".spec.routerRef.name"

	// BGPPolicyByRouterName indexes BGPPolicies by their routerRef.name.
	BGPPolicyByRouterName = ".spec.routerRef.name"

	// BGPAdvByRouterName indexes BGPAdvertisements by their routerRef.name.
	BGPAdvByRouterName = ".spec.routerRef.name"

	// BGPVRFInstanceByRouterName indexes BGPVRFInstances by their routerRef.name.
	BGPVRFInstanceByRouterName = ".spec.routerRef.name"

	// BGPRouterByTargetName indexes BGPRouters by their targetRef.name (the Node name).
	BGPRouterByTargetName = ".spec.targetRef.name"
)

// RegisterIndexes registers all field indexes required by galactic-router controllers.
// It must be called before starting the manager.
func RegisterIndexes(ctx context.Context, mgr ctrl.Manager) error {
	cache := mgr.GetCache()

	// BGPPeer: index by authSecretRef.name.
	if err := cache.IndexField(ctx, &bgpv1alpha1.BGPPeer{}, BGPPeerBySecretName, func(obj client.Object) []string {
		peer, ok := obj.(*bgpv1alpha1.BGPPeer)
		if !ok {
			return nil
		}
		if peer.Spec.AuthSecretRef == nil {
			return nil
		}
		return []string{peer.Spec.AuthSecretRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPPeer by authSecretRef.name: %w", err)
	}

	// BGPPeer: index by routerRef.name (only when routerRef is set, not routerSelector).
	if err := cache.IndexField(ctx, &bgpv1alpha1.BGPPeer{}, BGPPeerByRouterName, func(obj client.Object) []string {
		peer, ok := obj.(*bgpv1alpha1.BGPPeer)
		if !ok {
			return nil
		}
		if peer.Spec.RouterRef == nil {
			return nil
		}
		return []string{peer.Spec.RouterRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPPeer by routerRef.name: %w", err)
	}

	// BGPPolicy: index by routerRef.name.
	if err := cache.IndexField(ctx, &bgpv1alpha1.BGPPolicy{}, BGPPolicyByRouterName, func(obj client.Object) []string {
		policy, ok := obj.(*bgpv1alpha1.BGPPolicy)
		if !ok {
			return nil
		}
		if policy.Spec.RouterRef == nil {
			return nil
		}
		return []string{policy.Spec.RouterRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPPolicy by routerRef.name: %w", err)
	}

	// BGPAdvertisement: index by routerRef.name.
	if err := cache.IndexField(ctx, &bgpv1alpha1.BGPAdvertisement{}, BGPAdvByRouterName, func(obj client.Object) []string {
		adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
		if !ok {
			return nil
		}
		return []string{adv.Spec.RouterRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPAdvertisement by routerRef.name: %w", err)
	}

	// BGPVRFInstance: index by routerRef.name.
	if err := cache.IndexField(
		ctx, &bgpv1alpha1.BGPVRFInstance{},
		BGPVRFInstanceByRouterName,
		func(obj client.Object) []string {
			vrf, ok := obj.(*bgpv1alpha1.BGPVRFInstance)
			if !ok {
				return nil
			}
			if vrf.Spec.RouterRef == nil {
				return nil
			}
			return []string{vrf.Spec.RouterRef.Name}
		}); err != nil {
		return fmt.Errorf("index BGPVRFInstance by routerRef.name: %w", err)
	}

	// BGPRouter: index by targetRef.name (the Node name).
	if err := cache.IndexField(ctx, &bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
		router, ok := obj.(*bgpv1alpha1.BGPRouter)
		if !ok {
			return nil
		}
		return []string{router.Spec.TargetRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPRouter by targetRef.name: %w", err)
	}

	return nil
}
