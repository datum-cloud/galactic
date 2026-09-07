// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
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

// RegisterIndexes registers every field index galactic-router's and
// galactic-gateway's controllers need against mgr's cache. Each binary runs its
// own manager and cache, so it must be called once per process, before starting
// the manager.
//
// The cache starts a live informer for every type an index touches, immediately
// and regardless of whether any reconciler here reads that type again. Calling
// this from a binary whose role does not cover every BGP kind fails outright at
// startup with a forbidden list error. Only the router's manager, which holds
// the full BGP access, and the gateway's, which inherits it, should call this;
// anything narrower should call one of the single-index functions below.
func RegisterIndexes(ctx context.Context, mgr ctrl.Manager) error {
	c := mgr.GetCache()

	if err := registerBGPPeerBySecretNameIndex(ctx, c); err != nil {
		return err
	}
	if err := registerBGPPeerByRouterNameIndex(ctx, c); err != nil {
		return err
	}
	if err := registerBGPPolicyByRouterNameIndex(ctx, c); err != nil {
		return err
	}
	if err := registerBGPAdvByRouterNameIndex(ctx, c); err != nil {
		return err
	}
	if err := registerBGPVRFInstanceByRouterNameIndex(ctx, c); err != nil {
		return err
	}
	return RegisterBGPRouterTargetIndex(ctx, mgr)
}

// RegisterBGPRouterTargetIndex registers only the router-by-target index, the
// one the shard reconciler's router lookup needs.
//
// Deliberately narrower than RegisterIndexes: this binary's role grants only the
// kinds it uses, and the full function fails at manager startup with a forbidden
// error, the cache eagerly starting an informer for every type any index
// touches.
func RegisterBGPRouterTargetIndex(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetCache().IndexField(
		ctx, &bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
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

func registerBGPPeerBySecretNameIndex(ctx context.Context, c cache.Cache) error {
	if err := c.IndexField(ctx, &bgpv1alpha1.BGPPeer{}, BGPPeerBySecretName, func(obj client.Object) []string {
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
	return nil
}

func registerBGPPeerByRouterNameIndex(ctx context.Context, c cache.Cache) error {
	// index by routerRef.name (only when routerRef is set, not routerSelector).
	if err := c.IndexField(ctx, &bgpv1alpha1.BGPPeer{}, BGPPeerByRouterName, func(obj client.Object) []string {
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
	return nil
}

func registerBGPPolicyByRouterNameIndex(ctx context.Context, c cache.Cache) error {
	if err := c.IndexField(ctx, &bgpv1alpha1.BGPPolicy{}, BGPPolicyByRouterName, func(obj client.Object) []string {
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
	return nil
}

func registerBGPAdvByRouterNameIndex(ctx context.Context, c cache.Cache) error {
	if err := c.IndexField(ctx, &bgpv1alpha1.BGPAdvertisement{}, BGPAdvByRouterName, func(obj client.Object) []string {
		adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
		if !ok {
			return nil
		}
		return []string{adv.Spec.RouterRef.Name}
	}); err != nil {
		return fmt.Errorf("index BGPAdvertisement by routerRef.name: %w", err)
	}
	return nil
}

func registerBGPVRFInstanceByRouterNameIndex(ctx context.Context, c cache.Cache) error {
	if err := c.IndexField(
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
	return nil
}
