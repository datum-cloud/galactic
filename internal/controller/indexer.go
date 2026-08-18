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

// RegisterIndexes registers all field indexes required by galactic-router's
// and galactic-gateway's controllers (e.g. NetworkGatewayReconciler's own
// BGPRouterByTargetName lookup) against mgr's cache. Each binary runs its
// own separate manager/cache, so this must be called once per process --
// it must be called before starting the manager.
//
// controller-runtime's cache starts a live informer for every type touched
// by IndexField, immediately, regardless of whether any reconciler in this
// process ever reads that type again -- calling this full function from a
// binary whose RBAC doesn't cover every one of BGPPeer/BGPPolicy/
// BGPAdvertisement/BGPVRFInstance/BGPRouter fails outright ("cannot list
// resource ... at the cluster scope"), found live the first time
// cmd/galactic-nat66 called this instead of RegisterBGPRouterTargetIndex
// below. Only galactic-router's own manager (which already holds the full
// BGP RBAC set) and galactic-gateway's (which inherits it via its second
// ClusterRoleBinding onto galactic-router's ClusterRole, config/galactic-
// gateway/rbac.yaml's own doc comment) should call this; anything narrower
// should call one of the single-index functions below instead.
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

// RegisterBGPRouterTargetIndex registers only the BGPRouterByTargetName
// index against mgr's cache -- the single index
// NAT66ShardReconciler.applyShardAdvertisement's routerNameForNode lookup
// actually needs (nat66shard_controller.go). Deliberately narrower than
// RegisterIndexes: cmd/galactic-nat66's RBAC (config/galactic-nat66/rbac.yaml)
// grants exactly nat66shards/bgpadvertisements/bgprouters, not the full BGP
// CRD set RegisterIndexes' own doc comment explains that function requires
// -- calling RegisterIndexes here failed live with a
// bgppolicies-cluster-scope-forbidden error the moment the manager started
// (its cache eagerly starts an informer for every type any IndexField call
// touches, not just BGPRouter).
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
