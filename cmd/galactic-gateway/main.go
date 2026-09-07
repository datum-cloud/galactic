// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-gateway is the edge XDP gateway control plane. It loads and
// attaches the edge eBPF program to a gateway node's underlay-facing uplink and
// drives it through the NetworkGateway and NetworkRule reconcilers.
//
// It is a separate binary from galactic-router so that a crash on either side,
// tenant BGP or the gateway engine holding the XDP attachment, no longer takes
// the other down. Tenant BGP still runs in the router, co-located on the same
// node.
package main

import (
	"context"
	"os"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	networkAPIGroup   = "network.datumapis.com"
	networkAPIVersion = "v1alpha1"

	resourceNetworkGateways   = "networkgateways"
	resourceNetworkRules      = "networkrules"
	resourceBGPAdvertisements = "bgpadvertisements"
	resourceBGPRouters        = "bgprouters"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkWatchPermissions issues an access review for the watch verb on each
// resource the manager watches. A denial means the informer cache never syncs
// and every reconciler is silently blocked, so this logs a clear, actionable
// message at startup instead.
//
// BGPRouter is included even though this binary has no BGP client of its own:
// resolving a backend's uSID lists those CRDs directly, so read access to them
// is a real requirement here.
func checkWatchPermissions(mgr ctrl.Manager) {
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		ctrl.Log.Error(err, "RBAC pre-flight: cannot create client, skipping check")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := ctrl.Log.WithName("rbac-preflight")

	resources := []struct {
		group    string
		version  string
		resource string
	}{
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceNetworkGateways},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceNetworkRules},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceBGPAdvertisements},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceBGPRouters},
	}

	for _, r := range resources {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "watch",
					Group:    r.group,
					Version:  r.version,
					Resource: r.resource,
				},
			},
		}
		if err := c.Create(ctx, review); err != nil {
			logger.Error(err, "RBAC pre-flight: failed to submit access review for "+r.resource, "verb", "watch")
			continue
		}
		if review.Status.Allowed {
			continue
		}
		logger.Error(nil, "missing watch RBAC for "+r.resource,
			"verb", "watch", "detail", "informer cache will not sync; add resource to ServiceAccount ClusterRole and restart")
	}
}
