// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-router is the BGP control-plane reconciler for the Galactic
// data plane. It watches Cosmos BGP CRDs and drives a BGP runtime backend
// (GoBGP for tenant role, FRR stub for fabric role).
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
	bgpAPIGroup   = "bgp.miloapis.com"
	bgpAPIVersion = "v1alpha1"

	resourceBGPRouters        = "bgprouters"
	resourceBGPPeers          = "bgppeers"
	resourceBGPAdvertisements = "bgpadvertisements"
	resourceBGPPolicies       = "bgppolicies"
	resourceBGPVRFInstances   = "bgpvrfinstances"
	resourceSecrets           = "secrets"
	resourceNodes             = "nodes"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkWatchPermissions issues a SelfSubjectAccessReview for each resource
// type the manager watches, checking the watch verb. If any review denies
// the request the informer cache will never sync and all reconcilers will
// be silently blocked; this logs a clear, actionable message at startup so
// the problem is immediately obvious.
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
		group     string
		version   string
		resource  string
		namespace string
	}{
		{group: bgpAPIGroup, version: bgpAPIVersion, resource: resourceBGPRouters},
		{group: bgpAPIGroup, version: bgpAPIVersion, resource: resourceBGPPeers},
		{group: bgpAPIGroup, version: bgpAPIVersion, resource: resourceBGPAdvertisements},
		{group: bgpAPIGroup, version: bgpAPIVersion, resource: resourceBGPPolicies},
		{group: bgpAPIGroup, version: bgpAPIVersion, resource: resourceBGPVRFInstances},
		{version: "v1", resource: resourceSecrets},
		{version: "v1", resource: resourceNodes},
	}

	for _, r := range resources {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: r.namespace,
					Verb:      "watch",
					Group:     r.group,
					Version:   r.version,
					Resource:  r.resource,
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
