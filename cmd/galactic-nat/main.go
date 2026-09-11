// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-nat66 is one shard of the sharded, stateful NAT66 egress tier
// of the Galactic data plane. It loads and attaches the NAT66 XDP program to
// this shard's fabric-facing uplink and registers the reconciler that publishes
// this shard's operator-configured identity and Ready condition.
//
// It is deliberately its own standalone datapath rather than a personality on
// the edge gateway: tenant egress toward an arbitrary internet destination is a
// different pattern from ingress toward a fixed VIP and backend pool, and needs
// its own placement ring, state, and return path.
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

	resourceNAT66Shards       = "nat66shards"
	resourceBGPAdvertisements = "bgpadvertisements"
	resourceBGPRouters        = "bgprouters"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkWatchPermissions issues an access review for each resource the shard
// reconciler touches, checking the watch verb. A denial means the informer cache
// never syncs and the reconciler is silently blocked, so this logs a clear,
// actionable message at startup instead.
//
// It covers the routers and advertisements the shard advertisement path reads
// and writes, not just the shard resource itself.
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
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceNAT66Shards},
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
