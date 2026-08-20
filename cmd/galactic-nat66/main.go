// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-nat66 is one shard of the sharded, stateful NAT66
// egress tier of the Galactic data plane. It loads and attaches
// internal/plumbing/ebpf/nat66prog's XDP program to this shard's own
// fabric-facing uplink interface and registers the NAT66ShardReconciler
// that publishes this shard's operator-configured identity
// (Status.ShardAddress/Status.ShardSID) and Ready condition.
//
// This binary is deliberately its own standalone datapath, not a
// personality bolted onto galactic-gateway: tenant egress traffic
// (backend -> arbitrary internet destination) is a different traffic
// pattern from ingress (fixed VIP, fixed backend pool) and needs its own
// placement ring, own state, own self-routing return path -- see
// nat66prog's own doc comment and nat66.c's header comment for the full
// design.
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

// checkWatchPermissions issues a SelfSubjectAccessReview for each resource
// NAT66ShardReconciler now touches, checking the watch verb. If a review
// denies the request the informer cache will never sync and the
// reconciler will be silently blocked; this logs a clear, actionable
// message at startup so the problem is immediately obvious. Mirrors
// cmd/galactic-gateway/main.go's identically-named function.
//
// bgprouters/bgpadvertisements are new here: NAT66ShardReconciler's own
// doc comment used to describe this binary as reading no other CRD at
// all, but applyShardAdvertisement (nat66shard_controller.go) now looks
// up this node's BGPRouter and creates/updates/deletes a BGPAdvertisement
// for Status.ShardSID -- the same RBAC surface
// cmd/galactic-gateway/main.go's own checkWatchPermissions already checks
// for NetworkGatewayReconciler's identical pattern.
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
