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

	resourceNAT66Shards = "nat66shards"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkWatchPermissions issues a SelfSubjectAccessReview for nat66shards,
// checking the watch verb. If the review denies the request the informer
// cache will never sync and NAT66ShardReconciler will be silently
// blocked; this logs a clear, actionable message at startup so the
// problem is immediately obvious. Mirrors cmd/galactic-gateway/main.go's
// identically-named function, scoped to this binary's own single
// resource: unlike galactic-gateway's NetworkGatewayReconciler,
// NAT66ShardReconciler reads no other CRD (no BGPRouter/BGPAdvertisement
// lookup -- see internal/controller/nat66shard_controller.go's own doc
// comment for why this reconciler is deliberately much simpler).
func checkWatchPermissions(mgr ctrl.Manager) {
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		ctrl.Log.Error(err, "RBAC pre-flight: cannot create client, skipping check")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := ctrl.Log.WithName("rbac-preflight")

	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "watch",
				Group:    networkAPIGroup,
				Version:  networkAPIVersion,
				Resource: resourceNAT66Shards,
			},
		},
	}
	if err := c.Create(ctx, review); err != nil {
		logger.Error(err, "RBAC pre-flight: failed to submit access review for "+resourceNAT66Shards, "verb", "watch")
		return
	}
	if review.Status.Allowed {
		return
	}
	logger.Error(nil, "missing watch RBAC for "+resourceNAT66Shards,
		"verb", "watch", "detail", "informer cache will not sync; add resource to ServiceAccount ClusterRole and restart")
}
