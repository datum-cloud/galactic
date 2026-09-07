// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-vrf is the ingress sidecar: the second container in the
// shared Envoy fleet's pod, responsible only for VPC backend connectivity,
// meaning the Linux VRF device and SRv6 egress route lifecycle, driven entirely
// by a cluster-scoped watch on the EndpointSlices the CNI publishes per pod.
// This binary is the process wiring around internal/ingresssidecar: config,
// manager, metrics, and an access pre-flight check.
//
// Unlike the router and gateway binaries it exposes no gRPC health server.
// Neither has an established convention to copy, one disabling its probe and the
// other having none, so building one here would be new design work rather than
// following a pattern, and container liveness is enough.
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
	discoveryAPIGroup      = "discovery.k8s.io"
	discoveryAPIVersion    = "v1"
	resourceEndpointSlices = "endpointslices"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkWatchPermissions issues an access review for the watch verb on
// endpointslices, the only resource this binary's manager watches. A denial
// means the informer cache never syncs and the reconciler is silently blocked,
// so this logs a clear, actionable message at startup instead.
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
				Group:    discoveryAPIGroup,
				Version:  discoveryAPIVersion,
				Resource: resourceEndpointSlices,
			},
		},
	}
	if err := c.Create(ctx, review); err != nil {
		logger.Error(err, "RBAC pre-flight: failed to submit access review for "+resourceEndpointSlices, "verb", "watch")
		return
	}
	if review.Status.Allowed {
		return
	}
	logger.Error(nil, "missing watch RBAC for "+resourceEndpointSlices,
		"verb", "watch", "detail", "informer cache will not sync; add resource to ServiceAccount ClusterRole and restart")
}
