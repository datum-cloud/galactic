// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-vrf is #855's ingress sidecar: the second container in
// the shared Envoy Gateway fleet's pod, responsible only for VPC backend
// connectivity — Linux VRF device + SRv6 seg6 encap route lifecycle, driven
// entirely by a cluster-scoped watch on discoveryv1.EndpointSlice objects
// galactic-cni (#854) publishes per pod. See
// docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md and
// internal/ingresssidecar's own doc comment for the full design; this
// binary is just the process wiring (config, manager, metrics, RBAC
// pre-flight) around that package.
//
// Unlike galactic-router/galactic-gateway, this binary exposes no gRPC
// health server: neither of this repo's existing binaries has an
// established /healthz convention to copy (galactic-router explicitly
// disables its health probe; galactic-cni has none at all — see §5 of the
// plan), so building one here would be new design work rather than
// following a pattern, and container liveness (process exits, kubelet
// restarts it) is enough for v1.
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

// checkWatchPermissions issues a SelfSubjectAccessReview for the "watch"
// verb on endpointslices, the only resource this binary's manager watches.
// If the review denies the request the informer cache will never sync and
// the reconciler will be silently blocked; this logs a clear, actionable
// message at startup so the problem is immediately obvious. Mirrors
// cmd/galactic-router and cmd/galactic-gateway's identically-named
// functions, scoped to this binary's own single resource — see §9 item 8
// of the plan (the read-only ClusterRole decision this check exists to
// help catch a misconfiguration of).
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
