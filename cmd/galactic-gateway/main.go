// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-gateway is the edge XDP NAT+LB gateway control plane of
// the Galactic data plane. It loads and attaches the edge NAT+LB eBPF
// program (internal/plumbing/ebpf/edgeprog) to a gateway node's public/
// underlay-facing uplink interface and drives it via the
// NetworkGateway/NetworkRule reconcilers.
//
// This binary was split out of galactic-router so that a crash on either
// side (tenant BGP vs. the XDP-holding gateway engine) no longer takes the
// other down with it. Tenant BGP (the embedded GoBGP server and the
// BGPRouter/BGPPeer/
// BGPAdvertisement/BGPPolicy/BGPVRFInstance reconcilers) still runs in
// galactic-router, co-located on the same gateway node.
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

// checkWatchPermissions issues a SelfSubjectAccessReview for each resource
// type the manager watches, checking the watch verb. If any review denies
// the request the informer cache will never sync and all reconcilers will
// be silently blocked; this logs a clear, actionable message at startup so
// the problem is immediately obvious. Mirrors
// cmd/galactic-router/main.go's identically-named function, scoped to this
// binary's own resource set instead of the BGP-family CRDs.
//
// resourceBGPRouters is included even though this binary has no BGP
// client of its own: internal/controller/usidresolver.go's
// buildBackendSIDIndex lists
// BGPRouter CRDs directly (alongside BGPAdvertisement) to resolve a
// NetworkRule backend's SRv6 uSID, so read access to bgprouters is a real
// RBAC requirement here regardless of not needing a BGP runtime.
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
