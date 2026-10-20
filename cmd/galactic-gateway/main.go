// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-gateway is the edge XDP gateway control plane. It loads and
// attaches the edge eBPF program to a gateway node's underlay-facing uplink and
// drives it through the NetworkGateway and NetworkService reconcilers.
//
// It is a separate binary from galactic-router so that a crash on either side,
// tenant BGP or the gateway engine holding the XDP attachment, no longer takes
// the other down. Tenant BGP still runs in the router, co-located on the same
// node.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	networkAPIGroup   = "galactic.datumapis.com"
	networkAPIVersion = "v1alpha1"

	resourceNetworkGateways   = "networkgateways"
	resourceNetworkServices   = "networkservices"
	resourceBGPAdvertisements = "bgpadvertisements"
	resourceBGPRouters        = "bgprouters"
	resourceBGPVRFInstances   = "bgpvrfinstances"
	resourceServiceVIPBinding = "servicevipbindings"

	cloudAPIGroup          = "galactic.datumapis.com"
	cloudAPIVersion        = "v1alpha1"
	resourceVPCAttachments = "vpcattachments"
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
// is a real requirement here. ServiceVIPBinding is not checked here: the
// manager watches it only with IPv4 VIPs on, and ipv4VIPsAllowed decides that.
func checkWatchPermissions(mgr ctrl.Manager) {
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		ctrl.Log.Error(err, "RBAC pre-flight: cannot create client, skipping check")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := ctrl.Log.WithName("rbac-preflight")

	type watchedResource struct{ group, version, resource string }
	resources := []watchedResource{
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceNetworkGateways},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceNetworkServices},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceBGPAdvertisements},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceBGPRouters},
		{group: networkAPIGroup, version: networkAPIVersion, resource: resourceBGPVRFInstances},
		{group: cloudAPIGroup, version: cloudAPIVersion, resource: resourceVPCAttachments},
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

// errIPv4AccessDenied is ipv4VIPsAllowed's error when the access reviews
// complete and deny it, as opposed to a review that could not be made.
var errIPv4AccessDenied = errors.New("IPv4 VIP access denied")

// ipv4VIPsAllowed reports whether this process may serve IPv4 VIPs: c's
// identity can list and watch ServiceVIPBindings, which the IPv4 readiness
// gate reads and watches. Without that access the manager's cache would never
// sync and the gateway would stop serving every rule, IPv6 included. A denial
// wraps errIPv4AccessDenied and names what is missing; any other error means a
// review could not be made.
func ipv4VIPsAllowed(ctx context.Context, c client.Client) error {
	var missing []string
	for _, verb := range []string{"list", "watch"} {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     verb,
					Group:    networkAPIGroup,
					Version:  networkAPIVersion,
					Resource: resourceServiceVIPBinding,
				},
			},
		}
		if err := c.Create(ctx, review); err != nil {
			return fmt.Errorf("check %s access to %s.%s: %w", verb, resourceServiceVIPBinding, networkAPIGroup, err)
		}
		if !review.Status.Allowed {
			missing = append(missing, verb)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the gateway's ClusterRole does not grant %s on %s.%s", errIPv4AccessDenied,
			strings.Join(missing, " and "), resourceServiceVIPBinding, networkAPIGroup)
	}
	return nil
}

// ipv4ReviewRetry is how long resolveIPv4VIPs waits between access reviews
// that could not be made.
var ipv4ReviewRetry = time.Second

// resolveIPv4VIPs returns whether this process serves IPv4 VIPs: requested,
// from GALACTIC_GATEWAY_IPV4_VIPS, and allowed by ipv4VIPsAllowed. When access
// is denied it logs why and returns false, so the node keeps serving IPv6 and
// advertises no IPv4 VIP. A review that cannot be made is retried until ctx
// ends, and then returned as an error rather than read as a denial: turning
// IPv4 off makes the node report it unloaded, which removes backend IPv4
// bindings once no gateway reports it loaded, so a brief API server outage
// while every gateway restarts must not do that.
func resolveIPv4VIPs(ctx context.Context, c client.Client, requested bool) (bool, error) {
	if !requested {
		return false, nil
	}
	for {
		err := ipv4VIPsAllowed(ctx, c)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, errIPv4AccessDenied):
			ctrl.Log.WithName("rbac-preflight").Error(err,
				"IPv4 VIPs turned off on this node: grant get, list and watch on servicevipbindings and restart")
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("could not confirm access for IPv4 VIPs: %w", err)
		case <-time.After(ipv4ReviewRetry):
		}
	}
}
