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

	_ "golang.org/x/crypto/x509roots/fallback"
	authorizationv1 "k8s.io/api/authorization/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	networkAPIGroup   = "galactic.datumapis.com"
	networkAPIVersion = "v1alpha1"

	resourceNetworkGateways         = "networkgateways"
	resourceNetworkServices         = "networkservices"
	resourceNetworkServiceAddresses = "networkserviceaddresses"
	resourceBGPAdvertisements       = "bgpadvertisements"
	resourceBGPRouters              = "bgprouters"
	resourceBGPVRFInstances         = "bgpvrfinstances"
	resourceServiceVIPBinding       = "servicevipbindings"

	cloudAPIGroup          = "galactic.datumapis.com"
	cloudAPIVersion        = "v1alpha1"
	resourceVPCAttachments = "vpcattachments"
	resourceVPCs           = "vpcs"
)

// verbList and verbWatch are the verbs an informer needs on each type it
// watches.
const (
	verbList  = "list"
	verbWatch = "watch"
)

var informerVerbs = []string{verbList, verbWatch}

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// watchedResource is one type the gateway's manager watches: kind as the
// controllers register it, resource as access reviews name it.
type watchedResource struct{ group, version, kind, resource string }

// watchedResources returns every type the gateway's controllers and field
// indexes watch. TestWatchedResourcesMatchControllers fails when a controller
// watches a type this list leaves out, so add the type here along with the
// watch.
//
// BGPRouter is included even though this binary has no BGP client of its own:
// resolving a backend's uSID lists those CRDs directly, so read access to them
// is a real requirement here. VPCs are watched only with projectServices on.
// ServiceVIPBindings are watched whatever the IPv4 VIP and backend health
// switches say, since a shared address or port range rule reads them too.
func watchedResources(projectServices bool) []watchedResource {
	resources := []watchedResource{
		{group: networkAPIGroup, version: networkAPIVersion, kind: "NetworkGateway", resource: resourceNetworkGateways},
		{group: networkAPIGroup, version: networkAPIVersion, kind: "NetworkService", resource: resourceNetworkServices},
		{
			group: networkAPIGroup, version: networkAPIVersion, kind: "NetworkServiceAddress",
			resource: resourceNetworkServiceAddresses,
		},
		{group: networkAPIGroup, version: networkAPIVersion, kind: "BGPAdvertisement", resource: resourceBGPAdvertisements},
		{group: networkAPIGroup, version: networkAPIVersion, kind: "BGPRouter", resource: resourceBGPRouters},
		{group: networkAPIGroup, version: networkAPIVersion, kind: "BGPVRFInstance", resource: resourceBGPVRFInstances},
		{group: networkAPIGroup, version: networkAPIVersion, kind: "ServiceVIPBinding", resource: resourceServiceVIPBinding},
		{group: cloudAPIGroup, version: cloudAPIVersion, kind: "VPCAttachment", resource: resourceVPCAttachments},
	}
	if projectServices {
		resources = append(resources,
			watchedResource{group: cloudAPIGroup, version: cloudAPIVersion, kind: "VPC", resource: resourceVPCs})
	}
	return resources
}

// checkWatchPermissions issues access reviews for the list and watch verbs on
// each resource watchedResources names. A denial means the informer cache
// never syncs and every reconciler is silently blocked, so a denied verb fails
// startup with the resources it names. A review that cannot be made is logged
// and skipped, since the manager's own cache sync reports a real outage, but
// once ctx ends startup fails rather than passing a check it never finished.
func checkWatchPermissions(ctx context.Context, c client.Client, projectServices bool) error {
	logger := ctrl.Log.WithName("rbac-preflight")

	var denied []string
	for _, r := range watchedResources(projectServices) {
		var missing []string
		for _, verb := range informerVerbs {
			review := &authorizationv1.SelfSubjectAccessReview{
				Spec: authorizationv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     verb,
						Group:    r.group,
						Version:  r.version,
						Resource: r.resource,
					},
				},
			}
			if err := c.Create(ctx, review); err != nil {
				logger.Error(err, "RBAC pre-flight: failed to submit access review for "+r.resource, "verb", verb)
				continue
			}
			if !review.Status.Allowed {
				missing = append(missing, verb)
			}
		}
		if len(missing) > 0 {
			denied = append(denied, strings.Join(missing, " and ")+" on "+r.resource+"."+r.group)
		}
	}
	if len(denied) > 0 {
		return fmt.Errorf("the gateway's ClusterRole does not grant %s: the informer cache would "+
			"never sync, so grant it and restart", strings.Join(denied, ", "))
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("could not confirm the gateway's RBAC before startup: %w", err)
	}
	return nil
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
	for _, verb := range informerVerbs {
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
	return resolveBindingReader(ctx, c, requested, "IPv4 VIPs")
}

// resolveBackendHealth returns whether this process applies backend health:
// requested, from GALACTIC_GATEWAY_BACKEND_HEALTH, and allowed by
// ipv4VIPsAllowed's check of ServiceVIPBinding access, which reading health
// needs as much as IPv4 VIPs do. It behaves as resolveIPv4VIPs does.
func resolveBackendHealth(ctx context.Context, c client.Client, requested bool) (bool, error) {
	return resolveBindingReader(ctx, c, requested, "backend health")
}

// resolveBindingReader returns whether feature, which reads ServiceVIPBindings,
// is on: requested and allowed by ipv4VIPsAllowed. A denial is logged and
// turns it off; a review that cannot be made is retried until ctx ends and
// then returned as an error.
func resolveBindingReader(ctx context.Context, c client.Client, requested bool, feature string) (bool, error) {
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
				feature+" turned off on this node: grant get, list and watch on servicevipbindings and restart")
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("could not confirm access for %s: %w", feature, err)
		case <-time.After(ipv4ReviewRetry):
		}
	}
}
