// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"net"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NodeSourceAddressResolver resolves this node's own SRv6 SID base, the value
// usid_egress completes with each packet's Argument and writes as the source of
// every outer header it pushes. An egress shard sends a translated reply back
// to whatever that source was, so it decides whether a tenant's flow can
// complete at all.
//
// An interface address will not do, which is what this returned until #550.
// No node originates a point-to-point link prefix into the fabric, and
// usid_ingress decapsulates only destinations matching its locator_table, so a
// reply addressed to one is dropped either on the way or on arrival. Reading
// one locally is doubly wrong in this package: the sidecar runs inside Envoy's
// pod namespace, where the interfaces on offer are the pod's cluster-managed
// ones, not the node's uplink.
//
// This resolves from the node's own BGPRouter instead, the same CRD the CNI
// computes its advertised SIDs from, so the two cannot disagree about which
// SID this node owns.
type NodeSourceAddressResolver interface {
	ResolveNodeSourceAddress() (net.IP, error)
}

// k8sNodeSourceAddressResolver is the production NodeSourceAddressResolver.
type k8sNodeSourceAddressResolver struct {
	client    client.Client
	nodeName  string
	namespace string
}

// NewK8sNodeSourceAddressResolver returns a resolver that reads BGPRouter CRDs
// in namespace, looking for the one targeting nodeName.
func NewK8sNodeSourceAddressResolver(c client.Client, nodeName, namespace string) NodeSourceAddressResolver {
	return &k8sNodeSourceAddressResolver{client: c, nodeName: nodeName, namespace: namespace}
}

// ResolveNodeSourceAddress derives this node's SID base from its BGPRouter's
// SRv6 locator and node ID.
//
// A node whose router carries neither yet, its CRDs still converging after a
// restart, returns an error for the caller's existing non-fatal handling to log
// and retry.
//
// It uses a background context rather than a threaded one: the whole call chain
// up through the VRF backend carries no context today, and adding one is a
// cross-cutting signature change for a call that is cheap, idempotent, and
// safe to retry on the next reconcile.
func (r *k8sNodeSourceAddressResolver) ResolveNodeSourceAddress() (net.IP, error) {
	ctx := context.Background()
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := r.client.List(ctx, routerList, client.InNamespace(r.namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRouters in namespace %s: %w", r.namespace, err)
	}
	for _, router := range routerList.Items {
		if router.Spec.TargetRef.Name != r.nodeName {
			continue
		}
		if router.Spec.SRv6Locator == "" || router.Spec.NodeID == 0 {
			continue
		}
		sid, err := srv6.NodeSIDBase(router.Spec.SRv6Locator, router.Spec.NodeID)
		if err != nil {
			return nil, fmt.Errorf("derive node SID base from BGPRouter %s: %w", router.Name, err)
		}
		return net.IP(sid.AsSlice()), nil
	}
	return nil, fmt.Errorf("no BGPRouter with an SRv6 locator and node ID found for node %s in namespace %s",
		r.nodeName, r.namespace)
}

// nodeSourceAddressResolverMu guards nodeSourceAddressResolver, the same
// configuration-seam pattern the other setters in this package use:
// ensureNodeSourceAddress is called from one production site with no per-call
// state to thread this through.
var (
	nodeSourceAddressResolverMu sync.Mutex
	nodeSourceAddressResolver   NodeSourceAddressResolver
)

// SetNodeSourceAddressResolver configures ensureNodeSourceAddress to use r
// instead of the default local auto-detection, which is wrong for this
// package's deployment shape. A nil r, the default until startup wires one,
// keeps the original behavior.
func SetNodeSourceAddressResolver(r NodeSourceAddressResolver) {
	nodeSourceAddressResolverMu.Lock()
	defer nodeSourceAddressResolverMu.Unlock()
	nodeSourceAddressResolver = r
}

// getNodeSourceAddressResolver returns the currently configured resolver,
// or nil if none has been set.
func getNodeSourceAddressResolver() NodeSourceAddressResolver {
	nodeSourceAddressResolverMu.Lock()
	defer nodeSourceAddressResolverMu.Unlock()
	return nodeSourceAddressResolver
}
