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

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NodeSourceAddressResolver resolves this node's globally routable
// underlay-facing address, the address usid_egress's outer header must be
// sourced from for a reply to have a real path back.
//
// The default resolver auto-detects the interface carrying the local default
// IPv6 route. That is correct for a process in the host's root namespace, where
// it really is the fabric uplink, and wrong by construction here: this sidecar
// runs inside Envoy's pod namespace so socket binds resolve there, and inside
// that namespace the default route belongs to the pod's cluster-managed
// interface. Its address is a ULA drawn from the cluster's own pool, not this
// node's address, and a ULA source is exactly what a competent network edge's
// anti-spoofing filtering drops silently, after otherwise-working transit all
// the way to the destination.
//
// This resolver answers the same question differently, by reading the address
// off a BGPPeer this node's router already maintains rather than guessing from
// local namespace state that this deployment shape makes unreliable.
type NodeSourceAddressResolver interface {
	ResolveNodeSourceAddress() (net.IP, error)
}

// k8sNodeSourceAddressResolver is the production NodeSourceAddressResolver.
type k8sNodeSourceAddressResolver struct {
	client    client.Client
	nodeName  string
	namespace string
}

// NewK8sNodeSourceAddressResolver returns a resolver that reads BGPPeer CRDs in
// namespace, looking for one targeting nodeName's own BGPRouter.
func NewK8sNodeSourceAddressResolver(c client.Client, nodeName, namespace string) NodeSourceAddressResolver {
	return &k8sNodeSourceAddressResolver{client: c, nodeName: nodeName, namespace: namespace}
}

// ResolveNodeSourceAddress reads the local source address off a BGPPeer.
//
// A peer's address field is the remote peer's; the update source is the local
// one, the address used as the source for the BGP session. Every peer whose
// router reference names this node shares the same answer, a node using one
// consistent source for all its sessions, so the first with a usable update
// source wins. A node with none configured yet, its sessions still converging
// after a restart, returns an error for the caller's existing non-fatal
// handling to log and retry.
//
// It uses a background context rather than a threaded one: the whole call chain
// up through the VRF backend carries no context today, and adding one is a
// cross-cutting signature change for a call that is cheap, idempotent, and
// safe to retry on the next reconcile.
func (r *k8sNodeSourceAddressResolver) ResolveNodeSourceAddress() (net.IP, error) {
	ctx := context.Background()
	peerList := &bgpv1alpha1.BGPPeerList{}
	if err := r.client.List(ctx, peerList, client.InNamespace(r.namespace)); err != nil {
		return nil, fmt.Errorf("list BGPPeers in namespace %s: %w", r.namespace, err)
	}
	for _, peer := range peerList.Items {
		if peer.Spec.RouterRef == nil || peer.Spec.RouterRef.Name != r.nodeName {
			continue
		}
		if peer.Spec.UpdateSource == nil || *peer.Spec.UpdateSource == "" {
			continue
		}
		addr := net.ParseIP(*peer.Spec.UpdateSource)
		if addr == nil {
			continue
		}
		return addr, nil
	}
	return nil, fmt.Errorf("no BGPPeer with a usable updateSource found for node %s in namespace %s",
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
