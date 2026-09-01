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

// NodeSourceAddressResolver resolves this node's own real, globally-routable
// underlay-facing address -- the address usid_egress's outer SRv6 header
// must be sourced from for a reply to have any real-world path back to it.
//
// ensureNodeSourceAddress's default (srv6.ResolveNodeSourceAddress) answers
// this by auto-detecting the interface carrying the local default IPv6
// route -- correct for galactic-cni, which runs in the host's own root
// network namespace, where that really is the fabric uplink. It is wrong by
// construction for this package: #855 deliberately runs this sidecar inside
// Envoy's own pod netns (so SO_BINDTODEVICE resolves there), and *inside*
// that netns the interface carrying the default route is the pod's own
// Cilium-managed eth0 -- a ULA pod address drawn from the cluster's own
// tenant pool (fd20::/20), not this node's real address at all. Confirmed
// live: a captured outer SRv6 header's source matched this sidecar's own
// pod IP bit for bit, and a ULA source is exactly the kind of thing a
// competent network edge's own anti-spoofing/BCP38 filtering exists to
// silently drop -- which is what happened, all the way through otherwise-
// working global BGP transit to the destination.
//
// This resolver answers the same question a different way: read it off a
// BGPPeer this node's own galactic-router already maintains, rather than
// guessing from local netns state that #855's own design makes unreliable
// for this specific caller.
type NodeSourceAddressResolver interface {
	ResolveNodeSourceAddress() (net.IP, error)
}

// k8sNodeSourceAddressResolver is the production NodeSourceAddressResolver.
type k8sNodeSourceAddressResolver struct {
	client    client.Client
	nodeName  string
	namespace string
}

// NewK8sNodeSourceAddressResolver returns a NodeSourceAddressResolver that
// reads BGPPeer CRDs in namespace via c, looking for one targeting
// nodeName's own BGPRouter.
func NewK8sNodeSourceAddressResolver(c client.Client, nodeName, namespace string) NodeSourceAddressResolver {
	return &k8sNodeSourceAddressResolver{client: c, nodeName: nodeName, namespace: namespace}
}

// ResolveNodeSourceAddress implements NodeSourceAddressResolver.
//
// A BGPPeer's own Spec.Address is the *remote* peer's address (its own doc
// comment says so explicitly) -- Spec.UpdateSource is the local one: "the
// local IP address ... used as the source for the BGP TCP session". Every
// BGPPeer whose RouterRef names this node shares the same real answer here
// (a node uses one consistent source address for all of its own sessions),
// so the first one with a usable UpdateSource wins; nothing here needs them
// to agree beyond that, and a node with none configured yet (BFD/session
// still converging right after this sidecar's own restart) returns a plain
// error for ensureNodeSourceAddress's own existing non-fatal-on-failure
// handling to log and retry, matching every other resolver in this package.
//
// context.Background() rather than a threaded ctx: ensureEgressDatapath's
// entire call chain up through Backend.EnsureVRF carries no context
// parameter today, and adding one is a much larger, cross-cutting signature
// change for a call this package's own doc comments already describe as
// cheap, idempotent, and safe to retry on the next reconcile -- not a
// tradeoff worth making in the same change that fixes the actual address
// bug. Revisit if EnsureVRF ever grows a context for an unrelated reason.
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

// nodeSourceAddressResolverMu guards nodeSourceAddressResolver -- the same
// package-level-var-as-configuration-seam pattern gatewayAssignmentMu
// (gatewayaddress.go) and gatewayPublisher (store.go) already use, for the
// identical reason: ensureNodeSourceAddress is an unexported function
// called from exactly one production site with no per-call state to thread
// this through today.
var (
	nodeSourceAddressResolverMu sync.Mutex
	nodeSourceAddressResolver   NodeSourceAddressResolver
)

// SetNodeSourceAddressResolver configures ensureNodeSourceAddress to use r
// instead of its default (srv6.ResolveNodeSourceAddress) -- see
// NodeSourceAddressResolver's own doc comment for why the default is wrong
// for this package's real deployment shape. r == nil (the default, until
// cmd/galactic-vrf wires one) restores the old behavior; this is purely
// additive, matching every other opt-in setter in this package.
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
