// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"net/netip"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/model"
)

// Metric labels naming a BGPRouter by its namespace/name and a BGP peer by its
// neighbor address, matching the runtime's own router metrics.
const (
	labelRouter = "router"
	labelPeer   = "peer"
)

// routerReady mirrors each BGPRouter's Ready condition as this node last wrote
// it: 1 when True, 0 otherwise. Only the node a router targets exports it, so
// one series exists per router.
var routerReady = metrics.NewGaugeVec(prometheus.GaugeOpts{
	Name: "galactic_router_ready",
	Help: "Whether the BGPRouter's Ready condition is True (1) or not (0).",
}, []string{labelRouter})

// peerEstablished reports, per BGPRouter and peer held by its runtime, whether
// the session is Established. It is refreshed on every reconcile, at least
// every peerStatusRequeue, so a session that drops and recovers between two
// reconciles may never read 0; galactic_router_peer_session_drops_total counts
// those.
var peerEstablished = metrics.NewGaugeVec(prometheus.GaugeOpts{
	Name: "galactic_router_peer_established",
	Help: "Whether the BGP session to a peer is Established (1) or not (0).",
}, []string{labelRouter, labelPeer})

// exportedPeers records, per router, the peer addresses peerEstablished has a
// series for, so a peer the runtime no longer holds loses its series instead of
// reporting its last state forever.
var (
	exportedPeersMu sync.Mutex
	exportedPeers   = map[string]map[string]struct{}{}
)

// peerLabel formats a peer address as netip does, the form GoBGP's peer events
// carry, so this gauge and the runtime's galactic_router_peer_session_drops_total
// label a peer identically, IPv4-mapped addresses included.
func peerLabel(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.String()
	}
	return addr
}

// recordRouterReady sets routerReady from router's Ready condition.
func recordRouterReady(router *bgpv1alpha1.BGPRouter) {
	v := 0.0
	if meta.IsStatusConditionPresentAndEqual(router.Status.Conditions, ConditionReady, metav1.ConditionTrue) {
		v = 1
	}
	routerReady.WithLabelValues(types.NamespacedName{Namespace: router.Namespace, Name: router.Name}.String()).Set(v)
}

// recordPeerStates sets peerEstablished for every peer in rs and deletes the
// series of peers router's runtime no longer holds.
//
// An unhealthy runtime lists no peers because its BGP server is not running,
// not because the peers were removed, so it sets every peer already exported
// to 0 rather than deleting their series and silencing the alerts on them.
func recordPeerStates(key types.NamespacedName, rs model.RuntimeStatus) {
	router := key.String()
	if !rs.Healthy {
		exportedPeersMu.Lock()
		defer exportedPeersMu.Unlock()
		for addr := range exportedPeers[router] {
			peerEstablished.WithLabelValues(router, addr).Set(0)
		}
		return
	}
	current := make(map[string]struct{}, len(rs.Peers))
	for _, ps := range rs.Peers {
		addr := peerLabel(ps.Address)
		current[addr] = struct{}{}
		v := 0.0
		if ps.SessionState == model.BGPPeerStateEstablished {
			v = 1
		}
		peerEstablished.WithLabelValues(router, addr).Set(v)
	}

	exportedPeersMu.Lock()
	defer exportedPeersMu.Unlock()
	for addr := range exportedPeers[router] {
		if _, ok := current[addr]; !ok {
			peerEstablished.DeleteLabelValues(router, addr)
		}
	}
	if len(current) == 0 {
		delete(exportedPeers, router)
		return
	}
	exportedPeers[router] = current
}

// forgetRouterMetrics deletes every series exported for key, once its runtime
// has stopped.
func forgetRouterMetrics(key types.NamespacedName) {
	router := key.String()
	routerReady.DeleteLabelValues(router)
	peerEstablished.DeletePartialMatch(prometheus.Labels{labelRouter: router})
	exportedPeersMu.Lock()
	delete(exportedPeers, router)
	exportedPeersMu.Unlock()
}
