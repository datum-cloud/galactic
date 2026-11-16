// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nodevpc creates the state one VPC needs on one node before the node
// can carry its traffic: the canonical host VRF, the node's BGPVRFInstance for
// the VPC with its uSID Argument, and the eBPF vrf_table row that delivers
// SRv6 traffic for that Argument into the VRF.
//
// CNI ADD creates that state for a workload, and galactic-edge creates it for
// an attachment on a node where the VPC has no workload. Both take the same
// node locks, so each reuses what the other made. Neither removes it:
// galactic-router GC does, once nothing on the node uses the VPC.
package nodevpc

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Router is the BGP identity of a node's Galactic-owned BGPRouter.
type Router struct {
	Name        string
	ASN         uint32
	SRv6Locator string
	NodeID      int32
}

// LookupRouter finds the Galactic-owned BGPRouter (one with no
// routerClassName) targeting nodeName in namespace. It returns an error if
// none is found or if several are (ambiguous).
func LookupRouter(ctx context.Context, k8s client.Client, nodeName, namespace string) (Router, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routerList, client.InNamespace(namespace)); err != nil {
		return Router{}, fmt.Errorf("list BGPRouters in namespace %s: %w", namespace, err)
	}

	var matches []bgpv1alpha1.BGPRouter
	for _, r := range bgpv1alpha1.LegacyOwnedRouters(routerList.Items) {
		if r.Spec.TargetRef.Name == nodeName {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 0:
		return Router{}, fmt.Errorf("no BGPRouter found for node %s in namespace %s", nodeName, namespace)
	case 1:
	default:
		return Router{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(matches), nodeName, namespace)
	}

	slog.Debug("BGP: router matched", "nodeName", nodeName, "router", matches[0].Name,
		"asNumber", matches[0].Spec.LocalASN, "srv6Locator", matches[0].Spec.SRv6Locator, "nodeID", matches[0].Spec.NodeID)

	return Router{
		Name:        matches[0].Name,
		ASN:         uint32(matches[0].Spec.LocalASN),
		SRv6Locator: matches[0].Spec.SRv6Locator,
		NodeID:      matches[0].Spec.NodeID,
	}, nil
}

// RouteTarget returns the route target in "ASN:NN" form, from the low 32 bits
// of the hex VPC identifier vpcHex. Every node in the same VRF derives the
// same value, which is what scopes route import and export to a VPC.
func RouteTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// InstanceSpec returns the BGPVRFInstanceSpec of a VPC on a node: the node's
// router, the VPC's Argument on it, and the VPC's route target for import and
// export.
func InstanceSpec(routerName, rtValue string, vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec {
	return bgpv1alpha1.BGPVRFInstanceSpec{
		RouterTarget: bgpv1alpha1.RouterTarget{
			RouterRef: &bgpv1alpha1.RouterRef{Name: routerName},
		},
		VRFID:              vrfID,
		ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
		ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
	}
}
