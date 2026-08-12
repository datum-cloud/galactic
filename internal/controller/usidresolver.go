// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// backendSIDIndex resolves a NetworkRule backend's address to the SRv6 uSID
// of the worker node it is reachable through, by listing BGPAdvertisement
// and BGPRouter CRDs directly and matching by prefix containment.
//
// This is a genuinely new problem an earlier, rejected design never
// had to solve: that design tunneled every rule's traffic to a static
// per-tenant Geneve peer, so it never needed to know which worker node any
// individual backend Pod actually lived on. This design pushes an SRv6
// outer header addressed to that worker node directly (design plan
// decision #5), so it must resolve one.
//
// There is no exported "IP -> uSID" query anywhere in this codebase today
// (internal/runtime/gobgp/monitor.go decodes EVPN Prefix-SID attributes
// purely internally, only to drive local kernel route installation).
// Rather than embed a second GoBGP speaker or add one, this mirrors
// internal/reconcile/reconcile.go's resolveSRv6SID: combine a matching
// BGPAdvertisement's VRFID/Function with its BGPRouter's SRv6Locator/NodeID
// via srv6.ComputeSID. internal/cnibgp/bgp.go's buildAdvertisementSpec is
// the producer side of that same data — one BGPAdvertisement per VPC
// attachment's pod subnet(s), VRFID/Function always set — so every backend
// Pod address a NetworkRule could plausibly name is covered by exactly the
// same CRDs this reads.
//
// Known limitation: matching is by address containment only, with no
// tenant-identity check, because BGPAdvertisement carries no VPCRef/
// VPCAttachmentRef field to disambiguate against (neither does
// resolveSRv6SID's own matching, which is scoped by the caller already
// holding the specific BGPAdvertisement in hand). Two different tenants
// advertising overlapping private address space would resolve
// ambiguously here. This is a pre-existing gap in the address model, not
// one this resolver introduces, and is out of scope to close in this
// phase.
type backendSIDIndex struct {
	routers map[string]*bgpv1alpha1.BGPRouter
	advs    []*bgpv1alpha1.BGPAdvertisement
}

// buildBackendSIDIndex lists every BGPRouter and BGPAdvertisement in
// namespace once, so resolving N backends across a reconcile costs one pair
// of List calls rather than N. Advertisements with no VRFID/Function set
// are excluded up front — those carry no SRv6 decap behavior of their own
// (see NetworkGatewayReconciler's own VIP-preference advertisements, which
// are exactly that shape) and can never be a backend's location.
func buildBackendSIDIndex(ctx context.Context, c client.Client, namespace string) (*backendSIDIndex, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := c.List(ctx, routerList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRouters: %w", err)
	}
	routers := make(map[string]*bgpv1alpha1.BGPRouter, len(routerList.Items))
	for i := range routerList.Items {
		routers[routerList.Items[i].Name] = &routerList.Items[i]
	}

	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}
	advs := make([]*bgpv1alpha1.BGPAdvertisement, 0, len(advList.Items))
	for i := range advList.Items {
		if advList.Items[i].Spec.VRFID == nil || advList.Items[i].Spec.Function == nil {
			continue
		}
		advs = append(advs, &advList.Items[i])
	}

	return &backendSIDIndex{routers: routers, advs: advs}, nil
}

// resolveUSID returns the SRv6 uSID of the worker node addr (a backend
// Pod's address) is reachable through, per the matching strategy documented
// on backendSIDIndex.
func (idx *backendSIDIndex) resolveUSID(addr netip.Addr) (netip.Addr, error) {
	for _, adv := range idx.advs {
		for _, p := range adv.Spec.Prefixes {
			prefix, err := netip.ParsePrefix(string(p))
			if err != nil {
				continue // malformed prefix; not this resolver's job to validate
			}
			if !prefix.Contains(addr) {
				continue
			}
			router, ok := idx.routers[adv.Spec.RouterRef.Name]
			if !ok || router.Spec.SRv6Locator == "" || router.Spec.NodeID == 0 {
				continue
			}
			sid, err := srv6.ComputeSID(router.Spec.SRv6Locator, router.Spec.NodeID, *adv.Spec.VRFID, *adv.Spec.Function)
			if err != nil {
				return netip.Addr{}, fmt.Errorf(
					"compute SRv6 uSID for backend %s via BGPAdvertisement %s/BGPRouter %s: %w",
					addr, adv.Name, router.Name, err)
			}
			return sid, nil
		}
	}
	return netip.Addr{}, fmt.Errorf(
		"no BGPAdvertisement with a matching prefix and SRv6 VRFID/Function found for backend address %s", addr)
}
