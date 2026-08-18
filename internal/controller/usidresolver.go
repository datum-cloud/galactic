// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// backendSIDIndex resolves a NetworkRule backend's address to the SRv6 uSID
// of the worker node it is reachable through, by listing BGPAdvertisement,
// BGPRouter, and BGPVRFInstance CRDs directly and matching by prefix
// containment — then confirming tenant ownership of the match (see
// verifyTenantOwnership) before trusting it.
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
// Tenant ownership, not address containment alone, is what makes a match
// trustworthy: BGPAdvertisement carries no VPCRef field of its own to
// disambiguate against, so two tenants advertising overlapping (e.g.
// colliding ULA) address space would otherwise resolve to whichever
// advertisement the list happened to return first — silently routing a
// packet into the wrong tenant's VRF, not just an ambiguous-but-harmless
// pick. verifyTenantOwnership closes this the same way NPTv6 and the NAT66
// shard tier resolve tenant identity elsewhere in this design: from VRF
// context, never from the address alone. It costs no new CRD field —
// crdnames.BGPVRFInstanceName(vpc, nodeName) is already the deterministic
// name galactic-bgp writes a tenant's own BGPVRFInstance under (see
// internal/cnibgp/bgp.go), so a candidate match's (router, VRFID) pair can
// be cross-checked directly against the one BGPVRFInstance the calling
// NetworkRule's own VPCRef actually owns on that router's node.
type backendSIDIndex struct {
	routers      map[string]*bgpv1alpha1.BGPRouter
	advs         []*bgpv1alpha1.BGPAdvertisement
	vrfInstances map[string]*bgpv1alpha1.BGPVRFInstance // keyed by name: crdnames.BGPVRFInstanceName(vpc, nodeName)
}

// buildBackendSIDIndex lists every BGPRouter, BGPAdvertisement, and
// BGPVRFInstance in namespace once, so resolving N backends across a
// reconcile costs one triple of List calls rather than N. Advertisements
// with no VRFID/Function set are excluded up front — those carry no SRv6
// decap behavior of their own (see NetworkGatewayReconciler's own
// VIP-preference advertisements, which are exactly that shape) and can
// never be a backend's location.
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

	vrfList := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := c.List(ctx, vrfList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPVRFInstances: %w", err)
	}
	vrfInstances := make(map[string]*bgpv1alpha1.BGPVRFInstance, len(vrfList.Items))
	for i := range vrfList.Items {
		vrfInstances[vrfList.Items[i].Name] = &vrfList.Items[i]
	}

	return &backendSIDIndex{routers: routers, advs: advs, vrfInstances: vrfInstances}, nil
}

// verifyTenantOwnership reports whether adv (matched against addr by prefix
// containment) actually belongs to vpcRef on router's own node, rather than
// to some other tenant whose advertised prefix happens to contain addr too.
//
// galactic-bgp names a tenant's BGPVRFInstance deterministically —
// crdnames.BGPVRFInstanceName(vpc, nodeName) — and that VRFID is what a
// BGPAdvertisement's own VRFID must equal for the advertisement to have
// been originated on vpcRef's behalf on this node. A mismatch (or a
// missing BGPVRFInstance altogether) means adv belongs to a different
// tenant that happens to share router's node and, for a colliding-ULA
// backend address, possibly the same prefix — fail closed rather than
// trust it.
func (idx *backendSIDIndex) verifyTenantOwnership(vpcRef string, router *bgpv1alpha1.BGPRouter, vrfID int32) bool {
	vrfName := crdnames.BGPVRFInstanceName(vpcRef, router.Spec.TargetRef.Name)
	vrf, ok := idx.vrfInstances[vrfName]
	return ok && vrf.Spec.VRFID == vrfID
}

// resolveUSID returns the SRv6 uSID of the worker node addr (a backend
// Pod's address, belonging to vpcRef) is reachable through, per the
// matching strategy documented on backendSIDIndex. vpcRef scopes the match
// to advertisements this specific tenant's own BGPVRFInstance actually
// owns (verifyTenantOwnership) — a prefix-containment hit alone is never
// sufficient, so two tenants with colliding backend address space can
// never resolve into each other's VRF.
func (idx *backendSIDIndex) resolveUSID(addr netip.Addr, vpcRef string) (netip.Addr, error) {
	for _, adv := range idx.advs {
		router, ok := idx.routers[adv.Spec.RouterRef.Name]
		if !ok || router.Spec.SRv6Locator == "" || router.Spec.NodeID == 0 {
			continue
		}
		if !idx.verifyTenantOwnership(vpcRef, router, *adv.Spec.VRFID) {
			continue // adv belongs to some other tenant on this node; never a candidate for vpcRef
		}
		for _, p := range adv.Spec.Prefixes {
			prefix, err := netip.ParsePrefix(string(p))
			if err != nil {
				continue // malformed prefix; not this resolver's job to validate
			}
			if !prefix.Contains(addr) {
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
		"no BGPAdvertisement owned by VPC %s with a matching prefix and SRv6 VRFID/Function found for backend address %s",
		vpcRef, addr)
}
