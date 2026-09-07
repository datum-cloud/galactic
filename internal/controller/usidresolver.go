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

// backendSIDIndex resolves a NetworkRule backend's address to the SRv6 uSID of
// the worker node it is reachable through, by listing BGPAdvertisement,
// BGPRouter, and BGPVRFInstance CRDs and matching by prefix containment, then
// confirming tenant ownership of the match before trusting it.
//
// No exported "address to uSID" query exists in this codebase: the router
// decodes EVPN attributes internally, only to drive local route installation.
// Rather than add a second BGP speaker, this mirrors the reconciler's own SID
// resolution, combining a matching advertisement's VRFID and function with its
// router's locator and node ID. The CNI publish path is the producer side of
// exactly that data, one advertisement per attachment's pod subnets with both
// fields always set, so every backend address a rule could name is covered by
// the same CRDs.
//
// Tenant ownership, not address containment alone, is what makes a match
// trustworthy. BGPAdvertisement carries no tenant reference of its own, so two
// tenants advertising overlapping address space would otherwise resolve to
// whichever advertisement the list returned first, routing a packet into the
// wrong tenant's VRF rather than merely picking ambiguously. The check costs no
// new CRD field: a tenant's BGPVRFInstance already has a deterministic name, so
// a candidate's (router, VRFID) pair can be cross-checked against the one
// instance the calling rule's tenant owns on that router's node.
type backendSIDIndex struct {
	routers      map[string]*bgpv1alpha1.BGPRouter
	advs         []*bgpv1alpha1.BGPAdvertisement
	vrfInstances map[string]*bgpv1alpha1.BGPVRFInstance // keyed by name: crdnames.BGPVRFInstanceName(vpc, nodeName)
}

// buildBackendSIDIndex lists every BGPRouter, BGPAdvertisement, and
// BGPVRFInstance in namespace once, so resolving many backends across a
// reconcile costs one set of list calls rather than one per backend.
//
// Advertisements with no VRFID or function set are excluded up front: those
// carry no SRv6 decap behavior and can never be a backend's location.
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

// verifyTenantOwnership reports whether adv, matched against an address by
// prefix containment, actually belongs to vpcRef on router's node rather than
// to another tenant whose advertised prefix happens to contain that address
// too.
//
// A tenant's BGPVRFInstance is named deterministically, and its VRFID is what
// an advertisement's VRFID must equal for that advertisement to have been
// originated on the tenant's behalf on this node. A mismatch, or a missing
// instance, means the advertisement belongs to a different tenant sharing the
// node and possibly the prefix, so this fails closed.
func (idx *backendSIDIndex) verifyTenantOwnership(vpcRef string, router *bgpv1alpha1.BGPRouter, vrfID int32) bool {
	vrfName := crdnames.BGPVRFInstanceName(vpcRef, router.Spec.TargetRef.Name)
	vrf, ok := idx.vrfInstances[vrfName]
	return ok && vrf.Spec.VRFID == vrfID
}

// resolveUSID returns the SRv6 uSID of the worker node the backend address addr,
// belonging to vpcRef, is reachable through. vpcRef scopes the match to
// advertisements that tenant's own BGPVRFInstance owns: a prefix-containment hit
// alone is never sufficient, so two tenants with colliding address space cannot
// resolve into each other's VRF.
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
