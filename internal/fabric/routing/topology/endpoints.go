// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package topology generates fabric routers' BGPPeers from FabricEndpoint
// records and FabricTopology relationships. Analyze decides which endpoints
// are usable, Generate turns a topology and those endpoints into the peers
// it wants, and the reconcilers write them, keep the ones a removal has not
// yet released, and report status. The functions here are pure: the same
// objects always give the same peers, in the same order, with the same
// names.
package topology

import (
	"fmt"
	"net/netip"
	"sort"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// EndpointState is one endpoint as this cell sees it.
type EndpointState struct {
	Endpoint *networkv1alpha1.FabricEndpoint

	// Local is true when a topology in the namespace generates for the
	// endpoint's cell, so its router should exist here.
	Local bool

	// Usable is true when topologies may peer over the endpoint.
	Usable bool

	// ReadyReason and ReadyMessage explain Usable.
	ReadyReason, ReadyMessage string

	// ConflictReason and ConflictMessage are set when another endpoint
	// holds this one's identity or an address.
	ConflictReason, ConflictMessage string

	// IPv4 and IPv6 are the parsed addresses; invalid ones are not set.
	IPv4, IPv6 netip.Addr
}

// Address is the endpoint's address in family f, if it has one.
func (s *EndpointState) Address(f networkv1alpha1.FabricSessionFamily) (netip.Addr, bool) {
	a := s.IPv4
	if f == networkv1alpha1.FabricSessionFamilyIPv6 {
		a = s.IPv6
	}
	return a, a.IsValid()
}

// Analyze evaluates every endpoint of one namespace. localCells are the
// cells a topology in the namespace generates for; routers are the
// namespace's BGPRouters by name.
//
// Of two endpoints for the same router on the same transport, or holding
// one address on the same transport of a routing domain, the one whose name
// sorts first keeps it and the other is in conflict and unusable. Every cell
// holding the same records picks the same winner, whatever order its copies
// were created in.
func Analyze(
	endpoints []networkv1alpha1.FabricEndpoint, localCells map[string]bool,
	routers map[string]*networkv1alpha1.BGPRouter,
) map[string]*EndpointState {
	ordered := make([]*networkv1alpha1.FabricEndpoint, 0, len(endpoints))
	for i := range endpoints {
		ordered = append(ordered, &endpoints[i])
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })

	type identity struct{ domain, cell, router, transport string }
	type claim struct {
		domain, transport string
		addr              netip.Addr
	}
	identities := map[identity]string{}
	addresses := map[claim]string{}
	out := make(map[string]*EndpointState, len(ordered))
	for _, ep := range ordered {
		s := &EndpointState{Endpoint: ep, Local: localCells[ep.Spec.Cell]}
		s.IPv4 = parse(ep.Spec.Addresses.IPv4, true)
		s.IPv6 = parse(ep.Spec.Addresses.IPv6, false)
		out[ep.Name] = s

		id := identity{ep.Spec.RoutingDomain, ep.Spec.Cell, ep.Spec.RouterRef.Name, ep.Spec.Transport}
		if holder, taken := identities[id]; taken {
			s.ConflictReason = networkv1alpha1.FabricEndpointReasonDuplicate
			s.ConflictMessage = fmt.Sprintf("FabricEndpoint %s already places router %s of cell %s on transport %s",
				holder, ep.Spec.RouterRef.Name, ep.Spec.Cell, ep.Spec.Transport)
			continue
		}
		identities[id] = ep.Name
		for _, a := range []netip.Addr{s.IPv4, s.IPv6} {
			if !a.IsValid() {
				continue
			}
			c := claim{ep.Spec.RoutingDomain, ep.Spec.Transport, a}
			if holder, taken := addresses[c]; taken && s.ConflictReason == "" {
				s.ConflictReason = networkv1alpha1.FabricEndpointReasonAddressInUse
				s.ConflictMessage = fmt.Sprintf("FabricEndpoint %s already holds %s on transport %s",
					holder, a, ep.Spec.Transport)
			}
		}
		if s.ConflictReason != "" {
			continue
		}
		for _, a := range []netip.Addr{s.IPv4, s.IPv6} {
			if a.IsValid() {
				addresses[claim{ep.Spec.RoutingDomain, ep.Spec.Transport, a}] = ep.Name
			}
		}
	}
	for _, s := range out {
		s.Usable, s.ReadyReason, s.ReadyMessage = readiness(s, routers)
	}
	return out
}

// readiness decides whether an endpoint may be peered over, and why.
func readiness(s *EndpointState, routers map[string]*networkv1alpha1.BGPRouter) (bool, string, string) {
	ep := s.Endpoint
	switch {
	case s.ConflictReason != "":
		return false, s.ConflictReason, s.ConflictMessage
	case ep.Spec.Interface != nil:
		return false, networkv1alpha1.FabricEndpointReasonInterfaceUnsupported,
			"sessions over an interface are not generated yet"
	case !s.Local:
		return true, networkv1alpha1.FabricEndpointReasonRemote,
			"router of cell " + ep.Spec.Cell + ", known here through this record"
	}
	router := routers[ep.Spec.RouterRef.Name]
	switch {
	case router == nil:
		return false, networkv1alpha1.FabricEndpointReasonRouterNotFound,
			"BGPRouter " + ep.Spec.RouterRef.Name + " does not exist"
	case router.Spec.LocalASN != ep.Spec.ASN:
		return false, networkv1alpha1.FabricEndpointReasonASNMismatch,
			fmt.Sprintf("asn %d differs from BGPRouter %s's localASN %d", ep.Spec.ASN, router.Name, router.Spec.LocalASN)
	}
	return true, networkv1alpha1.FabricEndpointReasonLocal, "router " + router.Name + " runs in this cell"
}

func parse(s *string, v4 bool) netip.Addr {
	if s == nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(*s)
	if err != nil || a.Is4() != v4 {
		return netip.Addr{}
	}
	return a
}
