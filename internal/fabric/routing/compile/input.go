// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package compile turns one fabric BGPRouter and the objects it references
// into the FRR configuration that router runs. It is a pure function of its
// input: no API reads, no clock, no randomness, so the same input always
// yields the same text and digest. Resolution (reading the objects) and
// activation (applying the text) live elsewhere.
package compile

import (
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Input is everything one router's configuration depends on. Maps are keyed
// by metadata.name in the router's namespace. A reference to a name missing
// from its map is an unresolved dependency, never "no filter".
type Input struct {
	// Router is the fabric router being compiled.
	Router *networkv1alpha1.BGPRouter

	// Class is the router's BGPRouterClass.
	Class *networkv1alpha1.BGPRouterClass

	// Parameters is the class's FRRRouterParameters.
	Parameters *networkv1alpha1.FRRRouterParameters

	// Peers are the BGPPeers whose routerRef names Router.
	Peers []networkv1alpha1.BGPPeer

	// Advertisements are the BGPAdvertisements whose routerRef names Router.
	Advertisements []networkv1alpha1.BGPAdvertisement

	// StaticRoutes are the BGPStaticRoutes whose routerRef names Router.
	StaticRoutes []networkv1alpha1.BGPStaticRoute

	// Profiles, Policies, PrefixLists and CommunitySets hold the objects
	// available for reference.
	Profiles      map[string]*networkv1alpha1.BGPPeerProfile
	Policies      map[string]*networkv1alpha1.BGPPolicy
	PrefixLists   map[string]*networkv1alpha1.BGPPrefixList
	CommunitySets map[string]*networkv1alpha1.BGPCommunitySet
}
