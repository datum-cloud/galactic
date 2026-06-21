// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package model defines the internal desired-state and runtime-status types
// that decouple the Cosmos CRD API from the BGP runtime backends.
package model

import (
	"time"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Re-export cosmos enum types for use throughout galactic-router.
type (
	AddressFamily      = bgpv1alpha1.AddressFamily
	BGPPolicyDirection = bgpv1alpha1.BGPPolicyDirection
	BGPPolicyAction    = bgpv1alpha1.BGPPolicyAction
	BGPPeerState       = bgpv1alpha1.BGPPeerState
)

// Re-export cosmos constants.
const (
	BGPPolicyDirectionImport = bgpv1alpha1.BGPPolicyDirectionImport
	BGPPolicyDirectionExport = bgpv1alpha1.BGPPolicyDirectionExport
	BGPPolicyActionPermit    = bgpv1alpha1.BGPPolicyActionPermit
	BGPPolicyActionDeny      = bgpv1alpha1.BGPPolicyActionDeny
	BGPPeerStateIdle         = bgpv1alpha1.BGPPeerStateIdle
	BGPPeerStateConnect      = bgpv1alpha1.BGPPeerStateConnect
	BGPPeerStateActive       = bgpv1alpha1.BGPPeerStateActive
	BGPPeerStateOpenSent     = bgpv1alpha1.BGPPeerStateOpenSent
	BGPPeerStateOpenConfirm  = bgpv1alpha1.BGPPeerStateOpenConfirm
	BGPPeerStateEstablished  = bgpv1alpha1.BGPPeerStateEstablished
)

// DesiredRouter is the full desired state of a BGP router instance, assembled
// from one BGPRouter and all of its associated peers, advertisements, and policies.
type DesiredRouter struct {
	Namespace       string
	Name            string
	LocalASN        uint32
	RouterID        string
	AddressFamilies []AddressFamily
	Peers           []DesiredPeer
	Advertisements  []DesiredAdvertisement
	Policies        []DesiredPolicy
}

// DesiredPeer describes a single BGP session to configure.
type DesiredPeer struct {
	Name            string
	PeerASN         uint32
	Address         string
	AddressFamilies []AddressFamily
	HoldTime        time.Duration
	KeepaliveTime   time.Duration
	AuthPassword    string
}

// DesiredAdvertisement describes a set of prefixes to originate.
type DesiredAdvertisement struct {
	Name            string
	AddressFamily   AddressFamily
	Prefixes        []string
	Communities     []string
	LocalPreference *uint32
	// NextHop is the BGP next-hop for EVPN advertisements (node's primary IPv6 addr).
	// Required when AddressFamily is l2vpn/evpn; rejection occurs in GoBGP backend if empty.
	NextHop string
}

// DesiredPolicy describes a routing policy in one direction.
type DesiredPolicy struct {
	Name      string
	Direction BGPPolicyDirection
	Terms     []DesiredPolicyTerm
}

// DesiredPolicyTerm is a single ordered statement within a policy.
type DesiredPolicyTerm struct {
	Sequence int32
	Match    DesiredPolicyMatch
	Action   BGPPolicyAction
	Set      *DesiredPolicySetActions // nil when Action is deny
}

// DesiredPolicyMatch defines conditions under which a term fires.
type DesiredPolicyMatch struct {
	Any             bool
	AddressFamilies []AddressFamily
}

// DesiredPolicySetActions defines mutations applied when a permit term matches.
type DesiredPolicySetActions struct {
	CommunitiesAdd    []string
	CommunitiesRemove []string
	LocalPreference   *uint32
}

// RuntimeStatus is the observed state returned by RouterRuntime.Status.
type RuntimeStatus struct {
	Healthy        bool
	Peers          []PeerStatus
	Advertisements []AdvertisementStatus
}

// PeerStatus holds the observed state of a single BGP peer session.
type PeerStatus struct {
	Name                string
	Address             string
	SessionState        BGPPeerState
	LastEstablishedTime *metav1.Time
}

// AdvertisementStatus holds the observed state of a single advertisement.
type AdvertisementStatus struct {
	Name               string
	AdvertisedPrefixes int32
}
