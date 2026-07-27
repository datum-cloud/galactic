// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package model defines the internal desired-state and runtime-status types
// that decouple the BGP CRD API from the BGP runtime backends.
package model

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Re-export BGP API enum types for use throughout galactic-router.
type (
	AddressFamily      = bgpv1alpha1.AddressFamily
	BGPPolicyDirection = bgpv1alpha1.BGPPolicyDirection
	BGPPolicyAction    = bgpv1alpha1.BGPPolicyAction
	BGPPeerState       = bgpv1alpha1.BGPPeerState
)

// Re-export BGP API constants.
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
// from one BGPRouter and all of its associated peers, VRF instances, advertisements, and policies.
type DesiredRouter struct {
	Namespace       string
	Name            string
	LocalASN        int64
	RouterID        string
	AddressFamilies []AddressFamily
	Peers           []DesiredPeer
	VRFInstances    []DesiredVRFInstance
	Advertisements  []DesiredAdvertisement
	Policies        []DesiredPolicy
}

// DesiredPeer describes a single BGP session to configure.
type DesiredPeer struct {
	Name            string
	PeerASN         int64
	Address         string
	RemotePort      int32
	AddressFamilies []AddressFamily
	HoldTime        time.Duration
	KeepaliveTime   time.Duration
	AuthPassword    string
}

// DesiredVRFInstance describes an L2VPN EVPN VRF to configure on the BGP router.
type DesiredVRFInstance struct {
	Name string
	// VRFID is the 16-bit PoP-local VRF identifier (BGPVRFInstanceSpec.VRFID).
	// The runtime derives the RFC 4364 Type 1 route distinguisher from it as
	// "routerID:vrfID".
	VRFID              int32
	ImportRouteTargets []string
	ExportRouteTargets []string
}

// DesiredAdvertisement describes a set of prefixes to originate.
type DesiredAdvertisement struct {
	Name            string
	AddressFamily   AddressFamily
	Prefixes        []string
	Communities     []string
	LocalPreference *uint32
	// NextHop is the BGP next-hop address placed in MpReachNLRI (node's transit-reachable
	// IPv6 address). Required when AddressFamily is l2vpn/evpn.
	NextHop string
	// SRv6SID, when set, is placed in the EVPN Type 5 GWIPAddress field instead of NextHop.
	// Must be the End.DT46 SID for this VPC attachment so that receiving nodes install
	// a seg6 encap route targeting the correct SRv6 decap instruction.
	SRv6SID string
	// VRFID is the 16-bit PoP-local VRF identifier carried from the BGPAdvertisement
	// spec. The runtime derives the per-VRF route distinguisher as "routerID:vrfID" so
	// that advertisements from different VRFs on the same router produce distinct NLRIs.
	// When nil, the legacy "routerID:0" fallback is used.
	VRFID *int32
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
