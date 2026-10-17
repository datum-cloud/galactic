// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

// FRRObjectName is the name an object renders under in FRR: a route-map,
// prefix-list, community-list or peer group. The fleet's legacy names are
// letters, digits, '-' and '_'; '.' is also accepted.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9_.-]*$`
type FRRObjectName string

// LocalObjectRef references an object of the kind the field names, in the
// referrer's namespace.
type LocalObjectRef struct {
	// Name is the referenced object's name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// FRRNameOverride sets the name an object renders under in FRR. When unset
// the object's metadata.name is used.
type FRRNameOverride struct {
	// Name is the FRR object name.
	// +optional
	Name *FRRObjectName `json:"name,omitempty"`
}

// BGPPeerTransport holds session transport settings shared by a peer and its
// profile. A field set on a BGPPeer overrides the same field on its profile.
type BGPPeerTransport struct {
	// EBGPMultihopTTL allows an eBGP session over up to this many hops.
	// Unset renders no multihop line.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	EBGPMultihopTTL *int32 `json:"ebgpMultihopTTL,omitempty"`

	// AdvertisementIntervalSeconds is the minimum interval between UPDATE
	// messages. Unset leaves the implementation's default.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=600
	AdvertisementIntervalSeconds *int32 `json:"advertisementIntervalSeconds,omitempty"`
}

// BGPPrefixLimitAction is what a session does once a family's received
// prefixes exceed the limit.
//
// +kubebuilder:validation:Enum=WarnOnly;Restart;Shutdown
type BGPPrefixLimitAction string

const (
	// BGPPrefixLimitWarnOnly logs and keeps the session up.
	BGPPrefixLimitWarnOnly BGPPrefixLimitAction = "WarnOnly"
	// BGPPrefixLimitRestart shuts the session down and restarts it after
	// restartMinutes.
	BGPPrefixLimitRestart BGPPrefixLimitAction = "Restart"
	// BGPPrefixLimitShutdown shuts the session down until it is cleared.
	BGPPrefixLimitShutdown BGPPrefixLimitAction = "Shutdown"
)

// BGPPrefixLimit bounds the prefixes a peer may send in one family.
//
// +kubebuilder:validation:XValidation:rule="(self.action == 'Restart') == has(self.restartMinutes)",message="restartMinutes is required with, and only with, action Restart"
type BGPPrefixLimit struct {
	// Maximum is the number of prefixes accepted before the action applies.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	Maximum int64 `json:"maximum"`

	// WarningThresholdPercent logs a warning once received prefixes reach
	// this share of maximum.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	WarningThresholdPercent *int32 `json:"warningThresholdPercent,omitempty"`

	// Action is what happens once maximum is exceeded.
	Action BGPPrefixLimitAction `json:"action"`

	// RestartMinutes is the delay before a Restart action re-establishes
	// the session.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	RestartMinutes *int32 `json:"restartMinutes,omitempty"`
}

// BGPNextHopMode controls the next hop a peer family advertises.
//
// +kubebuilder:validation:Enum=Unchanged;Self;SelfForce
type BGPNextHopMode string

const (
	// BGPNextHopUnchanged keeps the implementation's default next hop.
	BGPNextHopUnchanged BGPNextHopMode = "Unchanged"
	// BGPNextHopSelf rewrites the next hop to the local session address.
	BGPNextHopSelf BGPNextHopMode = "Self"
	// BGPNextHopSelfForce rewrites the next hop to the local session
	// address on reflected routes too, which Self leaves unchanged.
	BGPNextHopSelfForce BGPNextHopMode = "SelfForce"
)

// FRRPeerFamilySettings holds FRR-specific peer family settings with no
// implementation-neutral equivalent.
type FRRPeerFamilySettings struct {
	// Weight is FRR's local, non-propagated path preference for routes
	// learned from the peer. It is not LOCAL_PREF.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Weight *int32 `json:"weight,omitempty"`
}

// BGPPeerFamilySettings holds one address family's session settings for a
// peer or a peer profile. Every field is optional: on a peer, an unset field
// falls through to the profile's setting for the same family.
//
// +kubebuilder:validation:XValidation:rule="self.afi == 'ipv4' ? self.safi == 'unicast' : true",message="IPv4 only supports unicast SAFI"
// +kubebuilder:validation:XValidation:rule="self.afi == 'ipv6' ? self.safi == 'unicast' : true",message="IPv6 only supports unicast SAFI"
// +kubebuilder:validation:XValidation:rule="self.afi == 'l2vpn' ? self.safi == 'evpn' : true",message="L2VPN only supports evpn SAFI"
type BGPPeerFamilySettings struct {
	// AFI is the address family indicator.
	AFI AFI `json:"afi"`

	// SAFI is the subsequent address family indicator.
	SAFI SAFI `json:"safi"`

	// SoftReconfigurationInbound keeps a copy of the routes received from
	// the peer, so an import policy change applies without a refresh.
	// +optional
	SoftReconfigurationInbound *bool `json:"softReconfigurationInbound,omitempty"`

	// PrefixLimit bounds the prefixes the peer may send in this family.
	// +optional
	PrefixLimit *BGPPrefixLimit `json:"prefixLimit,omitempty"`

	// SendCommunity restricts the community attributes sent to the peer to
	// the named ones. Unset sends every community attribute, the pinned
	// FRR's default.
	// +optional
	SendCommunity *SendCommunityType `json:"sendCommunity,omitempty"`

	// AllowASIn accepts routes whose AS path holds the local ASN up to this
	// many times.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	AllowASIn *int32 `json:"allowASIn,omitempty"`

	// ImportPolicyRef names the BGPPolicy applied to routes received from
	// the peer in this family.
	// +optional
	ImportPolicyRef *LocalObjectRef `json:"importPolicyRef,omitempty"`

	// ExportPolicyRef names the BGPPolicy applied to routes sent to the peer
	// in this family. A fabric peer family must resolve one: there is no
	// implicit export-everything default.
	// +optional
	ExportPolicyRef *LocalObjectRef `json:"exportPolicyRef,omitempty"`

	// NextHopMode controls the advertised next hop.
	// +optional
	NextHopMode *BGPNextHopMode `json:"nextHopMode,omitempty"`

	// RouteReflectorClient treats the peer as a route-reflector client in
	// this family.
	// +optional
	RouteReflectorClient *bool `json:"routeReflectorClient,omitempty"`

	// FRR holds FRR-specific settings.
	// +optional
	FRR *FRRPeerFamilySettings `json:"frr,omitempty"`
}
