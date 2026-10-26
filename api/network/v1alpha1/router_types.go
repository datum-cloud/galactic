package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BGPRouterPhase describes the lifecycle phase of a BGPRouter.
type BGPRouterPhase string

const (
	BGPRouterPhasePending BGPRouterPhase = "Pending"
	BGPRouterPhaseReady   BGPRouterPhase = "Ready"
	BGPRouterPhaseFailed  BGPRouterPhase = "Failed"
)

// BGPRouter defines a logical BGP routing context. It abstracts a processing
// instance bound to a specific execution context (e.g., a VRF or network
// namespace) on a target node and acts as the primary ownership boundary for
// BGPPeer, BGPAdvertisement, and BGPPolicy resources.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpr
// +kubebuilder:printcolumn:name="TARGET",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="ASN",type="integer",JSONPath=".spec.localASN"
// +kubebuilder:printcolumn:name="ROUTER-ID",type="string",JSONPath=".spec.routerID"
// +kubebuilder:printcolumn:name="PHASE",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPRouter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPRouterSpec   `json:"spec,omitempty"`
	Status BGPRouterStatus `json:"status,omitempty"`
}

// BGPRoutingPlane names which routing plane a BGPRouter belongs to.
//
// +kubebuilder:validation:Enum=Underlay;Overlay
type BGPRoutingPlane string

const (
	// BGPRoutingPlaneUnderlay is the fabric underlay that carries the
	// overlay's sessions and SRv6 locators between nodes.
	BGPRoutingPlaneUnderlay BGPRoutingPlane = "Underlay"

	// BGPRoutingPlaneOverlay is the tenant EVPN overlay.
	BGPRoutingPlaneOverlay BGPRoutingPlane = "Overlay"
)

// BGPRouterSpec defines the desired state of a BGPRouter.
//
// +kubebuilder:validation:XValidation:rule="has(self.routerClassName) == has(oldSelf.routerClassName) && (!has(self.routerClassName) || self.routerClassName == oldSelf.routerClassName)",message="routerClassName is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.plane) == has(oldSelf.plane) && (!has(self.plane) || self.plane == oldSelf.plane)",message="plane is immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.plane) || self.plane != 'Underlay' || has(self.routerClassName)",message="an Underlay router must name a routerClassName"
// +kubebuilder:validation:XValidation:rule="!has(self.frr) || has(self.routerClassName)",message="frr settings apply only to a router that names a routerClassName"
type BGPRouterSpec struct {
	// RouterClassName names the BGPRouterClass whose controller owns this
	// router. A router without one is owned by the Galactic EVPN
	// implementation (galactic-router and its related controllers). A
	// router naming a class is ignored by every component except that
	// class's controller, and by every component when the class does not
	// exist. Immutable.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	RouterClassName *string `json:"routerClassName,omitempty"`

	// Plane is the routing plane this router belongs to. Unset means the
	// tenant EVPN overlay. Underlay requires a routerClassName. Immutable.
	// +optional
	Plane *BGPRoutingPlane `json:"plane,omitempty"`

	// FRR holds settings for routers whose class is implemented with FRR.
	// +optional
	FRR *BGPRouterFRR `json:"frr,omitempty"`

	// TargetRef identifies the Node this router executes on.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// LocalASN is the BGP Autonomous System Number for this router.
	// Must be a valid 2-byte or 4-byte ASN per RFC 6793.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN int64 `json:"localASN"`

	// RouterID is a unique 32-bit identifier expressed in IPv4 dotted-decimal notation.
	// In an IPv6-only underlay this is a logical identifier only.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv4
	RouterID string `json:"routerID"`

	// AddressFamilies defines the address families this router activates.
	// +kubebuilder:validation:MinItems=1
	AddressFamilies []AddressFamily `json:"addressFamilies"`

	// SRv6Locator is the SRv6 locator block this router owns, expressed as an
	// IPv6 CIDR (e.g. "2001:db8:ff01::/48"). Individual SRv6 endpoint SIDs are
	// host addresses within this block.
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="srv6Locator must be a valid CIDR"
	// +kubebuilder:validation:XValidation:rule="self.contains(':')",message="srv6Locator must be an IPv6 CIDR"
	// +optional
	SRv6Locator string `json:"srv6Locator,omitempty"`

	// NodeID is this router's 16-bit slot within its PoP's SRv6Locator block,
	// used for RFC 9800 NEXT-CSID compression. Unique within the PoP.
	// The uSID carrier format reserves 0x0000 and 0xE000-0xFFFF (the latter is
	// Function space, not Node-ID space), leaving 0x0001-0xDFFF assignable.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=57343
	// +optional
	NodeID int32 `json:"nodeID,omitempty"`

	// ListenPort is the TCP port this router listens on for incoming BGP
	// peer connections. Defaults to 179 (the IANA-assigned BGP port) if unset.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ListenPort *int32 `json:"listenPort,omitempty"`
}

// BGPRouterStatus defines the observed state of a BGPRouter.
type BGPRouterStatus struct {
	// SupportsAdvertisementLeases reports independent expiry enforcement by the router.
	// Consumers must also require current observedGeneration and a healthy router.
	// +optional
	SupportsAdvertisementLeases bool `json:"supportsAdvertisementLeases,omitempty"`
	// LastSuccessfulReconcileTime is the last healthy apply or verified no-op reconciliation.
	// +optional
	LastSuccessfulReconcileTime *metav1.Time `json:"lastSuccessfulReconcileTime,omitempty"`

	// Phase is the high-level lifecycle state of this router.
	// +optional
	Phase BGPRouterPhase `json:"phase,omitempty"`

	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Peers summarizes peer session counts.
	// +optional
	Peers BGPRouterPeerSummary `json:"peers,omitempty"`

	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Fabric is the fabric router controller's view of a classed router.
	// Unset on routers the Galactic EVPN implementation owns.
	// +optional
	Fabric *BGPRouterFabricStatus `json:"fabric,omitempty"`
}

// BGPRouterPeerSummary summarizes BGP peer session counts.
type BGPRouterPeerSummary struct {
	// Total is the total number of configured peers.
	Total int32 `json:"total"`

	// Established is the count of peers currently in the Established state.
	Established int32 `json:"established"`
}

// BGPRouterList is a list of BGPRouter resources.
// +kubebuilder:object:root=true
type BGPRouterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPRouter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPRouter{}, &BGPRouterList{})
}

// BGPRouterFRR holds FRR settings for one router.
type BGPRouterFRR struct {
	// RolloutPolicyRef names the FabricRolloutPolicy the rollout manager
	// applies to this router. Unset uses the policy defaults.
	// +optional
	RolloutPolicyRef *LocalObjectRef `json:"rolloutPolicyRef,omitempty"`

	// Retain lists definitions rendered on this router even when no peer
	// or advertisement references them, so a migrated router's first
	// configuration matches the one it replaces. Retained definitions never
	// create sessions or advertisements.
	// +optional
	Retain *BGPRouterFRRRetain `json:"retain,omitempty"`
}

// BGPRouterFRRRetain names definitions to render while unreferenced.
type BGPRouterFRRRetain struct {
	// PolicyRefs names BGPPolicies.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	PolicyRefs []LocalObjectRef `json:"policyRefs,omitempty"`

	// PrefixListRefs names BGPPrefixLists.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	PrefixListRefs []LocalObjectRef `json:"prefixListRefs,omitempty"`

	// CommunitySetRefs names BGPCommunitySets.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=512
	CommunitySetRefs []LocalObjectRef `json:"communitySetRefs,omitempty"`

	// PeerProfileRefs names BGPPeerProfiles.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	PeerProfileRefs []LocalObjectRef `json:"peerProfileRefs,omitempty"`
}

// BGPRouterFabricStatus is the fabric router controller's view of a router.
type BGPRouterFabricStatus struct {
	// LatestRevision is the newest FabricRouterRevision compiled for the
	// router's current inputs.
	// +optional
	LatestRevision string `json:"latestRevision,omitempty"`

	// ActivationDependencyDigest is that revision's digest.
	// +optional
	ActivationDependencyDigest string `json:"activationDependencyDigest,omitempty"`

	// RenderedDigest is the SHA-256 of the frr.conf that revision renders.
	// +optional
	RenderedDigest string `json:"renderedDigest,omitempty"`
}
