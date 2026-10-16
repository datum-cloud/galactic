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

// BGPRouterSpec defines the desired state of a BGPRouter.
type BGPRouterSpec struct {
	// TargetRef identifies the Node this router executes on.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// LocalASN is the BGP Autonomous System Number for this router.
	// Must be a valid 2-byte or 4-byte ASN per RFC 6793.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
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
