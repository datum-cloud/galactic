package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Community is a BGP community in ASN:NN or IP:NN format.
// +kubebuilder:validation:MaxLength=32
type Community string

// Prefix is an IPv4 or IPv6 CIDR prefix.
// +kubebuilder:validation:MaxLength=64
// +kubebuilder:validation:XValidation:rule="self.matches('^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+/[0-9]{1,2}$|^[0-9a-fA-F:]+::?[0-9a-fA-F:]+/[0-9]{1,3}$')",message="must be a valid IPv4 or IPv6 CIDR"
type Prefix string

// RedistributeSource is a local routing table source to redistribute into BGP.
//
// +kubebuilder:validation:Enum=static;connected;kernel
type RedistributeSource string

const (
	// RedistributeSourceStatic redistributes statically configured routes.
	RedistributeSourceStatic RedistributeSource = "static"

	// RedistributeSourceConnected redistributes directly connected interface routes.
	RedistributeSourceConnected RedistributeSource = "connected"

	// RedistributeSourceKernel redistributes routes from the kernel routing table.
	RedistributeSourceKernel RedistributeSource = "kernel"
)

// AdvertisementOriginateType is the source from which routes are originated.
//
// +kubebuilder:validation:Enum=interface;kernel
type AdvertisementOriginateType string

const (
	// OriginateTypeInterface originates routes from local interface addresses.
	OriginateTypeInterface AdvertisementOriginateType = "interface"

	// OriginateTypeKernel originates routes learned from the kernel routing table.
	OriginateTypeKernel AdvertisementOriginateType = "kernel"
)

// AdvertisementOriginateFrom defines how routes are sourced from a local system
// resource rather than from the static Prefixes list.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'interface' ? has(self.interfaceName) : true",message="interfaceName is required when type is interface"
// +kubebuilder:validation:XValidation:rule="self.type == 'kernel' ? !has(self.interfaceName) : true",message="interfaceName must not be set when type is kernel"
type AdvertisementOriginateFrom struct {
	// Type is the source from which routes are originated.
	// +kubebuilder:validation:Enum=interface;kernel
	Type AdvertisementOriginateType `json:"type"`

	// InterfaceName is the name of the interface to originate routes from.
	// Required when type is "interface".
	// +optional
	// +kubebuilder:validation:MinLength=1
	InterfaceName *string `json:"interfaceName,omitempty"`
}

// AdvertisementPolicyRef references a BGPPolicy by name to apply as a conditional
// filter before advertisement.
type AdvertisementPolicyRef struct {
	// Name is the name of the BGPPolicy within the same namespace.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// BGPAdvertisement defines routing information to advertise from a single BGPRouter.
// Routes are originated from static Prefixes, redistributed routing table entries,
// or local interface/kernel routes. Fan-out via routerSelector is intentionally not
// supported to avoid ambiguous prefix attribution across multiple routers.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpadv
// +kubebuilder:printcolumn:name="ROUTER",type="string",JSONPath=".spec.routerRef.name"
// +kubebuilder:printcolumn:name="ADDRESS-FAMILY",type="string",JSONPath=".spec.addressFamily.afi"
// +kubebuilder:printcolumn:name="PREFIXES",type="integer",JSONPath=".status.advertisedPrefixes"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPAdvertisement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPAdvertisementSpec   `json:"spec,omitempty"`
	Status BGPAdvertisementStatus `json:"status,omitempty"`
}

// BGPAdvertisementSpec defines the desired advertisement state.
// At least one of prefixes, redistribute, or originateFrom must be specified.
//
// +kubebuilder:validation:XValidation:rule="(has(self.prefixes) && self.prefixes.size() > 0) || (has(self.redistribute) && self.redistribute.size() > 0) || has(self.originateFrom)",message="at least one of prefixes, redistribute, or originateFrom must be specified"
type BGPAdvertisementSpec struct {
	// RouterRef targets a single BGPRouter by name.
	// +kubebuilder:validation:Required
	RouterRef RouterRef `json:"routerRef"`

	// AddressFamily defines the AFI/SAFI for this advertisement.
	// +kubebuilder:validation:Required
	AddressFamily AddressFamily `json:"addressFamily"`

	// Prefixes is the list of CIDR prefixes to advertise.
	// At least one of Prefixes, Redistribute, or OriginateFrom must be specified.
	// +optional
	// +kubebuilder:validation:MaxItems=256
	// +listType=set
	Prefixes []Prefix `json:"prefixes,omitempty"`

	// Redistribute defines routing table sources to redistribute into BGP.
	// Routes matching the source type are originated without requiring explicit CIDR entries.
	// At least one of Prefixes, Redistribute, or OriginateFrom must be specified.
	// +optional
	// +kubebuilder:validation:MaxItems=3
	// +listType=set
	Redistribute []RedistributeSource `json:"redistribute,omitempty"`

	// OriginateFrom defines how routes are sourced from a local interface or kernel table.
	// When set, routes are originated from the specified source in addition to any static Prefixes.
	// At least one of Prefixes, Redistribute, or OriginateFrom must be specified.
	// +optional
	OriginateFrom *AdvertisementOriginateFrom `json:"originateFrom,omitempty"`

	// PolicyRef references a BGPPolicy to apply as a conditional filter before advertisement.
	// Only routes that match the policy are originated.
	// +optional
	PolicyRef *AdvertisementPolicyRef `json:"policyRef,omitempty"`

	// Communities is the default list of BGP communities to attach to all advertised prefixes.
	// Per-prefix communities in Prefixes[n].communities replace this value for individual prefixes.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[0-9]{1,10}:[0-9]{1,10}$') || c.matches('^[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}:[0-9]{1,10}$'))",message="community must be in ASN:NN or IP:NN format"
	Communities []Community `json:"communities,omitempty"`

	// LocalPreference sets the default BGP LOCAL_PREF attribute for all advertised prefixes.
	// Per-prefix localPreference in Prefixes[n].localPreference overrides this value.
	// Only meaningful for iBGP sessions.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LocalPreference *int32 `json:"localPreference,omitempty"`

	// VRFID is the 16-bit PoP-local VRF identifier this advertisement's SRv6
	// SID resolves into, per RFC 9800 uSID Argument addressing. Required when
	// Function is set.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	VRFID *int32 `json:"vrfID,omitempty"`

	// Function is the RFC 8986 SRv6 endpoint behavior applied when this
	// advertisement originates a compressed uSID. Required when VRFID is set.
	// +optional
	Function *SRv6Function `json:"function,omitempty"`
}

// BGPAdvertisementStatus defines the observed state of BGPAdvertisement.
type BGPAdvertisementStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AdvertisedPrefixes is the count of prefixes currently being originated.
	// +optional
	AdvertisedPrefixes int32 `json:"advertisedPrefixes,omitempty"`

	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BGPAdvertisementList is a list of BGPAdvertisement resources.
// +kubebuilder:object:root=true
type BGPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPAdvertisement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPAdvertisement{}, &BGPAdvertisementList{})
}
