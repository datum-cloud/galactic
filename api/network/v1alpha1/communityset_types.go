package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BGPCommunitySetType distinguishes standard from large BGP communities.
//
// +kubebuilder:validation:Enum=standard;large
type BGPCommunitySetType string

const (
	// BGPCommunitySetTypeStandard covers ASN:NN, IP:NN, and well-known names
	// (graceful-shutdown, no-export, no-advertise, blackhole).
	BGPCommunitySetTypeStandard BGPCommunitySetType = "standard"

	// BGPCommunitySetTypeLarge covers ASN:NN:NN large communities.
	BGPCommunitySetTypeLarge BGPCommunitySetType = "large"
)

// BGPCommunitySet defines a named list of BGP community values used by BGPPolicy
// terms to match or set communities on routes. It is referenced by name from
// BGPPolicyMatch.communitySetRef.
//
// A single BGPCommunitySet holds either standard or large communities — the type
// is declared upfront and all entries are validated against it via CEL.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpcs
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="ENTRIES",type="integer",JSONPath=".spec.entries"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPCommunitySet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPCommunitySetSpec   `json:"spec,omitempty"`
	Status BGPCommunitySetStatus `json:"status,omitempty"`
}

// BGPCommunitySetSpec defines the desired state of BGPCommunitySet.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'standard' ? self.all(e, e.matches('^[0-9]{1,10}:[0-9]{1,10}$') || e.matches('^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,10}$') || e == 'graceful-shutdown' || e == 'no-export' || e == 'no-advertise' || e == 'blackhole') : true",message="standard entries must be ASN:NN, IP:NN, or a well-known name"
// +kubebuilder:validation:XValidation:rule="self.type == 'large' ? self.all(e, e.matches('^[0-9]{1,10}:[0-9]{1,10}:[0-9]{1,10}$')) : true",message="large entries must be ASN:NN:NN"
type BGPCommunitySetSpec struct {
	// Type is the community format for all entries in this set.
	// +kubebuilder:validation:Required
	Type BGPCommunitySetType `json:"type"`

	// Entries is the list of community values.
	// Standard: ASN:NN, IP:NN, or well-known names (graceful-shutdown, no-export,
	// no-advertise, blackhole).
	// Large: ASN:NN:NN.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Entries []string `json:"entries"`
}

// BGPCommunitySetStatus defines the observed state of BGPCommunitySet.
type BGPCommunitySetStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BGPCommunitySetList is a list of BGPCommunitySet resources.
// +kubebuilder:object:root=true
type BGPCommunitySetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPCommunitySet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPCommunitySet{}, &BGPCommunitySetList{})
}
