package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BGPPrefixListEntry defines a single entry in a named BGP prefix-list.
// Entries are evaluated in ascending sequence order.
//
// GE and LE bound the matched prefix length. Both are limited by the
// entry's family (32 for IPv4, 128 for IPv6), GE may not be shorter than
// the prefix's own length, and LE may not be shorter than GE (or the
// prefix's length when GE is unset): FRR's own rule, mask length <= ge <= le.
// A malformed prefix is reported by the prefix field's rule alone.
//
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.prefix) || !has(self.ge) || self.ge <= (cidr(self.prefix).ip().family() == 4 ? 32 : 128)",message="ge must not exceed 32 for IPv4 or 128 for IPv6"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.prefix) || !has(self.le) || self.le <= (cidr(self.prefix).ip().family() == 4 ? 32 : 128)",message="le must not exceed 32 for IPv4 or 128 for IPv6"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.prefix) || !has(self.ge) || self.ge >= cidr(self.prefix).prefixLength()",message="ge must be at least the prefix length"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.prefix) || !has(self.le) || self.le >= (has(self.ge) ? self.ge : cidr(self.prefix).prefixLength())",message="le must be at least ge, or the prefix length when ge is unset"
type BGPPrefixListEntry struct {
	// Sequence is the evaluation order for this entry. Entries with lower
	// sequence numbers are evaluated first. Must be unique within the list.
	// The range is FRR's: 1 to 4294967295.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	Sequence int64 `json:"sequence"`

	// Action is the disposition when a route's prefix matches this entry.
	// +kubebuilder:validation:Required
	Action BGPPolicyAction `json:"action"`

	// Prefix is the IPv4 or IPv6 CIDR to match against.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="prefix must be a valid IPv4 or IPv6 CIDR"
	Prefix string `json:"prefix"`

	// GE is the minimum prefix-length to match (greater-than-or-equal).
	// For example, "10.0.0.0/8 ge 16" matches lengths /16 through /32, and
	// "2607:ed40:8003::/48 ge 49" lengths /49 through /128.
	// When unset, the prefix-length of Prefix is the lower bound.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	GE *int32 `json:"ge,omitempty"`

	// LE is the maximum prefix-length to match (less-than-or-equal).
	// For example, "10.0.0.0/8 le 24" matches 10.0.0.0/8 through 10.0.0.0/24.
	// When unset, the prefix-length of Prefix is the upper bound, unless GE
	// is set, in which case the family's maximum length is.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LE *int32 `json:"le,omitempty"`
}

// BGPPrefixList defines a named list of prefix-match entries used by BGPPolicy
// terms to filter routes by destination prefix. It is referenced by name from
// BGPPolicyMatch.prefixListRef.
//
// A single BGPPrefixList holds entries for either IPv4 or IPv6 — the address
// family is inferred from the CIDR family of the first entry and validated
// consistent across all entries via CEL.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgppfx
// +kubebuilder:printcolumn:name="ENTRIES",type="integer",JSONPath=".spec.entries"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPPrefixList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPPrefixListSpec   `json:"spec,omitempty"`
	Status BGPPrefixListStatus `json:"status,omitempty"`
}

// BGPPrefixListSpec defines the desired state of BGPPrefixList.
//
// +kubebuilder:validation:XValidation:rule="self.entries.all(e, e.prefix.contains(':') == self.entries[0].prefix.contains(':'))",message="all entries must be the same address family (IPv4 or IPv6)"
type BGPPrefixListSpec struct {
	// Entries is the ordered list of prefix-match entries, keyed by sequence.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1024
	// +listType=map
	// +listMapKey=sequence
	Entries []BGPPrefixListEntry `json:"entries"`
}

// BGPPrefixListStatus defines the observed state of BGPPrefixList.
type BGPPrefixListStatus struct {
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

// BGPPrefixListList is a list of BGPPrefixList resources.
// +kubebuilder:object:root=true
type BGPPrefixListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPPrefixList `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPPrefixList{}, &BGPPrefixListList{})
}
