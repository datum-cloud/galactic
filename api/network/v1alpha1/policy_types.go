package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BGPPolicyDirection is the direction in which a BGPPolicy is applied.
//
// +kubebuilder:validation:Enum=import;export
type BGPPolicyDirection string

const (
	// BGPPolicyDirectionImport applies the policy to routes received from peers.
	BGPPolicyDirectionImport BGPPolicyDirection = "import"

	// BGPPolicyDirectionExport applies the policy to routes advertised to peers.
	BGPPolicyDirectionExport BGPPolicyDirection = "export"
)

// BGPPolicyAction is the disposition applied when a policy term matches.
//
// +kubebuilder:validation:Enum=permit;deny
type BGPPolicyAction string

const (
	// BGPPolicyActionPermit allows the route and optionally applies set actions.
	BGPPolicyActionPermit BGPPolicyAction = "permit"

	// BGPPolicyActionDeny drops the route. Set actions must not be specified.
	BGPPolicyActionDeny BGPPolicyAction = "deny"
)

// BGPPolicy defines composable, ordered routing policy statements applied to a
// BGPRouter in a specific direction (import or export). It binds to one or more
// BGPRouter instances via routerRef or routerSelector.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpp
// +kubebuilder:printcolumn:name="DIRECTION",type="string",JSONPath=".spec.direction"
// +kubebuilder:printcolumn:name="TERMS",type="integer",JSONPath=".spec.terms"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPPolicySpec   `json:"spec,omitempty"`
	Status BGPPolicyStatus `json:"status,omitempty"`
}

// BGPPolicySpec defines the desired route policy state.
//
// +kubebuilder:validation:XValidation:rule="self.terms.all(t1, self.terms.filter(t2, t2.sequence == t1.sequence).size() == 1)",message="Term sequence numbers must be unique"
type BGPPolicySpec struct {
	RouterTarget `json:",inline"`

	// Direction is the policy direction: import or export.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=import;export
	Direction BGPPolicyDirection `json:"direction"`

	// Terms is the ordered list of policy statements.
	// Evaluated from lowest to highest sequence number.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Terms []BGPPolicyTerm `json:"terms"`
}

// BGPPolicyTerm is a single ordered policy statement with match conditions and an action.
//
// +kubebuilder:validation:XValidation:rule="self.action == 'deny' ? !has(self.set) : true",message="set actions are not permitted on deny terms"
type BGPPolicyTerm struct {
	// Sequence is the evaluation order. Lower values are evaluated first.
	// Must be unique within the policy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Sequence int32 `json:"sequence"`

	// Match defines the conditions under which this term fires.
	Match BGPPolicyMatch `json:"match"`

	// Action is the disposition when this term matches.
	// +kubebuilder:validation:Enum=permit;deny
	Action BGPPolicyAction `json:"action"`

	// Set defines mutations applied when action is "permit".
	// Must not be set when action is "deny".
	// +optional
	Set *BGPPolicySetActions `json:"set,omitempty"`
}

// BGPPolicyMatch defines the conditions under which a policy term fires.
//
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.prefixList) || self.prefixList.size() == 0",message="prefixList must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.asPathFilter) || self.asPathFilter.pattern.size() == 0",message="asPathFilter must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.communityMatch) || self.communityMatch.size() == 0",message="communityMatch must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.evpnRouteType) || self.evpnRouteType.size() == 0",message="evpnRouteType must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.vni) || self.vni == 0",message="vni must be unset when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.macAddress) || self.macAddress.size() == 0",message="macAddress must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.ipPrefix) || self.ipPrefix.size() == 0",message="ipPrefix must be empty when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.localPreference) || self.localPreference == 0",message="localPreference must be unset when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.med) || self.med == 0",message="med must be unset when any is true"
// +kubebuilder:validation:XValidation:rule="!has(self.any) || !self.any || !has(self.addressFamilies) || self.addressFamilies.size() == 0",message="addressFamilies must be empty when any is true"
type BGPPolicyMatch struct {
	// Any matches all routes. When true, all other match fields are ignored.
	// +optional
	Any bool `json:"any,omitempty"`

	// AddressFamilies constrains the match to specific AFI/SAFI combinations.
	// If empty, all address families are matched.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	AddressFamilies []AddressFamily `json:"addressFamilies,omitempty"`

	// PrefixList constrains the match to routes whose prefix matches one of
	// the given CIDR blocks. Each entry must be a valid IPv4 or IPv6 CIDR.
	// +optional
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(p, isCIDR(p))",message="each prefixList entry must be a valid IPv4 or IPv6 CIDR"
	PrefixList []string `json:"prefixList,omitempty"`

	// ASPathFilter matches routes by AS path using a regex pattern.
	// The pattern is matched against the full AS path string (space-separated ASNs).
	// +optional
	ASPathFilter *ASPathFilter `json:"asPathFilter,omitempty"`

	// CommunityMatch matches routes by BGP community.
	// Each entry is a community string in ASN:NN or IP:NN format.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=32
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[0-9]{1,10}:[0-9]{1,10}$') || c.matches('^[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}:[0-9]{1,10}$'))",message="each communityMatch entry must be in ASN:NN or IP:NN format"
	CommunityMatch []string `json:"communityMatch,omitempty"`

	// EVPNRouteType matches specific EVPN route types.
	// Only meaningful when l2vpn/evpn address family is configured.
	// +optional
	// +kubebuilder:validation:MaxItems=5
	EVPNRouteType []EVPNRouteType `json:"evpnRouteType,omitempty"`

	// VNI matches routes by VNI (VXLAN Network Identifier).
	// Range: 0–16777215 (24-bit VNI).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16777215
	VNI *uint32 `json:"vni,omitempty"`

	// MACAddress matches MAC-IP routes (EVPN Type-2) by MAC address.
	// Format: colon-separated hex bytes (e.g., "aa:bb:cc:dd:ee:ff").
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`
	MACAddress *string `json:"macAddress,omitempty"`

	// IPPrefix matches routes by exact IP prefix (CIDR notation).
	// +optional
	// +kubebuilder:validation:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="ipPrefix must be a valid IPv4 or IPv6 CIDR"
	IPPrefix *string `json:"ipPrefix,omitempty"`

	// LocalPreference matches routes by BGP LOCAL_PREF value.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LocalPreference *int32 `json:"localPreference,omitempty"`

	// MED matches routes by Multi-Exit Discriminator value.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MED *int32 `json:"med,omitempty"`
}

// ASPathFilter matches BGP routes by AS path using a regex pattern.
type ASPathFilter struct {
	// Pattern is a regular expression matched against the AS path.
	// The AS path is represented as a space-separated string of ASNs.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Pattern string `json:"pattern"`

	// MatchType determines whether the pattern must match the full path
	// or can match a substring. Default: "contains".
	// +kubebuilder:validation:Enum=full;contains
	// +kubebuilder:default=contains
	MatchType ASPathMatchType `json:"matchType,omitempty"`
}

// ASPathMatchType determines how an AS path filter pattern is applied.
//
// +kubebuilder:validation:Enum=full;contains
type ASPathMatchType string

const (
	// ASPathMatchFull requires the pattern to match the entire AS path.
	ASPathMatchFull ASPathMatchType = "full"

	// ASPathMatchContains requires the pattern to match a substring of the AS path.
	ASPathMatchContains ASPathMatchType = "contains"
)

// EVPNRouteType is an EVPN route type per RFC 7432.
//
// +kubebuilder:validation:Enum=inclusiveMulticastEthernetTag;macIPAdvertisement;iPPrefixAdvertisement;stickyMACAddress;iPv6PrefixAdvertisement
type EVPNRouteType string

const (
	// EVPNRouteTypeInclusiveMulticastEthernetTag is Type-1: Inclusive Multicast Ethernet Tag route.
	EVPNRouteTypeInclusiveMulticastEthernetTag EVPNRouteType = "inclusiveMulticastEthernetTag"

	// EVPNRouteTypeMACIPAdvertisement is Type-2: MAC-IP Advertisement route.
	EVPNRouteTypeMACIPAdvertisement EVPNRouteType = "macIPAdvertisement"

	// EVPNRouteTypeIPPrefixAdvertisement is Type-3: IP Prefix Advertisement route.
	EVPNRouteTypeIPPrefixAdvertisement EVPNRouteType = "iPPrefixAdvertisement"

	// EVPNRouteTypeStickyMACAddress is Type-4: Sticky MAC Address route.
	EVPNRouteTypeStickyMACAddress EVPNRouteType = "stickyMACAddress"

	// EVPNRouteTypeIPv6PrefixAdvertisement is Type-5: IPv6 Prefix Advertisement route.
	EVPNRouteTypeIPv6PrefixAdvertisement EVPNRouteType = "iPv6PrefixAdvertisement"
)

// BGPPolicySetActions defines mutations applied when a term matches with action "permit".
type BGPPolicySetActions struct {
	// Communities defines community add/remove operations.
	// +optional
	Communities *CommunitySet `json:"communities,omitempty"`

	// LocalPreference sets the LOCAL_PREF attribute.
	// Only meaningful on import (iBGP) or export to iBGP peers.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LocalPreference *int32 `json:"localPreference,omitempty"`

	// Origin sets the BGP origin attribute.
	// +optional
	Origin *BGPOrigin `json:"origin,omitempty"`

	// AsPath manipulates the AS path (prepend or replace).
	// +optional
	AsPath *AsPathSet `json:"asPath,omitempty"`

	// NextHop overrides the next-hop attribute.
	// +optional
	NextHop *NextHopSet `json:"nextHop,omitempty"`

	// ExtCommunities defines extended community add/remove operations.
	// Each entry must be in a valid extended community format (ASN:NN, IP:NN,
	// or type-specific like "rt:65000:100").
	// +optional
	ExtCommunities *ExtendedCommunitySet `json:"extCommunities,omitempty"`

	// Metric sets the MED (Multi-Exit Discriminator) attribute.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Metric *int32 `json:"metric,omitempty"`

	// Color sets the SRv6 policy color for path selection.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Color *int32 `json:"color,omitempty"`
}

// BGPOrigin is the BGP origin attribute per RFC 4271.
//
// +kubebuilder:validation:Enum=igp;egp;incomplete
type BGPOrigin string

const (
	// BGPOriginIGP indicates the route was learned via an IGP.
	BGPOriginIGP BGPOrigin = "igp"

	// BGPOriginEGP indicates the route was learned via the EGP protocol.
	BGPOriginEGP BGPOrigin = "egp"

	// BGPOriginIncomplete indicates the route origin is unknown.
	BGPOriginIncomplete BGPOrigin = "incomplete"
)

// AsPathSet defines AS path manipulation operations.
//
// +kubebuilder:validation:XValidation:rule="!has(self.prepend) || !has(self.replace) || self.replace.size() == 0",message="prepend and replace are mutually exclusive"
type AsPathSet struct {
	// Prepend adds an ASN to the AS path N times.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	Prepend *uint32 `json:"prepend,omitempty"`

	// ASN is the AS number to prepend (used when prepend is set).
	// Defaults to the local ASN if not specified.
	// +optional
	ASN *int64 `json:"asn,omitempty"`

	// Replace replaces the entire AS path with the given list.
	// Mutually exclusive with prepend.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	Replace []int64 `json:"replace,omitempty"`
}

// NextHopSet defines next-hop attribute overrides.
//
// +kubebuilder:validation:XValidation:rule="!has(self.self) || !self.self || !has(self.address) || self.address.size() == 0",message="self and address are mutually exclusive"
type NextHopSet struct {
	// Self sets the next-hop to the local router's BGP peer address.
	// +optional
	Self *bool `json:"self,omitempty"`

	// Address sets the next-hop to a specific IP address.
	// Mutually exclusive with self.
	// +optional
	// +kubebuilder:validation:MaxLength=45
	Address *string `json:"address,omitempty"`
}

// CommunitySet defines community add and remove operations.
type CommunitySet struct {
	// Add is a list of communities to attach.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=24
	Add []string `json:"add,omitempty"`

	// Remove is a list of communities to strip.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=24
	Remove []string `json:"remove,omitempty"`
}

// ExtendedCommunitySet defines extended community add and remove operations.
type ExtendedCommunitySet struct {
	// Add is a list of extended communities to attach.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[0-9a-fA-F:.]+$'))",message="each extCommunity entry must contain only valid characters (digits, letters, colons, dots)"
	Add []string `json:"add,omitempty"`

	// Remove is a list of extended communities to strip.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[0-9a-fA-F:.]+$'))",message="each extCommunity entry must contain only valid characters (digits, letters, colons, dots)"
	Remove []string `json:"remove,omitempty"`
}

// BGPPolicyStatus defines the observed state of BGPPolicy.
type BGPPolicyStatus struct {
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

// BGPPolicyList is a list of BGPPolicy resources.
// +kubebuilder:object:root=true
type BGPPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPPolicy{}, &BGPPolicyList{})
}
