package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BGPVRFInstance configures an L2VPN EVPN VRF on matched BGPRouters.
// The referenced BGPRouter must have l2vpn-evpn in its addressFamilies.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpvrf
// +kubebuilder:printcolumn:name="VRF-ID",type="integer",JSONPath=".spec.vrfID"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type BGPVRFInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPVRFInstanceSpec   `json:"spec,omitempty"`
	Status BGPVRFInstanceStatus `json:"status,omitempty"`
}

// BGPVRFInstanceSpec defines the desired VRF configuration.
type BGPVRFInstanceSpec struct {
	RouterTarget `json:",inline"`

	// VRFID is the 16-bit PoP-local VRF identifier used for RFC 9800 uSID
	// Argument addressing and to derive the RFC 4364 Type 1 Route
	// Distinguisher ("routerID:vrfID"). Unique per (VPC, PoP). Value 0 is
	// reserved.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	VRFID int32 `json:"vrfID"`

	// ImportRouteTargets is the list of BGP extended community route targets
	// used to import routes into this VRF.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	ImportRouteTargets []RouteTarget `json:"importRouteTargets"`

	// ExportRouteTargets is the list of BGP extended community route targets
	// attached to routes exported from this VRF.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	ExportRouteTargets []RouteTarget `json:"exportRouteTargets"`

	// NPTv6 configures stateless RFC 6296 Network Prefix Translation for
	// this VRF: backends presenting an address within ULAPrefix are
	// translated, checksum-neutrally and bidirectionally, to the
	// corresponding address in PublicPrefix. Unset means this VRF's traffic
	// crosses the SRv6 fabric with its own ULA source/destination
	// unmodified — the common case. Keyed by this VRFID, never by address,
	// specifically so two VRFs may configure the identical ULAPrefix (e.g.
	// both using the same private range) without collision — each VRF's
	// mapping is independent, looked up only after this VRF's own identity
	// is already resolved from the SRv6 uSID Argument, never derived from
	// address content alone.
	// +optional
	NPTv6 *NPTv6Spec `json:"nptv6,omitempty"`
}

// NPTv6Spec is one VRF's stateless RFC 6296 prefix-translation mapping.
// ULAPrefix and PublicPrefix must share the same prefix length — RFC 6296
// translation only ever rewrites the shared prefix, never the host bits.
//
// +kubebuilder:validation:XValidation:rule="self.ulaPrefix.split('/')[1] == self.publicPrefix.split('/')[1]",message="ulaPrefix and publicPrefix must share the same prefix length"
type NPTv6Spec struct {
	// ULAPrefix is this VRF's tenant-facing IPv6 ULA prefix (e.g.
	// "fd20:60::/64"), as presented by backends inside the VRF.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="ulaPrefix must be a valid CIDR"
	// +kubebuilder:validation:XValidation:rule="self.contains(':')",message="ulaPrefix must be an IPv6 CIDR"
	ULAPrefix string `json:"ulaPrefix"`

	// PublicPrefix is the externally-routable IPv6 prefix ULAPrefix
	// translates to/from, same prefix length as ULAPrefix.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="publicPrefix must be a valid CIDR"
	// +kubebuilder:validation:XValidation:rule="self.contains(':')",message="publicPrefix must be an IPv6 CIDR"
	PublicPrefix string `json:"publicPrefix"`
}

// RouteTarget is a BGP extended community in "ASN:NN" or "IP:NN" format.
//
// +kubebuilder:validation:XValidation:rule="self.value.matches('^([0-9]{1,9}[.][0-9]{1,9}[.][0-9]{1,9}[.][0-9]{1,9}|[0-9]{1,10}):[0-9]{1,10}$')",message="value must be in ASN:NN or IP:NN format"
type RouteTarget struct {
	// Value is the route target extended community string.
	// Format: "ASN:NN" (e.g. "65000:100") or "IP:NN" (e.g. "192.0.2.1:100").
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=21
	Value string `json:"value"`
}

// BGPVRFInstanceStatus defines the observed state of BGPVRFInstance.
type BGPVRFInstanceStatus struct {
	// Conditions are top-level conditions for this BGPVRFInstance.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Routers holds per-router reconciliation status.
	//
	// +listType=map
	// +listMapKey=routerName
	// +optional
	Routers []RouterStatus `json:"routers,omitempty"`
}

// BGPVRFInstanceList is a list of BGPVRFInstance resources.
// +kubebuilder:object:root=true
type BGPVRFInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPVRFInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPVRFInstance{}, &BGPVRFInstanceList{})
}
