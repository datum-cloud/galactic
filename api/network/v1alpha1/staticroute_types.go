// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BGPStaticRouteAction is what a static route does with matching traffic.
//
// +kubebuilder:validation:Enum=Discard;NextHop
type BGPStaticRouteAction string

const (
	// BGPStaticRouteDiscard drops matching traffic (FRR's Null0).
	BGPStaticRouteDiscard BGPStaticRouteAction = "Discard"
	// BGPStaticRouteNextHop forwards matching traffic to nextHop.
	BGPStaticRouteNextHop BGPStaticRouteAction = "NextHop"
)

// BGPStaticRoute installs one static route in a router's default routing
// instance. Installing a route never advertises it: advertisement is a
// separate BGPAdvertisement, and an aggregate never creates a discard route.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgpsr
// +kubebuilder:printcolumn:name="ROUTER",type="string",JSONPath=".spec.routerRef.name"
// +kubebuilder:printcolumn:name="DESTINATION",type="string",JSONPath=".spec.destination"
// +kubebuilder:printcolumn:name="ACTION",type="string",JSONPath=".spec.action"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPStaticRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   BGPStaticRouteSpec   `json:"spec"`
	Status BGPStaticRouteStatus `json:"status,omitempty"`
}

// BGPStaticRouteSpec defines one static route.
//
// +kubebuilder:validation:XValidation:rule="self.addressFamily == 'ipv4' || self.addressFamily == 'ipv6'",message="addressFamily must be ipv4 or ipv6"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.destination) || cidr(self.destination).ip().family() == (self.addressFamily == 'ipv4' ? 4 : 6)",message="destination must be in addressFamily"
// +kubebuilder:validation:XValidation:rule="(self.action == 'NextHop') == has(self.nextHop)",message="nextHop is required with, and only with, action NextHop"
// +kubebuilder:validation:XValidation:rule="!has(self.nextHop) || !isIP(self.nextHop) || ip(self.nextHop).family() == (self.addressFamily == 'ipv4' ? 4 : 6)",message="nextHop must be in addressFamily"
type BGPStaticRouteSpec struct {
	// RouterRef names the BGPRouter whose routing instance holds the route.
	RouterRef RouterRef `json:"routerRef"`

	// AddressFamily is the route's family: ipv4 or ipv6.
	AddressFamily AFI `json:"addressFamily"`

	// Destination is the route's prefix in CIDR notation.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="destination must be a valid CIDR"
	Destination string `json:"destination"`

	// Action is what the route does with matching traffic.
	Action BGPStaticRouteAction `json:"action"`

	// NextHop is the gateway address for action NextHop.
	// +optional
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="nextHop must be a valid IP address"
	NextHop *string `json:"nextHop,omitempty"`
}

// BGPStaticRouteStatus defines the observed state of BGPStaticRoute.
type BGPStaticRouteStatus struct {
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

// BGPStaticRouteList is a list of BGPStaticRoute resources.
// +kubebuilder:object:root=true
type BGPStaticRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPStaticRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPStaticRoute{}, &BGPStaticRouteList{})
}
