// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FabricEndpoint is where one fabric router is reached on one transport
// network: its addresses there, the ASN it speaks, the cell that owns it and
// its failure domain. A FabricTopology generates both ends of a managed
// session from two endpoint records, so a router's record must be present
// in every cell whose routers peer with it, including cells where the router
// itself does not run. Whoever distributes the rest of the cell's intent
// distributes these records too; nothing in the cluster copies them between
// cells.
//
// An endpoint is a record, not an allocation: nothing here asks an
// addressing service for an address. spec.source says where the addresses
// came from.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fep
// +kubebuilder:printcolumn:name="DOMAIN",type="string",JSONPath=".spec.routingDomain"
// +kubebuilder:printcolumn:name="CELL",type="string",JSONPath=".spec.cell"
// +kubebuilder:printcolumn:name="ROUTER",type="string",JSONPath=".spec.routerRef.name"
// +kubebuilder:printcolumn:name="TRANSPORT",type="string",JSONPath=".spec.transport"
// +kubebuilder:printcolumn:name="IPV4",type="string",JSONPath=".spec.addresses.ipv4"
// +kubebuilder:printcolumn:name="IPV6",type="string",JSONPath=".spec.addresses.ipv6"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type FabricEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   FabricEndpointSpec   `json:"spec"`
	Status FabricEndpointStatus `json:"status,omitempty"`
}

// FabricEndpointSourceType names who wrote an endpoint's addresses.
//
// +kubebuilder:validation:Enum=Manual;AddressClaim
type FabricEndpointSourceType string

const (
	// FabricEndpointSourceManual is an address an operator or the
	// deployment pipeline authored, with no allocation behind it.
	FabricEndpointSourceManual FabricEndpointSourceType = "Manual"
	// FabricEndpointSourceAddressClaim is an address allocated by an
	// addressing-service claim, which the endpoint records.
	FabricEndpointSourceAddressClaim FabricEndpointSourceType = "AddressClaim"
)

// FabricEndpointSpec is one router's presence on one transport network. Its
// identity (routing domain, cell, router and transport) is immutable: moving
// a router to another transport is a new endpoint and the removal of the
// old one, so the old one's sessions drain like any other removal.
//
// +kubebuilder:validation:XValidation:rule="self.routingDomain == oldSelf.routingDomain && self.cell == oldSelf.cell && self.routerRef == oldSelf.routerRef && self.transport == oldSelf.transport",message="an endpoint's routing domain, cell, router and transport are immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.source.ipv4ClaimRef) || has(self.addresses.ipv4)",message="an IPv4 claim needs an IPv4 address"
// +kubebuilder:validation:XValidation:rule="!has(self.source.ipv6ClaimRef) || has(self.addresses.ipv6)",message="an IPv6 claim needs an IPv6 address"
// +kubebuilder:validation:XValidation:rule="!has(self.addresses.ipv6) || !isIP(self.addresses.ipv6) || !ip(self.addresses.ipv6).isLinkLocalUnicast() || has(self.interface)",message="a link-local IPv6 address needs an interface"
// +kubebuilder:validation:XValidation:rule="self.source.type != 'AddressClaim' || ((!has(self.addresses.ipv4) || has(self.source.ipv4ClaimRef)) && (!has(self.addresses.ipv6) || has(self.source.ipv6ClaimRef)))",message="an AddressClaim source names the claim of every address"
type FabricEndpointSpec struct {
	// RoutingDomain is the fabric this endpoint belongs to. A topology
	// considers only endpoints of its own routing domain.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	RoutingDomain string `json:"routingDomain"`

	// Cell is the cell that runs the router. The router exists as a
	// BGPRouter only in that cell; every other cell knows it through this
	// record alone.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Cell string `json:"cell"`

	// RouterRef names the BGPRouter, in this namespace of the owning cell.
	RouterRef LocalObjectRef `json:"routerRef"`

	// Transport names the network the addresses are on, such as
	// private-mesh or public. Two endpoints peer only over a transport they
	// share.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Transport string `json:"transport"`

	// ASN is the router's local ASN, the remote ASN of every session toward
	// this endpoint. In the owning cell it must equal the BGPRouter's.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	ASN int64 `json:"asn"`

	// Addresses are the router's addresses on the transport, at most one
	// per family. A session is generated only in a family both ends carry.
	Addresses FabricEndpointAddresses `json:"addresses"`

	// Interface is the router's interface on the transport. It is required
	// with a link-local IPv6 address. The topology generator does not yet
	// generate sessions toward an endpoint that names one.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.@-]{1,15}$`
	Interface *string `json:"interface,omitempty"`

	// FailureDomain is the failure domain the router is in. Unset, the
	// owning cell reads it from the router's Node label the topology names.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	FailureDomain *string `json:"failureDomain,omitempty"`

	// Source records where the addresses came from.
	// +kubebuilder:default={type: Manual}
	Source FabricEndpointSource `json:"source,omitempty"`
}

// FabricEndpointAddresses are a router's addresses on one transport.
//
// +kubebuilder:validation:XValidation:rule="has(self.ipv4) || has(self.ipv6)",message="an endpoint has an IPv4 or an IPv6 address"
type FabricEndpointAddresses struct {
	// IPv4 is the router's IPv4 address on the transport.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 4",message="ipv4 must be an IPv4 address"
	IPv4 *string `json:"ipv4,omitempty"`

	// IPv6 is the router's IPv6 address on the transport.
	// +optional
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 6",message="ipv6 must be an IPv6 address"
	IPv6 *string `json:"ipv6,omitempty"`
}

// FabricEndpointSource records where an endpoint's addresses came from. A
// claim reference is provenance: nothing resolves it, and the addresses in
// the spec are what sessions use.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'AddressClaim' || (!has(self.ipv4ClaimRef) && !has(self.ipv6ClaimRef))",message="claim references need the AddressClaim source"
type FabricEndpointSource struct {
	// Type is Manual or AddressClaim.
	// +kubebuilder:default=Manual
	Type FabricEndpointSourceType `json:"type,omitempty"`

	// IPv4ClaimRef is the claim the IPv4 address was allocated by.
	// +optional
	IPv4ClaimRef *AddressClaimRef `json:"ipv4ClaimRef,omitempty"`

	// IPv6ClaimRef is the claim the IPv6 address was allocated by.
	// +optional
	IPv6ClaimRef *AddressClaimRef `json:"ipv6ClaimRef,omitempty"`
}

// Endpoint condition types.
const (
	// FabricEndpointConditionReady is True when topologies may generate
	// sessions toward the endpoint.
	FabricEndpointConditionReady = "Ready"
	// FabricEndpointConditionConflict is True when another endpoint holds
	// this endpoint's identity or one of its addresses on its transport.
	FabricEndpointConditionConflict = "Conflict"
)

// Endpoint condition reasons.
const (
	// FabricEndpointReasonLocal is a usable endpoint of a router this cell
	// runs.
	FabricEndpointReasonLocal = "Local"
	// FabricEndpointReasonRemote is a usable endpoint of another cell's
	// router, which this cell cannot check against a BGPRouter.
	FabricEndpointReasonRemote = "Remote"
	// FabricEndpointReasonRouterNotFound is an endpoint of this cell
	// naming no BGPRouter.
	FabricEndpointReasonRouterNotFound = "RouterNotFound"
	// FabricEndpointReasonASNMismatch is an endpoint of this cell whose ASN
	// differs from its BGPRouter's.
	FabricEndpointReasonASNMismatch = "ASNMismatch"
	// FabricEndpointReasonInterfaceUnsupported is an endpoint naming an
	// interface, which the generator does not yet peer over.
	FabricEndpointReasonInterfaceUnsupported = "InterfaceUnsupported"
	// FabricEndpointReasonAddressInUse is an endpoint with an address an
	// older endpoint on the same transport already holds.
	FabricEndpointReasonAddressInUse = "AddressInUse"
	// FabricEndpointReasonDuplicate is a second endpoint for one router on
	// one transport.
	FabricEndpointReasonDuplicate = "DuplicateEndpoint"
	// FabricEndpointReasonNoConflict is an endpoint nothing else claims.
	FabricEndpointReasonNoConflict = "NoConflict"
)

// FabricEndpointStatus is this cell's view of an endpoint.
type FabricEndpointStatus struct {
	// ObservedGeneration is the generation the conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Local is true when a FabricTopology in this namespace generates
	// sessions for the endpoint's cell, so its router runs here.
	// +optional
	Local bool `json:"local,omitempty"`

	// Conditions are Ready and Conflict.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FabricEndpointList is a list of FabricEndpoint resources.
// +kubebuilder:object:root=true
type FabricEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricEndpoint{}, &FabricEndpointList{})
}
