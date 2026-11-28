// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeListenerServiceReference names the EdgeService that grants a listener's
// provider SocketAccess and PublicListener on its ingress gVPC.
type EdgeListenerServiceReference struct {
	// Namespace is the EdgeService's namespace, the ingress gVPC's namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`

	// Name is the EdgeService's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// EdgeListenerProtocol is the transport protocol of one listener port.
// +kubebuilder:validation:Enum=tcp;udp
type EdgeListenerProtocol string

// Listener port protocols.
const (
	EdgeListenerProtocolTCP EdgeListenerProtocol = "tcp"
	EdgeListenerProtocolUDP EdgeListenerProtocol = "udp"
)

// EdgeListenerPort is one public port and the port the provider's instances
// serve it on.
type EdgeListenerPort struct {
	// Protocol is tcp or udp.
	// +required
	Protocol EdgeListenerProtocol `json:"protocol"`

	// Port is the public port on the listener's addresses.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// BackendPort is the port each provider instance listens on, on its
	// listener attachment's address.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	BackendPort int32 `json:"backendPort"`
}

// EdgeListenerSessionAffinity selects which parts of a flow the gateway hashes
// to pick a backend, as NetworkService's sessionAffinity does.
// +kubebuilder:validation:Enum=None;ClientIP;ClientIPAndProtocol
type EdgeListenerSessionAffinity string

// Listener session affinities.
const (
	EdgeListenerSessionAffinityNone                EdgeListenerSessionAffinity = "None"
	EdgeListenerSessionAffinityClientIP            EdgeListenerSessionAffinity = "ClientIP"
	EdgeListenerSessionAffinityClientIPAndProtocol EdgeListenerSessionAffinity = "ClientIPAndProtocol"
)

// EdgeListenerFailurePolicy decides whether backends of unknown health, and a
// set whose backends are all unhealthy, receive traffic.
// +kubebuilder:validation:Enum=FailOpen;FailClosed
type EdgeListenerFailurePolicy string

// Listener failure policies.
const (
	EdgeListenerFailOpen   EdgeListenerFailurePolicy = "FailOpen"
	EdgeListenerFailClosed EdgeListenerFailurePolicy = "FailClosed"
)

// EdgeListenerSpec is the public addresses and ports the platform gives one
// provider. Only the platform authority writes it; no provider may.
// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef",message="providerRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.serviceRef == oldSelf.serviceRef",message="serviceRef is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.healthPort) || self.ports.exists(p, p.protocol == 'tcp')",message="healthPort is required when every port is udp: a health check probes a TCP port"
type EdgeListenerSpec struct {
	// ProviderRef is the provider the listener serves. It must list
	// PublicListener.
	// +required
	ProviderRef EdgeProviderReference `json:"providerRef"`

	// ServiceRef is the EdgeService granting the provider SocketAccess and
	// PublicListener on its ingress gVPC. The provider's listener
	// attachments are made against it.
	// +required
	ServiceRef EdgeListenerServiceReference `json:"serviceRef"`

	// Addresses are the public addresses, at most one IPv6 and one IPv4. Each
	// must fall in one of the cell's gateway VIP prefixes; core refuses any
	// other with AddressOutsidePool. An IPv4 address is written in dotted
	// form.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:items:MaxLength=39
	// +kubebuilder:validation:XValidation:rule="self.all(a, isIP(a))",message="addresses must be valid IPv4 or IPv6 addresses, IPv4 in dotted form"
	// +kubebuilder:validation:XValidation:rule="self.filter(a, isIP(a) && ip(a).family() == 6).size() <= 1",message="addresses may hold at most one IPv6 address"
	// +kubebuilder:validation:XValidation:rule="self.filter(a, isIP(a) && ip(a).family() == 4).size() <= 1",message="addresses may hold at most one IPv4 address"
	Addresses []string `json:"addresses"`

	// Ports are the public ports. Core writes one gateway NetworkService per
	// port. Two ports of one protocol cannot share a backendPort, since a
	// backend's reply is translated back to one public port.
	// +required
	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(p, self.exists_one(q, q.protocol == p.protocol && q.backendPort == p.backendPort))",message="two ports of one protocol cannot share a backendPort"
	Ports []EdgeListenerPort `json:"ports"`

	// HealthPort is the TCP port probed on each backend. Unset, it is the
	// first tcp port's backendPort. It is required when every port is udp.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	HealthPort *int32 `json:"healthPort,omitempty"`

	// SessionAffinity is copied into each of the listener's NetworkServices.
	// +optional
	// +kubebuilder:default=ClientIPAndProtocol
	SessionAffinity EdgeListenerSessionAffinity `json:"sessionAffinity,omitempty"`

	// FailurePolicy is copied into the health check of each of the listener's
	// NetworkServices.
	// +optional
	// +kubebuilder:default=FailOpen
	FailurePolicy EdgeListenerFailurePolicy `json:"failurePolicy,omitempty"`
}

// Condition types of an EdgeListener. Core (galactic-controller) sets both.
const (
	EdgeListenerAccepted   = "Accepted"
	EdgeListenerProgrammed = "Programmed"
)

// Reasons core gives on an EdgeListener's conditions.
const (
	// EdgeListenerReasonAccepted: Accepted is True.
	EdgeListenerReasonAccepted = "Accepted"
	// EdgeListenerReasonProviderNotApproved: the provider is unknown, not
	// approved, or does not list PublicListener.
	EdgeListenerReasonProviderNotApproved = "ProviderNotApproved"
	// EdgeListenerReasonCapabilityNotGranted: the service does not grant the
	// provider SocketAccess and PublicListener.
	EdgeListenerReasonCapabilityNotGranted = "CapabilityNotGranted"
	// EdgeListenerReasonAddressOutsidePool: an address is outside the cell's
	// gateway VIP prefixes.
	EdgeListenerReasonAddressOutsidePool = "AddressOutsidePool"
	// EdgeListenerReasonAddressClaimed: another service already serves an
	// address on one of the listener's protocols and ports.
	EdgeListenerReasonAddressClaimed = "AddressClaimed"
	// EdgeListenerReasonBackendsReady: Programmed is True.
	EdgeListenerReasonBackendsReady = "BackendsReady"
	// EdgeListenerReasonNoBackends: no listener attachment is serving.
	EdgeListenerReasonNoBackends = "NoBackends"
	// EdgeListenerReasonLocalBackendsExcluded: backends on nodes that
	// advertise the listener's addresses are excluded until gateway local
	// delivery is qualified.
	EdgeListenerReasonLocalBackendsExcluded = "LocalBackendsExcluded"
)

// EdgeListenerBackend is one listener attachment and whether it receives new
// flows.
type EdgeListenerBackend struct {
	// Attachment is the EdgeAttachment's namespace and name.
	// +required
	// +kubebuilder:validation:MaxLength=317
	Attachment string `json:"attachment"`

	// Node is the attachment's node.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node,omitempty"`

	// Address is the attachment's IPv6 address in the ingress gVPC.
	// +optional
	// +kubebuilder:validation:MaxLength=39
	Address string `json:"address,omitempty"`

	// Serving is whether the attachment receives new flows: it is
	// programmed, its instance lease is valid and its provider reports Ready.
	// +optional
	Serving bool `json:"serving,omitempty"`
}

// EdgeListenerStatus is written by core only.
type EdgeListenerStatus struct {
	// ObservedGeneration is the generation Conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions are Accepted and Programmed.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Backends are the provider's listener attachments.
	// +optional
	// +listType=map
	// +listMapKey=attachment
	// +kubebuilder:validation:MaxItems=1024
	Backends []EdgeListenerBackend `json:"backends,omitempty"`
}

// EdgeListener gives an approved provider public addresses and ports, served
// by the gateway nodes of the cell. It lives in the gateway namespace. The
// platform authority writes its spec and core its status; no provider writes
// either. Core turns each port into a gateway NetworkService whose backends are
// the provider's listener attachments.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.name`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeListener struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeListenerSpec `json:"spec"`

	// +optional
	Status EdgeListenerStatus `json:"status,omitempty"`
}

// EdgeListenerList is a list of EdgeListener.
// +kubebuilder:object:root=true
type EdgeListenerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeListener `json:"items"`
}
