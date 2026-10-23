// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeCapability is a capability a provider implements, at one version, such
// as PacketAccess v1.
type EdgeCapability struct {
	// Name is the capability's name.
	// +required
	// +kubebuilder:validation:Enum=SocketAccess;PacketAccess;PrefixReachability
	Name string `json:"name"`

	// Version is the capability's version.
	// +required
	// +kubebuilder:validation:Pattern=`^v[1-9][0-9]*$`
	Version string `json:"version"`
}

// ServiceAccountReference names one ServiceAccount.
type ServiceAccountReference struct {
	// Namespace is the ServiceAccount's namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`

	// Name is the ServiceAccount's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ConfigurationKind names the provider-owned resource its services' own
// configuration is written in.
type ConfigurationKind struct {
	// Group is the resource's API group.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`

	// Kind is the resource's kind.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`
}

// EdgeProviderSpec is what a provider implements and which identities speak
// for it. It grants no tenant authority.
type EdgeProviderSpec struct {
	// ContractVersions are the provider contract versions it speaks.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:Pattern=`^v[0-9]+((alpha|beta)[0-9]+)?$`
	ContractVersions []string `json:"contractVersions"`

	// Capabilities are the capability versions it implements.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Capabilities []EdgeCapability `json:"capabilities"`

	// ServiceAccounts are the only identities whose bound tokens act for the
	// provider. A request from any other identity is refused. The
	// foundation's own identities cannot be listed.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(sa, !(sa.namespace == 'galactic-system' && sa.name in ['galactic-controller', 'galactic-edge']))",message="the foundation's ServiceAccounts cannot act for a provider"
	ServiceAccounts []ServiceAccountReference `json:"serviceAccounts"`

	// Configuration is the kind of the provider's own per-service
	// configuration.
	// +required
	Configuration ConfigurationKind `json:"configuration"`
}

// EdgeProviderStatus records the operator's approval.
type EdgeProviderStatus struct {
	// Approved is set by the operator's approval. No provider identity may
	// write it. An unapproved provider is refused admission, and clearing it
	// revokes every authorization issued to the provider.
	// +optional
	Approved bool `json:"approved,omitempty"`
}

// EdgeProvider registers a Galactic Edge provider: the contract and
// capability versions it implements, the ServiceAccounts that act for it, and
// the kind of its own configuration.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=galactic
// +kubebuilder:printcolumn:name="Approved",type=boolean,JSONPath=`.status.approved`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeProviderSpec `json:"spec"`

	// +optional
	Status EdgeProviderStatus `json:"status,omitempty"`
}

// EdgeProviderList is a list of EdgeProvider.
// +kubebuilder:object:root=true
type EdgeProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeProvider `json:"items"`
}
