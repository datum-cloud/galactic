// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PortRange is an inclusive transport port interval.
// +kubebuilder:validation:XValidation:rule="self.start <= self.end",message="port range start must not exceed end"
type PortRange struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// NetworkServiceAddressListener describes one socket interval in an address group.
// +kubebuilder:validation:XValidation:rule="has(self.port) != has(self.portRange)",message="exactly one of port and portRange is required"
// +kubebuilder:validation:XValidation:rule="!has(self.portRange) || self.protocol == 'udp'",message="ranges require UDP"
type NetworkServiceAddressListener struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol NetworkServiceProtocol `json:"protocol"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`
	// +optional
	PortRange *PortRange `json:"portRange,omitempty"`
}

// NetworkServiceAddressGroup identifies the complete desired listener inventory of one allocated VIP.
// +kubebuilder:validation:XValidation:rule="!has(self.listenerName) || self.listeners.exists(l, l.name == self.listenerName)",message="listenerName must identify a declared listener"
type NetworkServiceAddressGroup struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	UID string `json:"uid"`
	// +kubebuilder:validation:Minimum=1
	Generation int64 `json:"generation"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Revision string `json:"revision"`
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	ListenerName string `json:"listenerName,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	Listeners []NetworkServiceAddressListener `json:"listeners"`
}

// NetworkServiceAddressSpec is the authoritative listener inventory for one allocated address.
// +kubebuilder:validation:XValidation:rule="self.vpcRef == oldSelf.vpcRef && self.vipAddress == oldSelf.vipAddress && self.group.uid == oldSelf.group.uid",message="address allocation identity is immutable"
// +kubebuilder:validation:XValidation:rule="self.group.generation >= oldSelf.group.generation",message="address generation must not regress"
// +kubebuilder:validation:XValidation:rule="self.group.generation != oldSelf.group.generation || self.group == oldSelf.group",message="equal generations must have identical inventories"
// +kubebuilder:validation:XValidation:rule="!has(self.group.listenerName)",message="address inventory must not select an individual listener"
type NetworkServiceAddressSpec struct {
	// +kubebuilder:validation:MinLength=1
	VPCRef string `json:"vpcRef"`
	// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 6",message="VIP must be IPv6"
	VIPAddress string                     `json:"vipAddress"`
	Group      NetworkServiceAddressGroup `json:"group"`
}

// NetworkServiceAddress coordinates forwarding and withdrawal for a shared address.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=svcaddr
type NetworkServiceAddress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NetworkServiceAddressSpec   `json:"spec"`
	Status            NetworkServiceAddressStatus `json:"status,omitempty"`
}

// NetworkServiceAddressStatus reports address-level convergence.
type NetworkServiceAddressStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NetworkServiceAddressList contains address inventories.
// +kubebuilder:object:root=true
type NetworkServiceAddressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkServiceAddress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkServiceAddress{}, &NetworkServiceAddressList{})
}

const (
	CapabilitySharedAddressListeners = "SharedAddressListeners"
	CapabilityUDPPortRanges          = "UDPPortRanges"
)
