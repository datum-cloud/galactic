// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Direction is a workload direction. Ingress is traffic delivered to the
// workload through the interface; egress is traffic the workload sends
// through it.
type Direction string

const (
	// DirectionIngress is traffic the workload receives.
	DirectionIngress Direction = "Ingress"
	// DirectionEgress is traffic the workload sends.
	DirectionEgress Direction = "Egress"
)

// LocalPolicyReference names a TrafficPolicy in the binding's own namespace.
// There is no namespace field, so a binding can never refer to another
// tenant's policy.
type LocalPolicyReference struct {
	// Name is the TrafficPolicy's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// TrafficPolicyBindingSpec names the policy for each direction of one
// interface. An omitted reference selects the built-in default, whose only
// rule denies everything, for that direction alone.
type TrafficPolicyBindingSpec struct {
	// IngressPolicyRef is the policy for traffic delivered to the workload.
	// +optional
	IngressPolicyRef *LocalPolicyReference `json:"ingressPolicyRef,omitempty"`

	// EgressPolicyRef is the policy for traffic the workload sends.
	// +optional
	EgressPolicyRef *LocalPolicyReference `json:"egressPolicyRef,omitempty"`
}

// PolicyIdentity identifies the policy a direction resolved to. UID is the
// policy's API UID, or DefaultPolicyUID when the reference is omitted.
type PolicyIdentity struct {
	// Name is the policy's name.
	// +required
	Name string `json:"name"`

	// UID is the policy's API UID, or DefaultPolicyUID for the built-in
	// default.
	// +required
	UID string `json:"uid"`

	// Generation is the policy's metadata.generation, 0 for the built-in
	// default.
	// +optional
	Generation int64 `json:"generation,omitempty"`
}

// DirectionStatus reports what one direction's reference resolved to.
type DirectionStatus struct {
	// Policy is the resolved policy, absent while the reference is
	// unresolved.
	// +optional
	Policy *PolicyIdentity `json:"policy,omitempty"`

	// Conditions include Resolved.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AppliedState is how far one node's installation of a direction has got.
// +kubebuilder:validation:Enum=Applied;Pending;Failed
type AppliedState string

const (
	// StateApplied means the desired policy is installed.
	StateApplied AppliedState = "Applied"
	// StatePending means the desired policy is not installed yet.
	StatePending AppliedState = "Pending"
	// StateFailed means installing the desired policy failed.
	StateFailed AppliedState = "Failed"
)

// AppliedPolicy is what one node has installed for one direction.
type AppliedPolicy struct {
	// Policy is the installed policy's identity, absent when nothing is
	// installed and the direction denies as policy_unavailable.
	// +optional
	Policy *PolicyIdentity `json:"policy,omitempty"`

	// State is Applied when Policy is installed and matches the desired
	// policy, Pending while it is not yet, and Failed when installation
	// failed. A Failed direction keeps enforcing Policy, its last good
	// snapshot, or denies when there is none.
	// +required
	State AppliedState `json:"state"`

	// ObservedGeneration is the binding generation this entry reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message explains a Pending or Failed state.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when Policy last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// NodeBindingStatus is what one node enforces for the interface. Each node
// writes only its own entry, and removes it once the interface has left the
// node.
type NodeBindingStatus struct {
	// Node is the node's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node"`

	// Ingress is the node's installed ingress policy.
	// +optional
	Ingress *AppliedPolicy `json:"ingress,omitempty"`

	// Egress is the node's installed egress policy.
	// +optional
	Egress *AppliedPolicy `json:"egress,omitempty"`
}

// TrafficPolicyBindingStatus separates what the API asked for from what each
// node enforces. Admission success is never reported as convergence.
type TrafficPolicyBindingStatus struct {
	// ObservedGeneration is the generation Ingress and Egress describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Ingress is the resolved ingress reference.
	// +optional
	Ingress *DirectionStatus `json:"ingress,omitempty"`

	// Egress is the resolved egress reference.
	// +optional
	Egress *DirectionStatus `json:"egress,omitempty"`

	// Nodes lists what each node with the interface enforces.
	// +optional
	// +listType=map
	// +listMapKey=node
	// +kubebuilder:validation:MaxItems=64
	Nodes []NodeBindingStatus `json:"nodes,omitempty"`
}

// TrafficPolicyBinding binds an ingress and an egress TrafficPolicy to one
// VPC interface. It has no attachment field: it applies to the VPCAttachment
// with the same namespace and name, so an interface can never have two
// bindings.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tpb,categories=galactic
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.spec.ingressPolicyRef.name`
// +kubebuilder:printcolumn:name="Egress",type=string,JSONPath=`.spec.egressPolicyRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TrafficPolicyBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec TrafficPolicyBindingSpec `json:"spec"`

	// +optional
	Status TrafficPolicyBindingStatus `json:"status,omitempty"`
}

// TrafficPolicyBindingList is a list of TrafficPolicyBinding.
// +kubebuilder:object:root=true
type TrafficPolicyBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficPolicyBinding `json:"items"`
}
