// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeInstanceSpec identifies the provider pod an instance runs in. The pod
// writes it at create; a ValidatingAdmissionPolicy requires podUID to be the
// pod its token was issued for.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type EdgeInstanceSpec struct {
	// ProviderRef is the provider the instance runs. The provider's
	// admission binding checks the writer against it.
	// +required
	ProviderRef EdgeProviderReference `json:"providerRef"`

	// PodName is the provider pod's name, in the instance's namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	PodName string `json:"podName"`

	// PodUID is the provider pod's metadata.uid.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	PodUID string `json:"podUID"`

	// NodeName is the node the pod runs on.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName"`

	// BootID is the node's boot ID (/proc/sys/kernel/random/boot_id) when
	// the instance was created. Its lease's renew start is on that boot's
	// CLOCK_BOOTTIME, so galactic-edge applies no renewal of an instance
	// whose boot ID is not the node's current one.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	BootID string `json:"bootID"`
}

// An instance's liveness lease is a coordination.k8s.io/v1 Lease with the
// instance's namespace and name, owned by the instance. Its
// spec.holderIdentity is the provider process holding it, its
// spec.leaseTransitions the lease epoch and its metadata.uid the lease
// incarnation; these labels and annotations carry the rest. A lease missing
// any of them, or naming another provider, pod or owner, is no lease.
const (
	// EdgeLeaseProviderLabel names the instance's provider.
	EdgeLeaseProviderLabel = "galactic.datumapis.com/edge-provider"
	// EdgeLeasePodUIDAnnotation is the instance's spec.podUID.
	EdgeLeasePodUIDAnnotation = "galactic.datumapis.com/edge-pod-uid"
	// EdgeLeaseRenewStartAnnotation is the holder's CLOCK_BOOTTIME reading,
	// in decimal nanoseconds, taken before it sent the acquisition or
	// renewal that wrote the lease. The lease is valid until that reading
	// plus the cell's lease duration on that clock.
	EdgeLeaseRenewStartAnnotation = "galactic.datumapis.com/edge-renew-start"
	// EdgeLeaseSequenceAnnotation advances, in decimal, on every renewal.
	EdgeLeaseSequenceAnnotation = "galactic.datumapis.com/edge-sequence"
	// EdgeLeaseReleasedAnnotation is "true" once the holder of the epoch
	// stopped forwarding and gave the lease up, and "false" otherwise.
	EdgeLeaseReleasedAnnotation = "galactic.datumapis.com/edge-released"
)

// EdgeInstance is one running Galactic Edge provider pod. Its attachments
// name it, and the foundation checks it against the pod it names before
// admitting them. Routes name it with its lease's incarnation and epoch, and
// their forwarding gates stay open only while that lease is renewed. Its name
// is derived from the pod UID, so a retried create lands on the same object.
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeInstanceSpec `json:"spec"`
}

// EdgeInstanceList is a list of EdgeInstance.
// +kubebuilder:object:root=true
type EdgeInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeInstance `json:"items"`
}
