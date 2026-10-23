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
	// the instance was created. The lease's renewStart is on that boot's
	// CLOCK_BOOTTIME, so galactic-edge applies no renewal of an instance
	// whose boot ID is not the node's current one.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	BootID string `json:"bootID"`
}

// EdgeLease is an instance's liveness lease, a record of internal/edge/claim
// that the instance's provider process holds and renews by compare-and-swap
// on the object's resourceVersion. Only the instance writes it.
type EdgeLease struct {
	// Holder identifies the provider process holding the lease, new for
	// every process start. Empty while nobody holds it.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	Holder string `json:"holder,omitempty"`

	// Incarnation identifies this lease record across its deletion and
	// recreation. Routes accept the instance only at the incarnation and
	// epoch they name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Incarnation string `json:"incarnation"`

	// Epoch advances when a holder acquires the lease, never on renewal.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Epoch int64 `json:"epoch,omitempty"`

	// Sequence advances on every renewal.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Sequence int64 `json:"sequence,omitempty"`

	// RenewStart is the holder's CLOCK_BOOTTIME reading, in nanoseconds,
	// taken before it sent the acquisition or renewal that wrote this
	// record. The lease is valid until RenewStart plus the cell's lease
	// duration on that clock.
	// +optional
	// +kubebuilder:validation:Minimum=0
	RenewStart int64 `json:"renewStart,omitempty"`

	// Released reports that the holder of Epoch stopped forwarding and gave
	// the lease up.
	// +optional
	Released bool `json:"released,omitempty"`
}

// EdgeInstanceStatus holds the instance's lease.
type EdgeInstanceStatus struct {
	// Lease is the instance's liveness lease. Unset until the instance
	// first writes it.
	// +optional
	Lease *EdgeLease `json:"lease,omitempty"`
}

// EdgeInstance is one running Galactic Edge provider pod and its liveness
// lease. Its attachments name it, and the foundation checks it against the
// pod it names before admitting them. Routes name it with its lease epoch;
// their forwarding gates stay open only while the lease is renewed. Its name
// is derived from the pod UID, so a retried create lands on the same object.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
// +kubebuilder:printcolumn:name="Epoch",type=integer,JSONPath=`.status.lease.epoch`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeInstanceSpec `json:"spec"`

	// +optional
	Status EdgeInstanceStatus `json:"status,omitempty"`
}

// EdgeInstanceList is a list of EdgeInstance.
// +kubebuilder:object:root=true
type EdgeInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeInstance `json:"items"`
}
