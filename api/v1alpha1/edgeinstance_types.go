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
}

// EdgeInstance is one running Galactic Edge provider pod. Its attachments
// name it, and the foundation checks it against the pod it names before
// admitting them. Its name is derived from the pod UID, so a retried create
// lands on the same object.
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
