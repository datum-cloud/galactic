// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeProviderApproval is the operator's approval of the EdgeProvider of the
// same name. While it exists, galactic-controller sets that provider's
// status.approved; deleting it withdraws the approval and every binding
// issued to the provider. It is a kind of its own, not a field of the
// EdgeProvider, so that approving a provider takes a privilege that
// registering one does not, and an operator can keep it in the same Git
// source that deploys the provider.
//
// An approval names a provider, not one registration of it: it also covers
// a later change to the provider's spec, or a provider deleted and
// registered again under the same name. Deleting a provider leaves its
// approval in place.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,categories=galactic
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeProviderApproval struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

// EdgeProviderApprovalList is a list of EdgeProviderApproval.
// +kubebuilder:object:root=true
type EdgeProviderApprovalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeProviderApproval `json:"items"`
}
