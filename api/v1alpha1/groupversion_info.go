// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1alpha1 contains Galactic's own API, galactic.datumapis.com/v1alpha1:
// TrafficPolicy and TrafficPolicyBinding, the per-interface ingress and
// egress policy the CNI datapath enforces (see
// docs/enhancements/networking/interface-traffic-policy), and EdgeProvider
// and EdgeService, the Galactic Edge provider registration and tenant grant
// (see docs/enhancements/networking/galactic-edge).
// +kubebuilder:object:generate=true
// +groupName=galactic.datumapis.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "galactic.datumapis.com", Version: "v1alpha1"}

	// SchemeBuilder adds this package's kinds to a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&TrafficPolicy{}, &TrafficPolicyList{},
		&TrafficPolicyBinding{}, &TrafficPolicyBindingList{},
		&EdgeProvider{}, &EdgeProviderList{},
		&EdgeService{}, &EdgeServiceList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
