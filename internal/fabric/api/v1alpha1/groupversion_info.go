// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1alpha1 contains the FabricQuery API, the internal
// network.datumapis.com/v1alpha1 kind NSO writes on the federation hub, one
// per resolved edge cell, and the cell's fabric-api gateway executes.
//
// It belongs in the network repository beside EgressShard; it is defined
// here until it ships there, with the same group and version, so galactic can
// switch to the network import without a wire change.
// +kubebuilder:object:generate=true
// +groupName=network.datumapis.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "network.datumapis.com", Version: "v1alpha1"}

	// SchemeBuilder adds this package's kinds to a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &FabricQuery{}, &FabricQueryList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
