// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FabricRouterControllerName is the controllerName of BGPRouterClasses whose
// routers are fabric underlay routers, compiled and rolled out by
// fabric-router-controller and applied by fabric-config-agent.
const FabricRouterControllerName = "galactic.datumapis.com/fabric-router"

// BGPRouterClass names the implementation that owns the BGPRouters
// referencing it, the way a GatewayClass or StorageClass does. Selecting a
// class is what lets several routing implementations coexist on one node:
// each acts only on routers of its own classes.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=bgprc
// +kubebuilder:printcolumn:name="CONTROLLER",type="string",JSONPath=".spec.controllerName"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPRouterClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPRouterClassSpec   `json:"spec,omitempty"`
	Status BGPRouterClassStatus `json:"status,omitempty"`
}

// BGPRouterClassSpec defines the implementation behind a BGPRouterClass.
type BGPRouterClassSpec struct {
	// ControllerName identifies the controller that owns routers of this
	// class, as a domain-prefixed path. Immutable.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/[A-Za-z0-9][-A-Za-z0-9_./]*$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="controllerName is immutable"
	ControllerName string `json:"controllerName"`

	// ParametersRef references the implementation's parameters for routers
	// of this class, such as FRRRouterParameters. Immutable: a parameter
	// change is a new parameters object referenced by a new class.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="parametersRef is immutable"
	ParametersRef *BGPRouterClassParametersRef `json:"parametersRef,omitempty"`
}

// BGPRouterClassParametersRef references a cluster-scoped parameters object.
type BGPRouterClassParametersRef struct {
	// Group is the API group of the parameters object.
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`

	// Kind is the kind of the parameters object.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`

	// Name is the name of the parameters object.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// BGPRouterClassStatus is the observed state of a BGPRouterClass, written by
// its controller.
type BGPRouterClassStatus struct {
	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BGPRouterClassList is a list of BGPRouterClass resources.
// +kubebuilder:object:root=true
type BGPRouterClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPRouterClass `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPRouterClass{}, &BGPRouterClassList{})
}
