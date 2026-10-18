// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FRRRouterParametersKind is the kind a fabric BGPRouterClass's
// parametersRef names.
const FRRRouterParametersKind = "FRRRouterParameters"

// FabricRouterRevision is one immutable, fully resolved configuration for
// one fabric router: the typed specs of every object the router's
// configuration depends on, captured at one moment, with the identities and
// digests that make an activation reproducible. It carries no Secret
// material and no rendered FRR text; the node agent compiles the
// configuration with the same compiler that produced the digests.
//
// The fabric router controller creates revisions and never updates them.
// Its name is the router's name and the first ten hex digits of the
// activation dependency digest, so identical inputs map to one object.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=frrev
// +kubebuilder:printcolumn:name="ROUTER",type="string",JSONPath=".spec.target.routerName"
// +kubebuilder:printcolumn:name="NODE",type="string",JSONPath=".spec.target.nodeName"
// +kubebuilder:printcolumn:name="DIGEST",type="string",JSONPath=".spec.activationDependencyDigest",priority=1
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type FabricRouterRevision struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec FabricRouterRevisionSpec `json:"spec"`
}

// FabricRouterRevisionSpec is a revision's content. It is immutable.
//
// +kubebuilder:validation:XValidation:rule="self.target == oldSelf.target && self.configuration == oldSelf.configuration && self.parameters == oldSelf.parameters && self.compiler == oldSelf.compiler && self.inputs == oldSelf.inputs && self.semanticsDigest == oldSelf.semanticsDigest && self.activationDependencyDigest == oldSelf.activationDependencyDigest && self.renderedDigest == oldSelf.renderedDigest",message="a revision is immutable; a new configuration is a new revision"
type FabricRouterRevisionSpec struct {
	// Target is the router and Node this revision configures.
	Target FabricRouterTarget `json:"target"`

	// Parameters identifies the FRRRouterParameters the configuration
	// used.
	Parameters FabricRevisionParameters `json:"parameters"`

	// Compiler identifies the compiler semantics and the FRR build the
	// configuration targets.
	Compiler FabricRevisionCompiler `json:"compiler"`

	// Configuration is the resolved typed configuration. It is validated
	// by the controller that writes it rather than by this schema, which
	// would otherwise repeat every source kind's rules.
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	Configuration FabricRouterConfiguration `json:"configuration"`

	// Inputs lists every object the configuration was resolved from.
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=4096
	Inputs []FabricRevisionInput `json:"inputs"`

	// SemanticsDigest is the SHA-256, in hex, of the configuration in
	// canonical JSON.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	SemanticsDigest string `json:"semanticsDigest"`

	// ActivationDependencyDigest is the SHA-256, in hex, over the target
	// identity, the semantics digest, the parameters identity and the
	// compiler and FRR versions. Two revisions with the same digest
	// activate identically.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	ActivationDependencyDigest string `json:"activationDependencyDigest"`

	// RenderedDigest is the SHA-256, in hex, of the frr.conf the compiler
	// renders from the configuration, so an agent can check that its own
	// compile matches.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	RenderedDigest string `json:"renderedDigest"`
}

// FabricRouterTarget is the router and Node a revision configures, by name
// and UID, so a recreated router or a replaced Node never inherits one.
type FabricRouterTarget struct {
	// RouterName is the BGPRouter's name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	RouterName string `json:"routerName"`

	// RouterUID is the BGPRouter's UID.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	RouterUID string `json:"routerUID"`

	// NodeName is the Node the router runs on.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName"`

	// NodeUID is the Node's UID. Empty when the Node was not found.
	// +optional
	// +kubebuilder:validation:MaxLength=36
	NodeUID string `json:"nodeUID,omitempty"`
}

// FabricRevisionParameters identifies the parameters a revision used.
type FabricRevisionParameters struct {
	// Name is the FRRRouterParameters name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// UID is the FRRRouterParameters UID.
	// +kubebuilder:validation:MaxLength=36
	UID string `json:"uid"`
}

// FabricRevisionCompiler identifies the compiler and FRR build.
type FabricRevisionCompiler struct {
	// SemanticsVersion is the compiler's semantics version; a change that
	// alters rendered output for the same input bumps it.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	SemanticsVersion string `json:"semanticsVersion"`

	// FRRVersion is the FRR build the configuration targets.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	FRRVersion string `json:"frrVersion"`
}

// FabricRevisionInput is one source object of a revision.
type FabricRevisionInput struct {
	// Kind is the object's kind.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`

	// Name is the object's name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// UID is the object's UID.
	// +kubebuilder:validation:MaxLength=36
	UID string `json:"uid"`

	// Generation is the object's metadata.generation when it was read.
	Generation int64 `json:"generation"`

	// Digest is the SHA-256, in hex, of the object's spec in canonical
	// JSON.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	Digest string `json:"digest"`
}

// FabricRouterConfiguration is the resolved typed configuration of one
// fabric router: the router and parameters specs, and the specs of every
// peer, profile, policy, list, set, advertisement and static route it
// renders, each list ordered by name.
type FabricRouterConfiguration struct {
	Router         BGPRouterSpec              `json:"router"`
	Parameters     FRRRouterParametersSpec    `json:"parameters"`
	Peers          []FabricNamedPeer          `json:"peers,omitempty"`
	Profiles       []FabricNamedPeerProfile   `json:"profiles,omitempty"`
	Policies       []FabricNamedPolicy        `json:"policies,omitempty"`
	PrefixLists    []FabricNamedPrefixList    `json:"prefixLists,omitempty"`
	CommunitySets  []FabricNamedCommunitySet  `json:"communitySets,omitempty"`
	Advertisements []FabricNamedAdvertisement `json:"advertisements,omitempty"`
	StaticRoutes   []FabricNamedStaticRoute   `json:"staticRoutes,omitempty"`
}

// FabricNamedPeer is a peer's name and spec.
type FabricNamedPeer struct {
	Name string      `json:"name"`
	Spec BGPPeerSpec `json:"spec"`
}

// FabricNamedPeerProfile is a peer profile's name and spec.
type FabricNamedPeerProfile struct {
	Name string             `json:"name"`
	Spec BGPPeerProfileSpec `json:"spec"`
}

// FabricNamedPolicy is a policy's name and spec.
type FabricNamedPolicy struct {
	Name string        `json:"name"`
	Spec BGPPolicySpec `json:"spec"`
}

// FabricNamedPrefixList is a prefix list's name and spec.
type FabricNamedPrefixList struct {
	Name string            `json:"name"`
	Spec BGPPrefixListSpec `json:"spec"`
}

// FabricNamedCommunitySet is a community set's name and spec.
type FabricNamedCommunitySet struct {
	Name string              `json:"name"`
	Spec BGPCommunitySetSpec `json:"spec"`
}

// FabricNamedAdvertisement is an advertisement's name and spec.
type FabricNamedAdvertisement struct {
	Name string               `json:"name"`
	Spec BGPAdvertisementSpec `json:"spec"`
}

// FabricNamedStaticRoute is a static route's name and spec.
type FabricNamedStaticRoute struct {
	Name string             `json:"name"`
	Spec BGPStaticRouteSpec `json:"spec"`
}

// FabricRouterRevisionList is a list of FabricRouterRevision resources.
// +kubebuilder:object:root=true
type FabricRouterRevisionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricRouterRevision `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricRouterRevision{}, &FabricRouterRevisionList{})
}
