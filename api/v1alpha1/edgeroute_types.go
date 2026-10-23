// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeRouteClaim is a provider pod's claim on a route: the attachment that
// forwards the prefix and the instance lease, at one epoch, that keeps it
// forwarding. The pod writes it by compare-and-swap on the route's
// resourceVersion. A claim grants nothing until galactic-controller accepts
// it into the route's status.
type EdgeRouteClaim struct {
	// Attachment is the claiming EdgeAttachment's name, in the route's
	// namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Attachment string `json:"attachment"`

	// HolderPodUID is the claiming pod's metadata.uid. The provider's
	// admission binding requires it to be the pod the writer's token was
	// issued for.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	HolderPodUID string `json:"holderPodUID"`

	// HolderInstance is the claiming EdgeInstance's name, in the route's
	// namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	HolderInstance string `json:"holderInstance"`

	// InstanceEpoch is the epoch of the instance's lease the claim is held
	// under. The claim is valid only while that lease is valid at this epoch.
	// +required
	// +kubebuilder:validation:Minimum=1
	InstanceEpoch int64 `json:"instanceEpoch"`

	// Epoch is the claim's epoch. It advances whenever the attachment or the
	// instance epoch changes.
	// +required
	// +kubebuilder:validation:Minimum=1
	Epoch int64 `json:"epoch"`

	// Released reports that the holder of Epoch stopped forwarding and gave
	// the route up.
	// +optional
	Released bool `json:"released,omitempty"`
}

// EdgeRouteSpec is a provider's request to forward one prefix of a VPC
// through one of its attachments.
// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.vpcUID == oldSelf.vpcUID && self.prefix == oldSelf.prefix && self.incarnation == oldSelf.incarnation",message="providerRef, vpcUID, prefix and incarnation are immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.claim) || (has(self.claim) && self.claim.epoch >= oldSelf.claim.epoch)",message="the claim's epoch never decreases and the claim is never removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.claim) || !has(self.claim) || (self.claim.attachment == oldSelf.claim.attachment && self.claim.holderInstance == oldSelf.claim.holderInstance && self.claim.instanceEpoch == oldSelf.claim.instanceEpoch && self.claim.holderPodUID == oldSelf.claim.holderPodUID) || self.claim.epoch > oldSelf.claim.epoch",message="a new holder needs a new claim epoch"
type EdgeRouteSpec struct {
	// ProviderRef is the provider of the instances that claim the route.
	// +required
	ProviderRef EdgeProviderReference `json:"providerRef"`

	// VPCUID is the metadata.uid of the VPC the prefix is in.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	VPCUID string `json:"vpcUID"`

	// Prefix is the IPv6 prefix forwarded, a masked CIDR. It must be inside
	// the service's granted prefixes and must not overlap another route of
	// the VPC.
	// +required
	// +kubebuilder:validation:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="isCIDR(self) && cidr(self).ip().family() == 6 && cidr(self) == cidr(self).masked() && cidr(self).prefixLength() > 0",message="prefix must be a masked, non-default IPv6 CIDR"
	Prefix string `json:"prefix"`

	// Incarnation identifies this route object across its deletion and
	// recreation, set once at create. A recreated route has a new one, so no
	// acceptance of the old object applies to it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Incarnation string `json:"incarnation"`

	// Claim is the current claim on the route.
	// +optional
	Claim *EdgeRouteClaim `json:"claim,omitempty"`
}

// EdgeRouteHolder is the claim galactic-controller accepted: the only one
// any node forwards the prefix for.
type EdgeRouteHolder struct {
	// Epoch is the accepted claim epoch.
	// +required
	// +kubebuilder:validation:Minimum=1
	Epoch int64 `json:"epoch"`

	// Attachment is the accepted EdgeAttachment's name, in the route's
	// namespace.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Attachment string `json:"attachment"`

	// AttachmentUID is the accepted EdgeAttachment's metadata.uid.
	// +required
	// +kubebuilder:validation:MaxLength=36
	AttachmentUID string `json:"attachmentUID"`

	// Instance is the accepted EdgeInstance's name, in the route's
	// namespace.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Instance string `json:"instance"`

	// InstanceIncarnation is the incarnation of the instance's lease the
	// route was accepted under.
	// +required
	// +kubebuilder:validation:MaxLength=64
	InstanceIncarnation string `json:"instanceIncarnation"`

	// InstanceEpoch is the epoch of the instance's lease the route was
	// accepted under.
	// +required
	// +kubebuilder:validation:Minimum=1
	InstanceEpoch int64 `json:"instanceEpoch"`

	// Node is the node of the attachment, the only node that may forward
	// the prefix.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node"`

	// VPCNamespace is the namespace of the VPC, where its EdgeRouteIndex
	// lives.
	// +required
	// +kubebuilder:validation:MaxLength=63
	VPCNamespace string `json:"vpcNamespace"`
}

// Condition types galactic-controller sets on a route. Accepted is about the
// accepted holder: True while it may forward, False once it is revoked, after
// which only a new claim epoch is accepted. Claimed is about the claim in
// spec: True once it is the accepted holder, False with the reason while it
// is refused or waits for the previous holder to be fenced.
const (
	EdgeRouteAccepted = "Accepted"
	EdgeRouteClaimed  = "Claimed"
)

// EdgeRouteStatus is the route's acceptance and the fencing of its accepted
// holder.
type EdgeRouteStatus struct {
	// Conditions are Accepted and Claimed, set by galactic-controller.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Accepted is the holder galactic-controller last accepted, written only
	// after the route is committed to its VPC's EdgeRouteIndex. It stays
	// after a revocation, with Accepted False, so the node can confirm the
	// holder's gate closed.
	// +optional
	Accepted *EdgeRouteHolder `json:"accepted,omitempty"`

	// ClosedEpoch is the highest accepted epoch whose forwarding gate the
	// accepted holder's node confirmed closed. Only galactic-edge on that
	// node writes it, and it never decreases.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ClosedEpoch int64 `json:"closedEpoch,omitempty"`
}

// EdgeRoute is one prefix's forwarding claim in one VPC: which attachment of
// which provider instance forwards the prefix. It lives in the provider's
// namespace; its name is derived from the VPC UID and the prefix. Providers
// write the claim; only galactic-controller accepts one, and a node opens the
// prefix's forwarding gate only for the accepted holder, only while that
// holder's instance lease is valid.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Prefix",type=string,JSONPath=`.spec.prefix`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Attachment",type=string,JSONPath=`.status.accepted.attachment`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.accepted.node`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeRouteSpec `json:"spec"`

	// +optional
	Status EdgeRouteStatus `json:"status,omitempty"`
}

// EdgeRouteList is a list of EdgeRoute.
// +kubebuilder:object:root=true
type EdgeRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeRoute `json:"items"`
}

// EdgeRouteIndexEntry is one route the index holds: an accepted holder, or
// one whose fencing has not completed since its route was removed or
// revoked.
type EdgeRouteIndexEntry struct {
	// Prefix is the route's prefix.
	// +required
	// +kubebuilder:validation:MaxLength=43
	Prefix string `json:"prefix"`

	// Route is the EdgeRoute's namespace and name.
	// +required
	// +kubebuilder:validation:MaxLength=317
	Route string `json:"route"`

	// RouteUID is the EdgeRoute's metadata.uid.
	// +required
	// +kubebuilder:validation:MaxLength=36
	RouteUID string `json:"routeUID"`

	// Epoch is the route's last accepted epoch.
	// +required
	// +kubebuilder:validation:Minimum=1
	Epoch int64 `json:"epoch"`

	// AttachmentUID is the accepted attachment's metadata.uid.
	// +required
	// +kubebuilder:validation:MaxLength=36
	AttachmentUID string `json:"attachmentUID"`

	// Instance is the accepted instance's namespace and name.
	// +required
	// +kubebuilder:validation:MaxLength=317
	Instance string `json:"instance"`

	// InstanceIncarnation is the incarnation of the instance's lease the
	// route was accepted under.
	// +required
	// +kubebuilder:validation:MaxLength=64
	InstanceIncarnation string `json:"instanceIncarnation"`

	// InstanceEpoch is the epoch of the instance's lease the route was
	// accepted under.
	// +required
	// +kubebuilder:validation:Minimum=1
	InstanceEpoch int64 `json:"instanceEpoch"`

	// Node is the accepted attachment's node.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node"`

	// Removing, when set, is why the entry is leaving: the route is gone or
	// its holder revoked. The entry stays until the holder's gate is
	// confirmed closed or galactic-controller has waited the takeover
	// interval since it recorded the removal.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	Removing string `json:"removing,omitempty"`
}

// EdgeRouteIndexSpec is every route accepted in one VPC.
// +kubebuilder:validation:XValidation:rule="self.vpcUID == oldSelf.vpcUID",message="vpcUID is immutable"
type EdgeRouteIndexSpec struct {
	// VPCUID is the VPC's metadata.uid, also the index's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	VPCUID string `json:"vpcUID"`

	// Routes are the accepted routes, keyed by prefix. No two overlap.
	// +optional
	// +listType=map
	// +listMapKey=prefix
	// +kubebuilder:validation:MaxItems=2048
	Routes []EdgeRouteIndexEntry `json:"routes,omitempty"`

	// Rebuilt is set when the index was rebuilt from routes' status after it
	// was lost. Entries of routes deleted meanwhile are gone, so no first
	// claim is accepted until galactic-controller has waited the takeover
	// interval and cleared it.
	// +optional
	Rebuilt bool `json:"rebuilt,omitempty"`
}

// EdgeRouteIndex is galactic-controller's record of every accepted
// EdgeRoute in one VPC. Acceptance is a compare-and-swap on it, so two
// controller replicas that both believe they lead cannot accept overlapping
// routes. It lives in the VPC's namespace, named by the VPC's UID. Only
// galactic-controller reads or writes it.
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcUID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeRouteIndex struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeRouteIndexSpec `json:"spec"`
}

// EdgeRouteIndexList is a list of EdgeRouteIndex.
// +kubebuilder:object:root=true
type EdgeRouteIndexList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeRouteIndex `json:"items"`
}
