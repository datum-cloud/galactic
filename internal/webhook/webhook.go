// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook implements galactic-webhook's mutating admission webhook:
// on Pod CREATE, a pod carrying the galactic.datumapis.com/vpc annotation
// gets a VPCAttachment ID allocated and a NetworkAttachmentDefinition
// created, then gets patched to attach via that NAD. See this repo's design
// plan (.local/plan-vpc-nad-webhook-plan.md) for the full rationale —
// notably why the webhook creates only the NAD and not the VPCAttachment CR
// itself (galactic-cni creates that, at ADD time, alongside
// BGPVRFInstance/BGPAdvertisement).
package webhook

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

const (
	// annotationVPC is the pod annotation requesting attachment to a VPC by
	// name — the value is the VPC CR's Kubernetes object name.
	annotationVPC = "galactic.datumapis.com/vpc"

	// annotationVPCAttachmentRef is the reinvocation guard: once set, this
	// pod has already been processed by this webhook — see Handle's step 2.
	// It is the only durable record of that fact available at admission
	// time, since pod.Name may still be empty (generateName not yet
	// resolved by the API server).
	annotationVPCAttachmentRef = "galactic.datumapis.com/vpc-attachment-ref"

	// networksAnnotation is the Multus annotation used to attach a pod to
	// one or more NetworkAttachmentDefinitions.
	networksAnnotation = "k8s.v1.cni.cncf.io/networks"

	// labelVPC marks a NAD as belonging to a given VPC (value: the VPC CR's
	// name) — both a query key for AllocateVPCAttachmentID's free-ID scan
	// and, deliberately, the same annotation key used on the pod itself
	// (annotationVPC): same meaning ("associated with this VPC") in both
	// places, not a competing convention.
	labelVPC = "galactic.datumapis.com/vpc"

	// labelAttachmentID records, on every NAD this webhook creates, the
	// base62 VPCAttachment ID baked into that NAD's conflist. This is the
	// allocator's only source of truth for which IDs are already taken —
	// not VPCAttachmentStatus.VPCAttachment, which galactic-cni writes
	// later and may not exist for a given ID yet. See AllocateVPCAttachmentID.
	labelAttachmentID = "galactic.datumapis.com/vpcattachment-id"
)

// nadGVK is the GroupVersionKind for NetworkAttachmentDefinition.
var nadGVK = schema.GroupVersionKind{
	Group:   "k8s.cni.cncf.io",
	Version: "v1",
	Kind:    "NetworkAttachmentDefinition",
}

// NewScheme builds the runtime.Scheme galactic-webhook needs: core types
// (for decoding admitted Pods) and the cloud.datumapis.com VPC types (for
// looking up the VPC a pod requests attachment to). NAD is handled as
// unstructured.Unstructured and needs no scheme registration — the same
// pattern internal/cni's nad.go already uses.
func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	return scheme
}
