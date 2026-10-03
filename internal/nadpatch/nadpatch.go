// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nadpatch records, on a pod's network-attachment definition, the
// deterministic host-side interface name a master plugin just created. Shared
// between the master plugins, since the annotation is identical whichever
// interface type was made.
package nadpatch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/hostconf"
)

// AnnotationHostInterface is the annotation key recording the deterministic
// host-side interface name created for this VPC and attachment pair.
const AnnotationHostInterface = "k8s.v1.cni.cncf.io/host-interface"

// AnnotationSubnetLen is the annotation key recording the prefix length of the
// address allocated to this attachment. A hypervisor that adopts the host
// device reads both keys together: the name tells it which device to attach,
// and the prefix length tells it what to configure on the guest side. Recording
// the name alone leaves such a consumer unable to use either.
const AnnotationSubnetLen = "k8s.v1.cni.cncf.io/subnet-len"

// nadGVK is the GroupVersionKind for NetworkAttachmentDefinition.
var nadGVK = schema.GroupVersionKind{
	Group:   "k8s.cni.cncf.io",
	Version: "v1",
	Kind:    "NetworkAttachmentDefinition",
}

// ParsePodNamespace extracts the pod namespace from the CNI arguments string
// the runtime passes. Returns "" when absent, as in a standalone invocation.
func ParsePodNamespace(cniArgs string) string {
	for _, part := range strings.Split(cniArgs, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && key == "K8S_POD_NAMESPACE" {
			return value
		}
	}
	return ""
}

// ParsePodName extracts the pod name from the CNI arguments string the runtime
// passes. Returns "" when absent, as ParsePodNamespace does.
func ParsePodName(cniArgs string) string {
	for _, part := range strings.Split(cniArgs, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && key == "K8S_POD_NAME" {
			return value
		}
	}
	return ""
}

// AnnotateNAD patches the attachment definition with the given annotations.
//
// The definition is expected to already exist, created by the external VPC
// operator before the CNI runs, so not-found is a hard failure. So is every
// other rejection: the patch states no resourceVersion precondition, so a
// repeat attach just reapplies it, and any error that does come back means the
// annotations never reached the definition.
//
// The patch is a merge patch so it touches only this one annotation. The
// definition belongs to the external operator and carries annotations from
// Multus, the CNI tooling, and whatever applied it; a patch that replaced the
// whole annotation map would drop all of them. A key-scoped JSON Patch would
// scope the write just as narrowly but fails outright on a definition that
// carries no annotations yet, which is the common case.
func AnnotateNAD(ctx context.Context, k8s client.Client, nadName, nadNamespace string,
	annotations map[string]string) error {
	if nadNamespace == "" {
		return nil
	}
	if len(annotations) == 0 {
		return nil
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(nadName)
	nad.SetNamespace(nadNamespace)

	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": annotations,
		},
	})
	if err != nil {
		return fmt.Errorf("build annotation patch for %s/%s: %w", nadNamespace, nadName, err)
	}

	err = k8s.Patch(ctx, nad, client.RawPatch(types.MergePatchType, patch))
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("NetworkAttachmentDefinition %s/%s not found: %w", nadNamespace, nadName, err)
		}
		return fmt.Errorf("patch NetworkAttachmentDefinition %s/%s: %w", nadNamespace, nadName, err)
	}
	slog.Debug("NAD annotated", "name", nadName, "namespace", nadNamespace, "annotations", annotations)
	return nil
}

// Expected is what the attaching plugin was handed on stdin and must find in
// the live attachment definition before it creates any kernel state.
type Expected struct {
	// ChainType is a plugin type the definition's conflist must chain.
	ChainType string
	// VPC and VPCAttachment are the identifiers the runtime passed. Every plugin
	// stanza in the definition that names an identifier must name these.
	VPC           string
	VPCAttachment string
}

// VerifyDefinition fetches the attachment definition from the API server and
// fails unless it is live, chains want.ChainType, and names the identifiers the
// runtime handed this plugin.
//
// The chain check exists because a conflist that omits the BGP plugin, whether
// stale, hand-edited, or a bug in the operator that authors it, would otherwise
// let every plugin that does run report success, handing back a pod with a
// working interface and no path to its VPC.
//
// The identity checks exist because the runtime's copy of the definition can
// trail the API server's. A workload recreated under the same names gets a
// definition of the same name, and a pod can start from the previous
// incarnation's copy while that one is being deleted or after the operator has
// written a new attachment identifier into its replacement. Attaching with the
// old identifier publishes host interfaces and advertisements the attachment
// record no longer describes, and the pod still comes up looking healthy. Both
// cases fail with "try again later" so the runtime retries the sandbox, rereads
// the definition, and attaches with the identifier the record names.
//
// An empty nadNamespace, meaning no CNI arguments and so a manual rather than
// runtime-driven attach, is nothing to check: there is no definition to read.
func VerifyDefinition(ctx context.Context, k8s client.Client, nadName, nadNamespace string, want Expected) error {
	if nadNamespace == "" {
		return nil
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Name: nadName, Namespace: nadNamespace}, nad); err != nil {
		return &cnitypes.Error{Code: cnitypes.ErrInvalidNetworkConfig,
			Msg: fmt.Sprintf("get NetworkAttachmentDefinition %s/%s: %v", nadNamespace, nadName, err)}
	}

	if nad.GetDeletionTimestamp() != nil {
		return &cnitypes.Error{
			Code: cnitypes.ErrTryAgainLater,
			Msg: fmt.Sprintf("NetworkAttachmentDefinition %s/%s is being deleted; "+
				"refusing to attach with identifiers that may belong to a previous attachment",
				nadNamespace, nadName),
		}
	}

	configStr, found, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil || !found || configStr == "" {
		return &cnitypes.Error{Code: cnitypes.ErrInvalidNetworkConfig,
			Msg: fmt.Sprintf("NetworkAttachmentDefinition %s/%s has no spec.config", nadNamespace, nadName)}
	}

	if err := hostconf.VerifyChainIncludes([]byte(configStr), want.ChainType); err != nil {
		return err
	}
	return verifyIdentifiers([]byte(configStr), nadNamespace, nadName, want)
}

// verifyIdentifiers fails when any plugin stanza in the live conflist names a
// VPC or attachment identifier other than the ones the runtime passed. A stanza
// that names none, such as a third-party plugin, is not compared.
func verifyIdentifiers(configJSON []byte, nadNamespace, nadName string, want Expected) error {
	var conflist struct {
		Plugins []struct {
			Type          string `json:"type"`
			VPC           string `json:"vpc"`
			VPCAttachment string `json:"vpcattachment"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(configJSON, &conflist); err != nil {
		return &cnitypes.Error{Code: cnitypes.ErrInvalidNetworkConfig,
			Msg: fmt.Sprintf("parse NetworkAttachmentDefinition %s/%s config: %v", nadNamespace, nadName, err)}
	}

	for _, plugin := range conflist.Plugins {
		if plugin.VPC == "" && plugin.VPCAttachment == "" {
			continue
		}
		if plugin.VPC == want.VPC && plugin.VPCAttachment == want.VPCAttachment {
			continue
		}
		return &cnitypes.Error{
			Code: cnitypes.ErrTryAgainLater,
			Msg: fmt.Sprintf("stale attachment identifiers: runtime passed vpc %q vpcattachment %q, "+
				"but NetworkAttachmentDefinition %s/%s now names vpc %q vpcattachment %q for plugin %q",
				want.VPC, want.VPCAttachment, nadNamespace, nadName, plugin.VPC, plugin.VPCAttachment, plugin.Type),
		}
	}
	return nil
}
