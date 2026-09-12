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

// AnnotateNAD patches the attachment definition with the host interface name.
//
// The definition is expected to already exist, created by the external VPC
// operator before the CNI runs, so not-found is a hard failure. So is every
// other rejection: the patch states no resourceVersion precondition, so a
// repeat attach just reapplies it, and any error that does come back means the
// host interface name never reached the definition.
//
// The patch is a merge patch so it touches only this one annotation. The
// definition belongs to the external operator and carries annotations from
// Multus, the CNI tooling, and whatever applied it; a patch that replaced the
// whole annotation map would drop all of them. A key-scoped JSON Patch would
// scope the write just as narrowly but fails outright on a definition that
// carries no annotations yet, which is the common case.
func AnnotateNAD(ctx context.Context, k8s client.Client, nadName, nadNamespace, hostInterface string) error {
	if nadNamespace == "" {
		return nil
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(nadName)
	nad.SetNamespace(nadNamespace)

	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{AnnotationHostInterface: hostInterface},
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
	slog.Debug("NAD annotated", "name", nadName, "namespace", nadNamespace, "interface", hostInterface)
	return nil
}

// VerifyChainComplete fetches the attachment definition and fails if its config
// does not chain expectedType anywhere in its plugin list.
//
// A conflist that omits it, whether stale, hand-edited, or a bug in the operator
// that authors it, would otherwise let every plugin that does run report success,
// handing back a pod with a working interface and no path to its VPC.
//
// An empty nadNamespace, meaning no CNI arguments and so a manual rather than
// runtime-driven attach, is nothing to check: there is no definition to read.
func VerifyChainComplete(ctx context.Context, k8s client.Client, nadName, nadNamespace, expectedType string) error {
	if nadNamespace == "" {
		return nil
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Name: nadName, Namespace: nadNamespace}, nad); err != nil {
		return fmt.Errorf("get NetworkAttachmentDefinition %s/%s: %w", nadNamespace, nadName, err)
	}

	configStr, found, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil || !found || configStr == "" {
		return fmt.Errorf("NetworkAttachmentDefinition %s/%s has no spec.config", nadNamespace, nadName)
	}

	return hostconf.VerifyChainIncludes([]byte(configStr), expectedType)
}
