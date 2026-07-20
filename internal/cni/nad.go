// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// annotationHostInterface is the NAD annotation key that records the
// deterministic host-side interface name created by the CNI plugin for
// this VPC+VPCAttachment pair.
const annotationHostInterface = "k8s.v1.cni.cncf.io/host-interface"

// nadGVK is the GroupVersionKind for NetworkAttachmentDefinition.
var nadGVK = schema.GroupVersionKind{
	Group:   "k8s.cni.cncf.io",
	Version: "v1",
	Kind:    "NetworkAttachmentDefinition",
}

// parsePodNamespace extracts the K8S_POD_NAMESPACE value from the CNI_ARGS
// environment variable string passed as args.Args by Multus. Returns an empty
// string when the value is not present (e.g. standalone CNI invocation).
func parsePodNamespace(cniArgs string) string {
	for _, part := range strings.Split(cniArgs, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && key == "K8S_POD_NAMESPACE" {
			return value
		}
	}
	return ""
}

// annotateNAD patches the NetworkAttachmentDefinition with the host interface
// name. The NAD is expected to already exist (created by the external VPC
// operator before the CNI is invoked), so a not-found response is a hard
// failure rather than something to tolerate. A conflict response is the one
// case treated as non-fatal: it means the annotation was already applied by a
// previous invocation.
func annotateNAD(ctx context.Context, k8s client.Client, nadName, nadNamespace, hostInterface string) error {
	if nadNamespace == "" {
		return nil
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(nadName)
	nad.SetNamespace(nadNamespace)

	patch := fmt.Sprintf(`[{"op":"add","path":"/metadata/annotations","value":{"%s":"%s"}}]`,
		annotationHostInterface, hostInterface)

	err := k8s.Patch(ctx, nad, client.RawPatch(types.JSONPatchType, []byte(patch)))
	if err != nil {
		if apierrors.IsConflict(err) {
			slog.Debug("annotate NAD: already annotated by a previous invocation",
				"name", nadName, "namespace", nadNamespace)
			return nil
		}
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("NetworkAttachmentDefinition %s/%s not found: %w", nadNamespace, nadName, err)
		}
		return fmt.Errorf("patch NetworkAttachmentDefinition %s/%s: %w", nadNamespace, nadName, err)
	}
	slog.Debug("NAD annotated", "name", nadName, "namespace", nadNamespace, "interface", hostInterface)
	return nil
}
