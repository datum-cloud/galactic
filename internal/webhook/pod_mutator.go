// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

// maxAllocateAttempts bounds the allocate-then-create retry loop in
// createNAD: a NAD Create conflict means another concurrent admission
// request took the same ID between our List and our Create — see
// AllocateVPCAttachmentID's doc comment.
const maxAllocateAttempts = 5

// PodMutator implements admission.Handler for the VPC-attachment mutating
// webhook. On Pod CREATE, a pod carrying the annotationVPC annotation gets a
// VPCAttachment ID allocated and a NetworkAttachmentDefinition created, then
// gets patched to attach via that NAD — see package doc and this repo's
// design plan for the full rationale.
type PodMutator struct {
	// Client is used for both reads (cache-backed) and writes (direct to
	// the API server) — controller-runtime's client.Client already
	// provides this split transparently.
	Client client.Client

	// Decoder decodes the admitted Pod from the AdmissionRequest.
	Decoder admission.Decoder

	// NADDefaults supplies the galactic-owned conflist fields (MTU,
	// interface type, IPAM, terminations) VPCSpec doesn't carry.
	NADDefaults NADDefaults
}

var _ admission.Handler = &PodMutator{}

// networkSelectionElement mirrors the fields of Multus's
// NetworkSelectionElement this package needs to write. internal/gc reads
// this same annotation independently with its own equivalent local type —
// see its doc comment for why the two aren't shared.
type networkSelectionElement struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Handle implements admission.Handler. See this repo's design plan,
// "Handler logic," for the numbered steps this mirrors.
func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := m.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Step 2: reinvocation guard — a pod already carrying this annotation
	// was already processed by an earlier invocation of this same webhook.
	if _, done := pod.Annotations[annotationVPCAttachmentRef]; done {
		return admission.Allowed("already processed (reinvocation guard)")
	}

	// Step 3: silent no-op when the pod doesn't request a VPC.
	vpcName := pod.Annotations[annotationVPC]
	if vpcName == "" {
		return admission.Allowed("no " + annotationVPC + " annotation")
	}

	// Step 4: VPC attach is meaningless on host network.
	if pod.Spec.HostNetwork {
		return admission.Allowed("hostNetwork pod, VPC attach not applicable")
	}

	// Step 5: the named VPC must exist.
	var vpc cloudv1alpha1.VPC
	if err := m.Client.Get(ctx, client.ObjectKey{Name: vpcName, Namespace: req.Namespace}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return admission.Denied(fmt.Sprintf("vpc %q not found in namespace %q: pod not admitted", vpcName, req.Namespace))
		}
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("get vpc %q: %w", vpcName, err))
	}
	if vpc.Status.VPC == "" {
		return admission.Denied(fmt.Sprintf(
			"vpc %q has no assigned identifier yet (Status.VPC empty): pod not admitted", vpcName))
	}

	// Step 6: never create real objects on dry-run.
	if req.DryRun != nil && *req.DryRun {
		return admission.Allowed("dry-run, no changes made")
	}

	// Steps 7-9: allocate a free VPCAttachment ID and create its NAD,
	// bounded-retrying on an allocation collision.
	nadName, err := m.createNAD(ctx, &vpc, req.Namespace)
	if err != nil {
		if errors.Is(err, ErrIDSpaceExhausted) {
			return admission.Denied(fmt.Sprintf(
				"vpc %q has no free VPCAttachment IDs (0-65535 exhausted): pod not admitted", vpcName))
		}
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("create NAD: %w", err))
	}

	// Step 10: patch the pod.
	mutated := pod.DeepCopy()
	if err := appendNetworksAnnotation(mutated, nadName, req.Namespace); err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("append networks annotation: %w", err))
	}
	if mutated.Annotations == nil {
		mutated.Annotations = map[string]string{}
	}
	mutated.Annotations[annotationVPCAttachmentRef] = fmt.Sprintf("%s/%s", req.Namespace, nadName)

	marshaledPod, err := json.Marshal(mutated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("marshal mutated pod: %w", err))
	}

	// Step 11.
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

// createNAD allocates a VPCAttachment ID and creates the corresponding NAD,
// retrying (re-allocate, re-create) up to maxAllocateAttempts times if the
// Create collides with a concurrent admission request that took the same ID
// first (see AllocateVPCAttachmentID's doc comment). Returns the NAD's name.
func (m *PodMutator) createNAD(ctx context.Context, vpc *cloudv1alpha1.VPC, namespace string) (string, error) {
	var lastErr error
	for range maxAllocateAttempts {
		id, err := AllocateVPCAttachmentID(ctx, m.Client, vpc, namespace)
		if err != nil {
			return "", err
		}

		nadName := fmt.Sprintf("%s-%s", vpc.Status.VPC, id)
		nad, err := buildNAD(nadName, namespace, vpc.Status.VPC, vpc.Name, id, m.NADDefaults)
		if err != nil {
			return "", err
		}

		err = m.Client.Create(ctx, nad)
		if err == nil {
			return nadName, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		// Someone else took this ID between our List and our Create — retry.
		lastErr = err
	}
	return "", fmt.Errorf("allocate+create NAD for vpc %q: exhausted %d retries: %w",
		vpc.Name, maxAllocateAttempts, lastErr)
}

// appendNetworksAnnotation adds a NAD reference to the pod's Multus networks
// annotation, preserving whatever was already there (parse-merge, not
// string concat). The existing value may be a JSON array (the form this
// function itself produces) or Multus's comma-separated shorthand
// ("net1,net2", a legacy/manual form); either way the result is a JSON
// array, since that's the only form that can express namespace alongside name.
func appendNetworksAnnotation(pod *corev1.Pod, nadName, namespace string) error {
	var elements []networkSelectionElement
	if raw := pod.Annotations[networksAnnotation]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &elements); err != nil {
			names := strings.Split(raw, ",")
			elements = make([]networkSelectionElement, 0, len(names))
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name != "" {
					elements = append(elements, networkSelectionElement{Name: name})
				}
			}
		}
	}
	elements = append(elements, networkSelectionElement{Name: nadName, Namespace: namespace})

	encoded, err := json.Marshal(elements)
	if err != nil {
		return fmt.Errorf("marshal networks annotation: %w", err)
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[networksAnnotation] = string(encoded)
	return nil
}
