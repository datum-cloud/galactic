// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package podslice owns the per-pod EndpointSlice the HTTP ingress extension
// server discovers VPC backends through: one slice per pod, named after the
// pod, in the pod's own namespace, and IPv6-only. galactic-bgp publishes it on
// CNI ADD and deletes it on CNI DEL; galactic-cni's node-side repair recreates
// one that has gone missing.
package podslice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/crdnames"
)

// Endpoint is what a pod's EndpointSlice publishes.
type Endpoint struct {
	// VPC and VPCAttachment identify the attachment, published as the
	// tenant identifier label and annotation.
	VPC           string
	VPCAttachment string
	// Addr is the pod's IPv6 address on the attachment.
	Addr net.IP
	// SID is the SRv6 uSID routing to the pod's VRF. The zero value omits the
	// annotation, for a node whose BGPRouter has no SRv6 identity.
	SID netip.Addr
	// SandboxID is the container ID of the sandbox whose ADD writes the
	// slice. Empty omits the annotation, which leaves the slice to the owner
	// reference rather than to any DEL.
	SandboxID string
}

// Publish creates or updates the EndpointSlice for pod podName in namespace.
//
// It sets an owner reference to the pod, so the cluster's garbage collector
// reclaims the slice of a pod that is deleted without a DEL removing it.
// An existing slice of that name without the tenant identifier label is
// refused rather than overwritten, since this package did not write it.
func Publish(ctx context.Context, k8s client.Client, namespace, podName string, ep Endpoint) error {
	pod := &corev1.Pod{}
	if err := k8s.Get(ctx, client.ObjectKey{Name: podName, Namespace: namespace}, pod); err != nil {
		return fmt.Errorf("get owning Pod %s/%s: %w", namespace, podName, err)
	}

	name := crdnames.EndpointSliceName(podName)
	slice := &discoveryv1.EndpointSlice{}
	getErr := k8s.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, slice)
	switch {
	case getErr == nil:
		// Defensive against a naming collision: the slice name is a
		// passthrough of the pod's name, so nothing but convention stops
		// another slice from landing on this exact name.
		if _, ok := slice.Labels[crdnames.LabelTenantID]; !ok {
			return fmt.Errorf(
				"EndpointSlice %s/%s already exists without a %s label — refusing to overwrite an object this plugin doesn't own",
				namespace, name, crdnames.LabelTenantID)
		}
	case apierrors.IsNotFound(getErr):
		slice = &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	default:
		return fmt.Errorf("get EndpointSlice %s/%s: %w", namespace, name, getErr)
	}

	if _, err := controllerutil.CreateOrUpdate(ctx, k8s, slice, func() error {
		return apply(k8s, slice, pod, ep)
	}); err != nil {
		return fmt.Errorf("apply EndpointSlice: %w", err)
	}
	return nil
}

// Restore creates the EndpointSlice for pod if none exists, and reports
// whether it did. It never updates an existing slice: one that appears
// between the caller's read and this create was written by an ADD with
// fresher state than the caller's.
func Restore(ctx context.Context, k8s client.Client, pod *corev1.Pod, ep Endpoint) (bool, error) {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: crdnames.EndpointSliceName(pod.Name), Namespace: pod.Namespace},
	}
	if err := apply(k8s, slice, pod, ep); err != nil {
		return false, err
	}
	if err := k8s.Create(ctx, slice); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return false, nil
		}
		return false, fmt.Errorf("create EndpointSlice %s/%s: %w", slice.Namespace, slice.Name, err)
	}
	return true, nil
}

// Delete deletes the EndpointSlice for pod podName in namespace when sandboxID
// wrote it, and reports whether it did.
//
// A slice naming another sandbox, or none, is left in place: the runtime can
// tear down a pod's previous sandbox after its replacement's ADD, and that DEL
// must not remove the replacement's slice. The delete is preconditioned on
// the UID and resourceVersion read, so an ADD landing between the read and
// the delete is never removed either. Not-found and a failed precondition
// both report false with no error.
func Delete(ctx context.Context, k8s client.Client, namespace, podName, sandboxID string) (bool, error) {
	name := crdnames.EndpointSliceName(podName)
	slice := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, slice); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get EndpointSlice %s/%s: %w", namespace, name, err)
	}
	if sandboxID == "" || slice.Annotations[crdnames.AnnotationSandboxID] != sandboxID {
		return false, nil
	}

	uid, rv := slice.UID, slice.ResourceVersion
	err := k8s.Delete(ctx, slice, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err), apierrors.IsConflict(err):
		return false, nil
	default:
		return false, fmt.Errorf("delete EndpointSlice %s/%s: %w", namespace, name, err)
	}
}

// apply sets slice's labels, annotations, endpoint and owner reference from
// pod and ep, leaving any other labels and annotations in place.
func apply(k8s client.Client, slice *discoveryv1.EndpointSlice, pod *corev1.Pod, ep Endpoint) error {
	if ep.Addr == nil {
		return errors.New("EndpointSlice endpoint has no address")
	}
	tenantID := crdnames.TenantIdentifier(ep.VPC, ep.VPCAttachment)

	if slice.Labels == nil {
		slice.Labels = make(map[string]string, 1)
	}
	slice.Labels[crdnames.LabelTenantID] = tenantID

	if slice.Annotations == nil {
		slice.Annotations = make(map[string]string, 3)
	}
	slice.Annotations[crdnames.AnnotationTenantID] = tenantID
	if ep.SID.IsValid() {
		slice.Annotations[crdnames.AnnotationSID] = ep.SID.String()
	} else {
		delete(slice.Annotations, crdnames.AnnotationSID)
	}
	if ep.SandboxID != "" {
		slice.Annotations[crdnames.AnnotationSandboxID] = ep.SandboxID
	} else {
		delete(slice.Annotations, crdnames.AnnotationSandboxID)
	}

	slice.AddressType = discoveryv1.AddressTypeIPv6
	ready := true
	slice.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{ep.Addr.String()},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		TargetRef: &corev1.ObjectReference{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
			UID:       pod.UID,
		},
	}}

	// Pod and slice are always in the same namespace, so the cross-namespace
	// restriction does not apply. Not a controller reference, and not
	// blocking owner deletion: ordering does not matter for this object.
	return controllerutil.SetOwnerReference(pod, slice, k8s.Scheme())
}
