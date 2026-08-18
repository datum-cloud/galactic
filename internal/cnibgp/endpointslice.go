// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"fmt"
	"log/slog"
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

// publishEndpointSlice creates or updates the per-pod discoveryv1.EndpointSlice
// that the HTTP-ingress extension server discovers VPC backends through (see
// crdnames.LabelTenantID's doc comment — Open Decision 2 of the #854 plan).
// One EndpointSlice per pod, named after the pod (crdnames.EndpointSliceName),
// IPv6-only (Open Decision 1: a dual-stack pod's IPv4 address is not
// published).
//
// Runs as its own step after publishBGPState returns successfully, not
// folded into its retry closure — see the #854 plan's Phase 4 rollback-risk
// note for why that sequencing, combined with fixing advertisementCreated's
// gating (bgp.go), is what keeps a failure here from ever causing rollback to
// delete a BGPAdvertisement still backing a live sibling.
//
// Also sets metadata.ownerReferences to the owning Pod (Open Decision 6 /
// Phase 8: the k8s garbage collector's own reclaim is the backstop for
// force-deleted/never-DEL'd pods; cmdDel's explicit delete, ops_del.go, is
// the fast, deterministic path for the common case).
func publishEndpointSlice(
	ctx context.Context, k8s client.Client, namespace, podName, vpc, vpcAttachment string, addr net.IP, sid netip.Addr,
) error {
	pod := &corev1.Pod{}
	if err := k8s.Get(ctx, client.ObjectKey{Name: podName, Namespace: namespace}, pod); err != nil {
		return fmt.Errorf("get owning Pod %s/%s: %w", namespace, podName, err)
	}

	name := crdnames.EndpointSliceName(podName)
	tenantID := crdnames.TenantIdentifier(vpc, vpcAttachment)

	slice := &discoveryv1.EndpointSlice{}
	getErr := k8s.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, slice)
	switch {
	case getErr == nil:
		// Naming-collision defensive check: EndpointSliceName is a trivial
		// passthrough of the pod's own name, so nothing but convention stops
		// some other EndpointSlice (Service-backed or otherwise) from
		// landing on this exact name/namespace. Bail rather than silently
		// start mutating an object this plugin doesn't own.
		if _, ok := slice.Labels[crdnames.LabelTenantID]; !ok {
			return fmt.Errorf(
				"EndpointSlice %s/%s already exists without a %s label — refusing to overwrite an object this plugin doesn't own",
				namespace, name, crdnames.LabelTenantID)
		}
	case apierrors.IsNotFound(getErr):
		slice = &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		}
	default:
		return fmt.Errorf("get EndpointSlice %s/%s: %w", namespace, name, getErr)
	}

	op, err := controllerutil.CreateOrUpdate(ctx, k8s, slice, func() error {
		if slice.Labels == nil {
			slice.Labels = make(map[string]string, 1)
		}
		slice.Labels[crdnames.LabelTenantID] = tenantID

		if slice.Annotations == nil {
			slice.Annotations = make(map[string]string, 2)
		}
		slice.Annotations[crdnames.AnnotationTenantID] = tenantID
		if sid.IsValid() {
			slice.Annotations[crdnames.AnnotationSID] = sid.String()
		} else {
			delete(slice.Annotations, crdnames.AnnotationSID)
		}

		slice.AddressType = discoveryv1.AddressTypeIPv6
		ready := true
		slice.Endpoints = []discoveryv1.Endpoint{{
			Addresses:  []string{addr.String()},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef: &corev1.ObjectReference{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
				UID:       pod.UID,
			},
		}}

		// Same namespace (Pod and EndpointSlice always are, here), so the
		// cross-namespace-owner restriction doesn't apply. Not a controller
		// ref (SetOwnerReference, not SetControllerReference) and
		// BlockOwnerDeletion left at its default false — ordering doesn't
		// matter for this object.
		return controllerutil.SetOwnerReference(pod, slice, k8s.Scheme())
	})
	if err != nil {
		return fmt.Errorf("apply EndpointSlice: %w", err)
	}
	slog.Debug("ADD: EndpointSlice applied", "name", name, "namespace", namespace,
		"tenantID", tenantID, "operation", op)
	return nil
}

// deleteEndpointSlice deletes the per-pod EndpointSlice cmdAdd published,
// treating not-found as success — see cmdDel's own doc comment for why DEL,
// unlike the rest of the chain's DEL paths, does real work here.
func deleteEndpointSlice(ctx context.Context, k8s client.Client, namespace, podName string) error {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.EndpointSliceName(podName),
			Namespace: namespace,
		},
	}
	if err := k8s.Delete(ctx, slice); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("delete EndpointSlice %s/%s: %w", namespace, slice.Name, err)
	}
	return nil
}
