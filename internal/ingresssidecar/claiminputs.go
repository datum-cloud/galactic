// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// tenantIndex indexes VPCAttachments by the TenantIdentifier of their
// recorded VPC and attachment identifiers, the value a backend's
// EndpointSlice carries.
const tenantIndex = "galactic.status.tenantIdentifier"

// RegisterClaimIndexes adds the field index KubeClaimInputs needs to a cache.
func RegisterClaimIndexes(ctx context.Context, idx client.FieldIndexer) error {
	return idx.IndexField(ctx, &cloudv1alpha1.VPCAttachment{}, tenantIndex, func(o client.Object) []string {
		a, ok := o.(*cloudv1alpha1.VPCAttachment)
		if !ok || a.Status.VPC == "" || a.Status.VPCAttachment == "" {
			return nil
		}
		return []string{crdnames.TenantIdentifier(a.Status.VPC, a.Status.VPCAttachment)}
	})
}

// KubeClaimInputs reads the claim inputs from the API server through a cache
// with RegisterClaimIndexes.
type KubeClaimInputs struct {
	Reader client.Reader
	// Namespace holds the proxy's VPCAttachments.
	Namespace string
	// Selector selects the proxy's VPCAttachments in Namespace. They are
	// NSO's to create, one per VPC and node the proxy serves.
	Selector labels.Selector
	// Node is this node; only attachments whose status records it are the
	// proxy's here.
	Node string
	Log  *slog.Logger
}

var _ ClaimInputs = (*KubeClaimInputs)(nil)

// Attachments implements ClaimInputs.
func (k *KubeClaimInputs) Attachments(ctx context.Context) ([]ProxyAttachment, error) {
	var list cloudv1alpha1.VPCAttachmentList
	if err := k.Reader.List(ctx, &list, client.InNamespace(k.Namespace),
		client.MatchingLabelsSelector{Selector: k.Selector}); err != nil {
		return nil, fmt.Errorf("list VPCAttachments: %w", err)
	}
	var out []ProxyAttachment
	for _, a := range list.Items {
		if !a.DeletionTimestamp.IsZero() || a.Status.Node != k.Node || a.Status.VPC == "" {
			continue
		}
		out = append(out, ProxyAttachment{VPC: a.Status.VPC, UID: string(a.UID),
			Addresses: specAddresses(a.Spec.Interface.Addresses)})
	}
	return out, nil
}

// Backends implements ClaimInputs. A backend whose VPCAttachment is not
// found yet is left out until it is.
func (k *KubeClaimInputs) Backends(ctx context.Context) ([]BackendAttachment, error) {
	req, err := labels.NewRequirement(crdnames.LabelTenantID, selection.Exists, nil)
	if err != nil {
		return nil, err
	}
	var slices discoveryv1.EndpointSliceList
	sel := client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*req)}
	if err := k.Reader.List(ctx, &slices, sel); err != nil {
		return nil, fmt.Errorf("list EndpointSlices: %w", err)
	}
	var out []BackendAttachment
	for i := range slices.Items {
		s := &slices.Items[i]
		route, err := BuildDesiredRoute(s)
		if err != nil || route == nil {
			continue
		}
		tenant := s.Annotations[crdnames.AnnotationTenantID]
		var atts cloudv1alpha1.VPCAttachmentList
		if err := k.Reader.List(ctx, &atts, client.MatchingFields{tenantIndex: tenant}); err != nil {
			return nil, fmt.Errorf("list the VPCAttachment of tenant %s: %w", tenant, err)
		}
		if len(atts.Items) != 1 || !atts.Items[0].DeletionTimestamp.IsZero() {
			if k.Log != nil {
				k.Log.Debug("backend has no single live VPCAttachment yet", "endpointSlice",
					s.Namespace+"/"+s.Name, "tenant", tenant, "matches", len(atts.Items))
			}
			continue
		}
		addr, ok := netip.AddrFromSlice(route.Prefix.IP)
		if !ok {
			continue
		}
		out = append(out, BackendAttachment{VPC: route.VPC, UID: string(atts.Items[0].UID), Address: addr.Unmap()})
	}
	return out, nil
}

// specAddresses returns the addresses of CIDR-notation interface addresses,
// skipping any that do not parse, as Worker reads them (D26).
func specAddresses(in []cloudv1alpha1.IPAddress) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		if p, err := netip.ParsePrefix(string(a)); err == nil {
			out = append(out, p.Addr().Unmap())
		} else if addr, err := netip.ParseAddr(string(a)); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}
