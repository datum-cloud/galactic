// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// Conflict decides whether prefix, routed through att under its service svc,
// overlaps what the VPC already uses for something else. It refuses with
// PrefixConflict when:
//
//   - an earlier service granting the VPC grants a prefix overlapping one of
//     svc's (grants are exclusive in a VPC; admission.GrantConflict);
//   - a workload subnet of the VPC (a VPCAttachment's podSubnet) overlaps
//     prefix: workload subnets take precedence over provider routes;
//   - another service's client pool in the VPC overlaps prefix; or
//   - prefix contains an address allocated to another attachment of svc's
//     own pool. A route inside its own service's pool, a delegated client
//     prefix, is otherwise allowed.
//
// Overlap with other routes is the EdgeRouteIndex's to decide. reader must
// read from the API server; svc must be what the caller just read, since its
// allocations are part of the decision.
func Conflict(ctx context.Context, reader client.Reader, svc *galacticv1alpha1.EdgeService,
	att *galacticv1alpha1.EdgeAttachment, prefix netip.Prefix) (*Refusal, error) {
	var services galacticv1alpha1.EdgeServiceList
	if err := reader.List(ctx, &services, client.InNamespace(svc.Namespace)); err != nil {
		return nil, err
	}
	if o, mine, theirs := admission.GrantConflict(svc, services.Items); o != nil {
		return refuse(ReasonPrefixConflict, "EdgeService %s's granted prefix %s overlaps earlier EdgeService %s's %s",
			svc.Name, mine, o.Name, theirs), nil
	}
	for i := range services.Items {
		o := &services.Items[i]
		if o.UID == svc.UID || o.Spec.VPCRef.UID != svc.Spec.VPCRef.UID || o.Spec.ClientPool == "" {
			continue
		}
		if p, err := netip.ParsePrefix(o.Spec.ClientPool); err == nil && p.Overlaps(prefix) {
			return refuse(ReasonPrefixConflict, "prefix %s overlaps EdgeService %s's client pool %s",
				prefix, o.Name, p), nil
		}
	}
	for _, a := range svc.Status.Allocations {
		if a.AttachmentUID == string(att.UID) {
			continue
		}
		if addr, err := netip.ParseAddr(a.Address); err == nil && prefix.Contains(addr) {
			return refuse(ReasonPrefixConflict, "prefix %s contains %s, the address of attachment %s",
				prefix, addr, a.Attachment), nil
		}
	}
	var subnets cloudv1alpha1.VPCAttachmentList
	if err := reader.List(ctx, &subnets, client.InNamespace(svc.Namespace)); err != nil {
		return nil, err
	}
	for i := range subnets.Items {
		va := &subnets.Items[i]
		if va.Spec.VPC.Name != svc.Spec.VPCRef.Name || va.Status.PodSubnet == "" {
			continue
		}
		if p, err := netip.ParsePrefix(va.Status.PodSubnet); err == nil && p.Masked().Overlaps(prefix) {
			return refuse(ReasonPrefixConflict, "prefix %s overlaps VPCAttachment %s's subnet %s",
				prefix, va.Name, p.Masked()), nil
		}
	}
	return nil, nil
}
