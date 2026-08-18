// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"net"

	discoveryv1 "k8s.io/api/discovery/v1"

	"go.datum.net/galactic/internal/crdnames"
)

// IsSelected reports whether slice carries the label this sidecar watches
// EndpointSlices through — presence of crdnames.LabelTenantID, per §3 of
// the plan ("select by label presence, group by its value"). Used both as
// the controller's watch predicate and by BuildDesiredRoute.
func IsSelected(slice *discoveryv1.EndpointSlice) bool {
	if slice == nil {
		return false
	}
	_, ok := slice.Labels[crdnames.LabelTenantID]
	return ok
}

// BuildDesiredRoute translates one EndpointSlice into the DesiredRoute this
// sidecar should converge toward.
//
// Returns (nil, nil) — "nothing to do, not an error" — when slice isn't one
// this sidecar owns (IsSelected is false) or hasn't picked up its SID
// annotation yet: crdnames.AnnotationSID is only set once the pod's hosting
// node's BGPRouter has SRv6Locator/NodeID configured (see that constant's
// own doc comment), so a freshly-published EndpointSlice can legitimately
// have the tenant label but no SID yet, pending a later update.
//
// Returns (nil, err) for a slice that IS selected but malformed in a way
// that indicates a real problem worth logging — a bad tenant identifier, an
// unparseable SID/address, or an unsupported (non-IPv6) AddressType, which
// per §3 should never occur for these backends.
func BuildDesiredRoute(slice *discoveryv1.EndpointSlice) (*DesiredRoute, error) {
	if !IsSelected(slice) {
		return nil, nil
	}

	tenantID := slice.Annotations[crdnames.AnnotationTenantID]
	vpc, _, ok := crdnames.ParseTenantIdentifier(tenantID)
	if !ok {
		return nil, fmt.Errorf("EndpointSlice %s/%s: malformed tenant identifier %q (annotation %s)",
			slice.Namespace, slice.Name, tenantID, crdnames.AnnotationTenantID)
	}

	sidStr, ok := slice.Annotations[crdnames.AnnotationSID]
	if !ok || sidStr == "" {
		return nil, nil
	}
	sid := net.ParseIP(sidStr)
	if sid == nil {
		return nil, fmt.Errorf("EndpointSlice %s/%s: invalid SID annotation %q",
			slice.Namespace, slice.Name, sidStr)
	}

	if slice.AddressType != discoveryv1.AddressTypeIPv6 {
		return nil, fmt.Errorf(
			"EndpointSlice %s/%s: unsupported AddressType %q — only IPv6 backends are published (§3 of the plan)",
			slice.Namespace, slice.Name, slice.AddressType)
	}
	if len(slice.Endpoints) == 0 || len(slice.Endpoints[0].Addresses) == 0 {
		return nil, fmt.Errorf("EndpointSlice %s/%s: no endpoint address", slice.Namespace, slice.Name)
	}
	addrStr := slice.Endpoints[0].Addresses[0]
	addr := net.ParseIP(addrStr)
	if addr == nil {
		return nil, fmt.Errorf("EndpointSlice %s/%s: invalid endpoint address %q",
			slice.Namespace, slice.Name, addrStr)
	}

	return &DesiredRoute{
		VPC:    vpc,
		Prefix: &net.IPNet{IP: addr, Mask: net.CIDRMask(128, 128)},
		SID:    sid,
	}, nil
}
