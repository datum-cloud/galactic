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

// IsSelected reports whether slice carries the tenant label this sidecar watches
// EndpointSlices through. Used both as the controller's watch predicate and by
// BuildDesiredRoute.
func IsSelected(slice *discoveryv1.EndpointSlice) bool {
	if slice == nil {
		return false
	}
	_, ok := slice.Labels[crdnames.LabelTenantID]
	return ok
}

// BuildDesiredRoute translates one EndpointSlice into the route this sidecar
// should converge toward.
//
// It returns nil with a nil error, meaning nothing to do rather than an error,
// when the slice is not one this sidecar owns or has not picked up its SID
// annotation yet. That annotation appears only once the pod's node has a locator
// and node ID configured, so a freshly published slice can legitimately carry
// the tenant label and no SID, pending a later update.
//
// It returns an error for a slice that is selected but malformed in a way worth
// logging: a bad tenant identifier, an unparseable SID or address, or a
// non-IPv6 address type, which should never occur for these backends.
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
