// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/crdnames"
)

func readySlice(namespace, name, tenantID, sid, addr string) *discoveryv1.EndpointSlice {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{crdnames.LabelTenantID: tenantID},
			Annotations: map[string]string{
				crdnames.AnnotationTenantID: tenantID,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{addr},
		}},
	}
	if sid != "" {
		slice.Annotations[crdnames.AnnotationSID] = sid
	}
	return slice
}

func TestBuildDesiredRouteNotSelected(t *testing.T) {
	slice := &discoveryv1.EndpointSlice{}
	got, err := BuildDesiredRoute(slice)
	if err != nil || got != nil {
		t.Fatalf("BuildDesiredRoute(unlabeled) = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestBuildDesiredRouteNoSIDYet(t *testing.T) {
	slice := readySlice("ns", "pod-a", "vpc1-att1", "", "fd00::1")
	got, err := BuildDesiredRoute(slice)
	if err != nil || got != nil {
		t.Fatalf("BuildDesiredRoute(no SID) = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestBuildDesiredRouteHappyPath(t *testing.T) {
	slice := readySlice("ns", "pod-a", "vpc1-att1", "fd00:1234::1", "fd00::abcd")
	got, err := BuildDesiredRoute(slice)
	if err != nil {
		t.Fatalf("BuildDesiredRoute: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("BuildDesiredRoute returned nil, want a DesiredRoute")
	}
	if got.VPC != "vpc1" {
		t.Errorf("VPC = %q, want %q", got.VPC, "vpc1")
	}
	if got.Prefix.String() != "fd00::abcd/128" {
		t.Errorf("Prefix = %q, want %q", got.Prefix.String(), "fd00::abcd/128")
	}
	if got.SID.String() != "fd00:1234::1" {
		t.Errorf("SID = %q, want %q", got.SID.String(), "fd00:1234::1")
	}
}

func TestBuildDesiredRouteMalformedTenantID(t *testing.T) {
	slice := readySlice("ns", "pod-a", "notenantsep", "fd00:1234::1", "fd00::abcd")
	got, err := BuildDesiredRoute(slice)
	if err == nil || got != nil {
		t.Fatalf("BuildDesiredRoute(malformed tenant id) = (%v, %v), want (nil, error)", got, err)
	}
}

func TestBuildDesiredRouteInvalidSID(t *testing.T) {
	slice := readySlice("ns", "pod-a", "vpc1-att1", "not-an-ip", "fd00::abcd")
	got, err := BuildDesiredRoute(slice)
	if err == nil || got != nil {
		t.Fatalf("BuildDesiredRoute(invalid SID) = (%v, %v), want (nil, error)", got, err)
	}
}

func TestBuildDesiredRouteWrongAddressType(t *testing.T) {
	slice := readySlice("ns", "pod-a", "vpc1-att1", "fd00:1234::1", "10.0.0.1")
	slice.AddressType = discoveryv1.AddressTypeIPv4
	got, err := BuildDesiredRoute(slice)
	if err == nil || got != nil {
		t.Fatalf("BuildDesiredRoute(IPv4 AddressType) = (%v, %v), want (nil, error)", got, err)
	}
}

func TestBuildDesiredRouteNoEndpointAddress(t *testing.T) {
	slice := readySlice("ns", "pod-a", "vpc1-att1", "fd00:1234::1", "")
	slice.Endpoints[0].Addresses = nil
	got, err := BuildDesiredRoute(slice)
	if err == nil || got != nil {
		t.Fatalf("BuildDesiredRoute(no address) = (%v, %v), want (nil, error)", got, err)
	}
}
