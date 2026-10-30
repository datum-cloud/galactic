// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

func TestSharedAddressRangeAdmission(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	group := api.NetworkServiceAddressGroup{
		UID:        "claim-1",
		Generation: 1,
		Revision:   "revision-1",
		Listeners: []api.NetworkServiceAddressListener{
			{
				Name:      "media",
				Protocol:  api.NetworkServiceProtocolUDP,
				PortRange: &api.PortRange{Start: 20000, End: 20999},
			},
		},
	}
	anchor := &api.NetworkServiceAddress{
		ObjectMeta: metav1.ObjectMeta{Name: "address", Namespace: protocolNamespace},
		Spec:       api.NetworkServiceAddressSpec{VPCRef: "vpc-a", VIPAddress: "2001:db8::1", Group: group},
	}
	if err := c.Create(ctx, anchor); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*api.NetworkServiceAddress)
	}{
		{"ClaimReplacement", func(a *api.NetworkServiceAddress) { a.Spec.Group.UID = "claim-2" }},
		{"SameGenerationDifferentInventory", func(a *api.NetworkServiceAddress) { a.Spec.Group.Revision = "revision-2" }},
		{"VIPReplacement", func(a *api.NetworkServiceAddress) { a.Spec.VIPAddress = "2001:db8::2" }},
		{"VPCReplacement", func(a *api.NetworkServiceAddress) { a.Spec.VPCRef = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := anchor.DeepCopy()
			tc.mutate(changed)
			if err := c.Update(ctx, changed); !apierrors.IsInvalid(err) {
				t.Fatalf("expected admission rejection, got %v", err)
			}
		})
	}
	anchor.Spec.Group.Generation = 2
	anchor.Spec.Group.Revision = "revision-2"
	if err := c.Update(ctx, anchor); err != nil {
		t.Fatal(err)
	}
	older := anchor.DeepCopy()
	older.Spec.Group.Generation = 1
	if err := c.Update(ctx, older); !apierrors.IsInvalid(err) {
		t.Fatalf("generation regression allowed: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*api.NetworkService)
		valid  bool
	}{
		{"Valid", func(*api.NetworkService) {}, true},
		{"BothShapes", func(r *api.NetworkService) { r.Spec.Port = 20000 }, false},
		{"Reversed", func(r *api.NetworkService) { r.Spec.PortRange.End = 19999 }, false},
		{"Overflow", func(r *api.NetworkService) { r.Spec.PortRange.End = 65536 }, false},
		{"TCPRange", func(r *api.NetworkService) { r.Spec.Protocol = api.NetworkServiceProtocolTCP }, false},
		{"Remapped", func(r *api.NetworkService) { r.Spec.BackendPort = 20001 }, false},
		{"IPv4", func(r *api.NetworkService) { r.Spec.VIPAddresses = []string{"192.0.2.1"} }, false},
		{"MissingInventory", func(r *api.NetworkService) { r.Spec.AddressGroup = nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := protocolService("range-"+strings.ToLower(tc.name), api.NetworkServiceProtocolUDP, 0, 0)
			r.Spec.PortRange = &api.PortRange{Start: 20000, End: 20999}
			r.Spec.AddressGroup = group.DeepCopy()
			r.Spec.AddressGroup.ListenerName = "media"
			tc.mutate(r)
			err := c.Create(ctx, r)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("expected refusal, got %v", err)
			}
		})
	}
}

func TestTerminalAddressRetirementAdmission(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	terminal := &api.NetworkServiceAddress{ObjectMeta: metav1.ObjectMeta{Name: "preemptive", Namespace: protocolNamespace}, Spec: api.NetworkServiceAddressSpec{Retired: true, VIPAddress: "2001:db8::1", Group: api.NetworkServiceAddressGroup{UID: "allocation", Generation: 1, Revision: "retired"}}}
	if err := c.Create(ctx, terminal); err != nil {
		t.Fatalf("preemptive retirement rejected: %v", err)
	}
	for _, mutate := range []func(*api.NetworkServiceAddress){
		func(a *api.NetworkServiceAddress) { a.Spec.Retired = false },
		func(a *api.NetworkServiceAddress) { a.Spec.Group.Generation++ },
		func(a *api.NetworkServiceAddress) { a.Spec.VPCRef = "new-vpc" },
	} {
		changed := terminal.DeepCopy()
		mutate(changed)
		if err := c.Update(ctx, changed); !apierrors.IsInvalid(err) {
			t.Fatalf("terminal mutation accepted: %v", err)
		}
	}
	active := terminal.DeepCopy()
	active.Name = "empty-active"
	active.ResourceVersion = ""
	active.UID = ""
	active.Spec.Retired = false
	if err := c.Create(ctx, active); !apierrors.IsInvalid(err) {
		t.Fatalf("empty active inventory accepted: %v", err)
	}
	active.Spec.VPCRef = "vpc"
	active.Spec.Group.Listeners = []api.NetworkServiceAddressListener{{Name: "control", Protocol: api.NetworkServiceProtocolTCP, Port: 443}}
	if err := c.Create(ctx, active); err != nil {
		t.Fatal(err)
	}
	active.Spec.Retired = true
	if err := c.Update(ctx, active); err != nil {
		t.Fatalf("existing inventory retirement rejected: %v", err)
	}
}

func TestCoordinatedBindingSourceAdmission(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	binding := &api.ServiceVIPBinding{ObjectMeta: metav1.ObjectMeta{Name: "source-bound", Namespace: protocolNamespace}, Spec: api.ServiceVIPBindingSpec{
		TargetRef: api.TargetRef{Kind: "Node", Name: "backend"}, VPCRef: "vpc", VIPAddress: "2001:db8::1", Port: 443, Protocol: api.NetworkServiceProtocolTCP,
		BackendAddress: "fd00::1", BackendPort: 8443, EgressKind: api.ServiceVIPBindingEgressKindTap,
		SourceRef: &api.ServiceVIPBindingSourceReference{Namespace: protocolNamespace, Name: "service", UID: "service-uid", Generation: 1, AllocationUID: "allocation"},
	}}
	if err := c.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*api.ServiceVIPBinding){
		func(b *api.ServiceVIPBinding) { b.Spec.SourceRef = nil },
		func(b *api.ServiceVIPBinding) { b.Spec.SourceRef.UID = "replacement" },
		func(b *api.ServiceVIPBinding) { b.Spec.SourceRef.Generation++ },
	} {
		changed := binding.DeepCopy()
		mutate(changed)
		if err := c.Update(ctx, changed); !apierrors.IsInvalid(err) {
			t.Fatalf("source mutation accepted: %v", err)
		}
	}
}
