// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	edgeProviderName = "connect-ip"
	packetAccess     = "PacketAccess"
)

func edgeService(name string) *galacticv1alpha1.EdgeService {
	return &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: "prod", UID: "11111111-2222-3333-4444-555555555555"},
			Capabilities: []string{packetAccess},
			Prefixes:     []string{"fd00:5::/48", "192.0.2.0/24"},
		},
	}
}

func TestEdgeSchema(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()

	provider := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: edgeProviderName},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{"v1alpha1"},
			Capabilities:     []galacticv1alpha1.EdgeCapability{{Name: packetAccess, Version: "v1"}},
			ServiceAccounts:  []galacticv1alpha1.ServiceAccountReference{{Namespace: "edge", Name: edgeProviderName}},
			Configuration: galacticv1alpha1.ConfigurationKind{
				Group: "connect.galactic.datumapis.com", Kind: "ConnectIPConfig",
			},
		},
	}
	if err := c.Create(ctx, provider); err != nil {
		t.Fatalf("valid EdgeProvider refused: %v", err)
	}
	noSA := provider.DeepCopy()
	noSA.ObjectMeta = metav1.ObjectMeta{Name: "no-sa"}
	noSA.Spec.ServiceAccounts = nil
	if err := c.Create(ctx, noSA); err == nil {
		t.Fatal("EdgeProvider without ServiceAccounts accepted")
	}
	foundation := provider.DeepCopy()
	foundation.ObjectMeta = metav1.ObjectMeta{Name: "foundation"}
	foundation.Spec.ServiceAccounts = []galacticv1alpha1.ServiceAccountReference{
		{Namespace: "galactic-system", Name: "galactic-edge"},
	}
	if err := c.Create(ctx, foundation); err == nil {
		t.Fatal("EdgeProvider listing galactic-edge's ServiceAccount accepted")
	}

	creates := []struct {
		name   string
		mutate func(*galacticv1alpha1.EdgeService)
		ok     bool
	}{
		{"Valid", func(*galacticv1alpha1.EdgeService) {}, true},
		{"PrefixWithHostBits", func(s *galacticv1alpha1.EdgeService) { s.Spec.Prefixes = []string{"fd00:5::1/48"} }, false},
		{"NotACIDR", func(s *galacticv1alpha1.EdgeService) { s.Spec.Prefixes = []string{"fd00:5::"} }, false},
		{"UnknownCapability", func(s *galacticv1alpha1.EdgeService) {
			s.Spec.Capabilities = []string{"RouteExchange"}
		}, false},
		{"NoCapability", func(s *galacticv1alpha1.EdgeService) { s.Spec.Capabilities = nil }, false},
		{"NoVPCUID", func(s *galacticv1alpha1.EdgeService) { s.Spec.VPCRef.UID = "" }, false},
		{"ClientPool", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:5::/120" }, true},
		{"ClientPoolIPv4", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "192.0.2.0/24" }, false},
		{"ClientPoolTooSmall", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:5::/121" }, false},
		{"ClientPoolHostBits", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:5::1/120" }, false},
		{"DrainTooLong", func(s *galacticv1alpha1.EdgeService) {
			d := int32(301)
			s.Spec.DrainSeconds = &d
		}, false},
	}
	for i, tt := range creates {
		t.Run("Create"+tt.name, func(t *testing.T) {
			s := edgeService(fmt.Sprintf("create-%d", i))
			tt.mutate(s)
			if err := c.Create(ctx, s); (err == nil) != tt.ok {
				t.Fatalf("Create: err = %v, want ok %t", err, tt.ok)
			}
		})
	}

	updates := []struct {
		name   string
		mutate func(*galacticv1alpha1.EdgeService)
		ok     bool
	}{
		{"Prefixes", func(s *galacticv1alpha1.EdgeService) { s.Spec.Prefixes = []string{"fd00:5::/56"} }, true},
		{"ValidUntil", func(s *galacticv1alpha1.EdgeService) {
			now := metav1.Now()
			s.Spec.ValidUntil = &now
		}, true},
		{"ProviderRef", func(s *galacticv1alpha1.EdgeService) { s.Spec.ProviderRef.Name = "tailnet" }, false},
		{"VPCUID", func(s *galacticv1alpha1.EdgeService) {
			s.Spec.VPCRef.UID = "66666666-7777-8888-9999-000000000000"
		}, false},
		{"Capabilities", func(s *galacticv1alpha1.EdgeService) {
			s.Spec.Capabilities = []string{packetAccess, "SocketAccess"}
		}, false},
		{"ClientPool", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:5::/120" }, false},
	}
	for i, tt := range updates {
		t.Run("Update"+tt.name, func(t *testing.T) {
			s := edgeService(fmt.Sprintf("update-%d", i))
			if err := c.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			gen := s.Generation
			tt.mutate(s)
			err := c.Update(ctx, s)
			if (err == nil) != tt.ok {
				t.Fatalf("Update: err = %v, want ok %t", err, tt.ok)
			}
			if tt.ok && s.Generation == gen {
				t.Fatalf("spec update kept generation %d; admission relies on it changing", gen)
			}
		})
	}
}

func edgeAttachment(name string) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{
				Namespace: "tenant", Name: "svc", UID: "11111111-2222-3333-4444-555555555555",
			},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: "inst"},
			PodUID:          "99999999-2222-3333-4444-555555555555",
			ContractVersion: galacticv1alpha1.GroupVersion.Version,
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: packetAccess, Version: "v1"}},
			PacketDevice:    &galacticv1alpha1.EdgePacketDevice{Owner: 1000, Group: 1000},
		},
	}
}

func TestEdgeAttachmentSchema(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()
	creates := []struct {
		name   string
		mutate func(*galacticv1alpha1.EdgeAttachment)
		ok     bool
	}{
		{"Valid", func(*galacticv1alpha1.EdgeAttachment) {}, true},
		{"PacketAccessWithoutDevice", func(a *galacticv1alpha1.EdgeAttachment) { a.Spec.PacketDevice = nil }, false},
		{"DeviceWithoutPacketAccess", func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.Capabilities = []galacticv1alpha1.EdgeCapability{{Name: "SocketAccess", Version: "v1"}}
		}, false},
		{"PrefixReachability", func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.Capabilities = append(a.Spec.Capabilities,
				galacticv1alpha1.EdgeCapability{Name: "PrefixReachability", Version: "v1"})
		}, false},
		{"NoPodUID", func(a *galacticv1alpha1.EdgeAttachment) { a.Spec.PodUID = "" }, false},
	}
	for i, tt := range creates {
		t.Run("Create"+tt.name, func(t *testing.T) {
			a := edgeAttachment(fmt.Sprintf("create-%d", i))
			tt.mutate(a)
			if err := c.Create(ctx, a); (err == nil) != tt.ok {
				t.Fatalf("Create: err = %v, want ok %t", err, tt.ok)
			}
		})
	}
	a := edgeAttachment("immutable")
	if err := c.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.Spec.PodUID = "00000000-2222-3333-4444-555555555555"
	if err := c.Update(ctx, a); err == nil {
		t.Error("attachment spec changed")
	}

	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "inst", Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			PodName:     "p", PodUID: "u", NodeName: "n",
		},
	}
	if err := c.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}
	inst.Spec.NodeName = "other"
	if err := c.Update(ctx, inst); err == nil {
		t.Error("instance spec changed")
	}
}
