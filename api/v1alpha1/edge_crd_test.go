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
