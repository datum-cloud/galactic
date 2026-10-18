// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// startTopologyAPI starts an API server holding the FabricEndpoint and
// FabricTopology CRDs, which fails if a rule exceeds the CEL cost budget.
func startTopologyAPI(t *testing.T) (client.Client, string) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	names := []string{"fabricendpoints", "fabrictopologies"}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_"+name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	env := &envtest.Environment{CRDs: crds}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	const ns = "fabric"
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	return c, ns
}

func admissionEndpoint(ns, name string, mutate func(*networkv1alpha1.FabricEndpointSpec)) *networkv1alpha1.FabricEndpoint {
	ep := &networkv1alpha1.FabricEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkv1alpha1.FabricEndpointSpec{
			RoutingDomain: "fabric", Cell: "cell-a", RouterRef: networkv1alpha1.LocalObjectRef{Name: "r1"},
			Transport: "private-mesh", ASN: 64512,
			Addresses: networkv1alpha1.FabricEndpointAddresses{IPv4: ptr.To("192.0.2.1"), IPv6: ptr.To("2001:db8::1")},
		},
	}
	if mutate != nil {
		mutate(&ep.Spec)
	}
	return ep
}

func claim(name string) *networkv1alpha1.AddressClaimRef {
	return &networkv1alpha1.AddressClaimRef{Project: "p", Namespace: "n", Name: name}
}

func TestFabricEndpointAdmission(t *testing.T) {
	c, ns := startTopologyAPI(t)
	ep := func(name string, mutate func(*networkv1alpha1.FabricEndpointSpec)) client.Object {
		return admissionEndpoint(ns, name, mutate)
	}
	runAdmission(t, c, []admissionCase{
		{"manual", ep("manual", nil), ""},
		{"ipv6 only", ep("v6only", func(s *networkv1alpha1.FabricEndpointSpec) { s.Addresses.IPv4 = nil }), ""},
		{"no address", ep("none", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses = networkv1alpha1.FabricEndpointAddresses{}
		}), "an endpoint has an IPv4 or an IPv6 address"},
		{"ipv6 in ipv4", ep("v6inv4", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses.IPv4 = ptr.To("2001:db8::2")
		}), "ipv4 must be an IPv4 address"},
		{"ipv4 in ipv6", ep("v4inv6", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses.IPv6 = ptr.To("192.0.2.2")
		}), "ipv6 must be an IPv6 address"},
		{"link-local without interface", ep("ll", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses.IPv6 = ptr.To("fe80::1")
		}), "a link-local IPv6 address needs an interface"},
		{"link-local with interface", ep("llif", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses.IPv6, s.Interface = ptr.To("fe80::1"), ptr.To("eth1")
		}), ""},
		{"claimed", ep("claimed", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Source = networkv1alpha1.FabricEndpointSource{Type: networkv1alpha1.FabricEndpointSourceAddressClaim,
				IPv4ClaimRef: claim("v4"), IPv6ClaimRef: claim("v6")}
		}), ""},
		{"claim without its address", ep("claimnoaddr", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Addresses.IPv4 = nil
			s.Source = networkv1alpha1.FabricEndpointSource{Type: networkv1alpha1.FabricEndpointSourceAddressClaim,
				IPv4ClaimRef: claim("v4"), IPv6ClaimRef: claim("v6")}
		}), "an IPv4 claim needs an IPv4 address"},
		{"claim source missing a claim", ep("claimmissing", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Source = networkv1alpha1.FabricEndpointSource{Type: networkv1alpha1.FabricEndpointSourceAddressClaim,
				IPv6ClaimRef: claim("v6")}
		}), "an AddressClaim source names the claim of every address"},
		{"claim on manual", ep("manualclaim", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Source = networkv1alpha1.FabricEndpointSource{Type: networkv1alpha1.FabricEndpointSourceManual,
				IPv6ClaimRef: claim("v6")}
		}), "claim references need the AddressClaim source"},
		{"bad transport", ep("badtransport", func(s *networkv1alpha1.FabricEndpointSpec) {
			s.Transport = "Private_Mesh"
		}), "spec.transport"},
	})

	t.Run("identity is immutable, addresses are not", func(t *testing.T) {
		ctx := context.Background()
		got := &networkv1alpha1.FabricEndpoint{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "manual"}, got); err != nil {
			t.Fatal(err)
		}
		if got.Spec.Source.Type != networkv1alpha1.FabricEndpointSourceManual {
			t.Errorf("source defaulted to %q, want Manual", got.Spec.Source.Type)
		}
		renumbered := got.DeepCopy()
		renumbered.Spec.Addresses.IPv6 = ptr.To("2001:db8::99")
		if err := c.Update(ctx, renumbered); err != nil {
			t.Fatalf("renumbering refused: %v", err)
		}
		for name, mutate := range map[string]func(*networkv1alpha1.FabricEndpointSpec){
			"transport": func(s *networkv1alpha1.FabricEndpointSpec) { s.Transport = "public" },
			"cell":      func(s *networkv1alpha1.FabricEndpointSpec) { s.Cell = "cell-b" },
			"router":    func(s *networkv1alpha1.FabricEndpointSpec) { s.RouterRef.Name = "r2" },
			"domain":    func(s *networkv1alpha1.FabricEndpointSpec) { s.RoutingDomain = "other" },
		} {
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "manual"}, got); err != nil {
				t.Fatal(err)
			}
			mutate(&got.Spec)
			err := c.Update(ctx, got)
			if err == nil || !strings.Contains(err.Error(), "immutable") {
				t.Errorf("changing the %s: %v, want an immutability refusal", name, err)
			}
		}
	})
}

func admissionTopology(ns, name string, mutate func(*networkv1alpha1.FabricTopologySpec)) *networkv1alpha1.FabricTopology {
	topo := &networkv1alpha1.FabricTopology{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkv1alpha1.FabricTopologySpec{
			RoutingDomain: "fabric", Cell: "cell-a",
			Members: networkv1alpha1.FabricTopologyMembers{
				RouterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"fabric": "member"}},
			},
			Mesh: []networkv1alpha1.FabricMeshRelationship{{
				Name: "private", Transports: []string{"private-mesh"},
				Families: []networkv1alpha1.FabricSessionFamily{networkv1alpha1.FabricSessionFamilyIPv6},
				Settings: networkv1alpha1.FabricSessionSettings{
					FamilySettings: []networkv1alpha1.BGPPeerFamilySettings{{
						AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast,
						FRR: &networkv1alpha1.FRRPeerFamilySettings{Weight: ptr.To[int32](100)},
					}},
				},
			}},
		},
	}
	if mutate != nil {
		mutate(&topo.Spec)
	}
	return topo
}

func TestFabricTopologyAdmission(t *testing.T) {
	c, ns := startTopologyAPI(t)
	topo := func(name string, mutate func(*networkv1alpha1.FabricTopologySpec)) client.Object {
		return admissionTopology(ns, name, mutate)
	}
	external := networkv1alpha1.FabricExternalRelationship{
		Name: "transit", Routers: networkv1alpha1.FabricTopologyMembers{
			Routers: []networkv1alpha1.LocalObjectRef{{Name: "edge"}}},
		UpdateSource: networkv1alpha1.FabricUpdateSourceNone,
		Peers:        []networkv1alpha1.FabricExternalPeer{{Address: "198.51.100.1", ASN: 64999}},
	}
	runAdmission(t, c, []admissionCase{
		{"mesh", topo("mesh", nil), ""},
		{"external", topo("external", func(s *networkv1alpha1.FabricTopologySpec) {
			s.Mesh, s.External = nil, []networkv1alpha1.FabricExternalRelationship{external}
		}), ""},
		{"no relationship", topo("empty", func(s *networkv1alpha1.FabricTopologySpec) { s.Mesh = nil }),
			"a topology has at least one relationship"},
		{"no members", topo("nomembers", func(s *networkv1alpha1.FabricTopologySpec) {
			s.Members = networkv1alpha1.FabricTopologyMembers{}
		}), "name a routerSelector or routers"},
		{"route reflector client set by hand", topo("rrc", func(s *networkv1alpha1.FabricTopologySpec) {
			s.Mesh[0].Settings.FamilySettings[0].RouteReflectorClient = ptr.To(true)
		}), "the relationship sets routeReflectorClient"},
		{"evpn family", topo("evpn", func(s *networkv1alpha1.FabricTopologySpec) {
			s.Mesh[0].Settings.FamilySettings = []networkv1alpha1.BGPPeerFamilySettings{{
				AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN}}
		}), "fabric sessions carry unicast families"},
		{"external sourced without a transport", topo("extnosource", func(s *networkv1alpha1.FabricTopologySpec) {
			e := external
			e.UpdateSource = networkv1alpha1.FabricUpdateSourceEndpointAddress
			s.Mesh, s.External = nil, []networkv1alpha1.FabricExternalRelationship{e}
		}), "sourcing from the endpoint address needs the transport"},
		{"external peer not an address", topo("extbad", func(s *networkv1alpha1.FabricTopologySpec) {
			e := external
			e.Peers = []networkv1alpha1.FabricExternalPeer{{Address: "transit-1", ASN: 64999}}
			s.Mesh, s.External = nil, []networkv1alpha1.FabricExternalRelationship{e}
		}), "address must be an IP address"},
		{"long name", topo(strings.Repeat("t", 64), nil), "at most 63 characters"},
	})

	t.Run("defaults, and domain and cell are immutable", func(t *testing.T) {
		ctx := context.Background()
		got := &networkv1alpha1.FabricTopology{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "mesh"}, got); err != nil {
			t.Fatal(err)
		}
		if got.Spec.MaxSessionsPerRouter != 64 || got.Spec.FailureDomainLabel != "topology.kubernetes.io/zone" ||
			got.Spec.Mesh[0].UpdateSource != networkv1alpha1.FabricUpdateSourceEndpointAddress {
			t.Errorf("defaults: %d %q %q", got.Spec.MaxSessionsPerRouter, got.Spec.FailureDomainLabel,
				got.Spec.Mesh[0].UpdateSource)
		}
		got.Spec.Cell = "cell-b"
		if err := c.Update(ctx, got); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("changing the cell: %v, want an immutability refusal", err)
		}
	})
}
