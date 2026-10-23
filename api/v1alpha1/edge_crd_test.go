// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	testPool         = "fd00:5::/120"
	edgeProviderName = "connect-ip"
	packetAccess     = "PacketAccess"
	edgeVPCUID       = "11111111-2222-3333-4444-555555555555"
	ipv4Prefix       = "192.0.2.0/24"
	otherValue       = "other"
	secondPod        = "pod-2"
)

func edgeService(name string) *galacticv1alpha1.EdgeService {
	return &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: "prod", UID: edgeVPCUID},
			Capabilities: []string{packetAccess},
			Prefixes:     []string{"fd00:5::/48", ipv4Prefix},
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
		{"ClientPool", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = testPool }, true},
		{"ClientPoolIPv4", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = ipv4Prefix }, false},
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
		{"AddClientPool", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = testPool }, true},
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

	// A pool, once set, is fixed: changing or removing it is refused.
	pooled := edgeService("pooled")
	pooled.Spec.ClientPool = testPool
	if err := c.Create(ctx, pooled); err != nil {
		t.Fatal(err)
	}
	for name, pool := range map[string]string{"ChangeClientPool": "fd00:5::100/120", "RemoveClientPool": ""} {
		t.Run(name, func(t *testing.T) {
			var s galacticv1alpha1.EdgeService
			if err := c.Get(ctx, client.ObjectKeyFromObject(pooled), &s); err != nil {
				t.Fatal(err)
			}
			s.Spec.ClientPool = pool
			if err := c.Update(ctx, &s); err == nil {
				t.Fatalf("client pool changed to %q", pool)
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
				Namespace: "tenant", Name: "svc", UID: edgeVPCUID,
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
			PodName:     "p", PodUID: "u", NodeName: "n", BootID: "boot",
		},
	}
	if err := c.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}
	inst.Spec.NodeName = otherValue
	if err := c.Update(ctx, inst); err == nil {
		t.Error("instance spec changed")
	}
}

func TestEdgeRouteSchema(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()

	route := func(name, prefix string) *galacticv1alpha1.EdgeRoute {
		return &galacticv1alpha1.EdgeRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: galacticv1alpha1.EdgeRouteSpec{
				ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
				VPCUID:      edgeVPCUID, Prefix: prefix, Incarnation: "inc",
			},
		}
	}
	for _, bad := range []string{ipv4Prefix, "fd00:5::1/48", "::/0", "fd00:5::"} {
		if err := c.Create(ctx, route("bad", bad)); err == nil {
			t.Errorf("route prefix %q accepted", bad)
		}
	}
	r := route("r", "fd00:5::/64")
	if err := c.Create(ctx, r); err != nil {
		t.Fatalf("valid EdgeRoute refused: %v", err)
	}
	claim := galacticv1alpha1.EdgeRouteClaim{
		Attachment: "a1", HolderPodUID: "pod-1", HolderInstance: "i1", InstanceEpoch: 1, Epoch: 1,
	}
	r.Spec.Claim = &claim
	if err := c.Update(ctx, r); err != nil {
		t.Fatalf("first claim refused: %v", err)
	}

	update := func(what string, ok bool, mutate func(*galacticv1alpha1.EdgeRoute)) {
		t.Helper()
		var cur galacticv1alpha1.EdgeRoute
		if err := c.Get(ctx, client.ObjectKeyFromObject(r), &cur); err != nil {
			t.Fatal(err)
		}
		mutate(&cur)
		err := c.Update(ctx, &cur)
		if ok && err != nil {
			t.Errorf("%s refused: %v", what, err)
		}
		if !ok && err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	update("prefix change", false, func(r *galacticv1alpha1.EdgeRoute) { r.Spec.Prefix = "fd00:6::/64" })
	update("incarnation change", false, func(r *galacticv1alpha1.EdgeRoute) { r.Spec.Incarnation = otherValue })
	update("claim removal", false, func(r *galacticv1alpha1.EdgeRoute) { r.Spec.Claim = nil })
	update("new holder at the same epoch", false, func(r *galacticv1alpha1.EdgeRoute) {
		r.Spec.Claim.Attachment, r.Spec.Claim.HolderPodUID = "a2", secondPod
	})
	update("new instance epoch at the same claim epoch", false, func(r *galacticv1alpha1.EdgeRoute) {
		r.Spec.Claim.InstanceEpoch = 2
	})
	update("release", true, func(r *galacticv1alpha1.EdgeRoute) { r.Spec.Claim.Released = true })
	update("lower epoch", false, func(r *galacticv1alpha1.EdgeRoute) {
		r.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{
			Attachment: "a2", HolderPodUID: secondPod, HolderInstance: "i2", InstanceEpoch: 1, Epoch: 1,
		}
	})
	update("takeover at the next epoch", true, func(r *galacticv1alpha1.EdgeRoute) {
		r.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{
			Attachment: "a2", HolderPodUID: secondPod, HolderInstance: "i2", InstanceEpoch: 1, Epoch: 2,
		}
	})

	idx := &galacticv1alpha1.EdgeRouteIndex{
		ObjectMeta: metav1.ObjectMeta{Name: edgeVPCUID, Namespace: testNamespace},
		Spec:       galacticv1alpha1.EdgeRouteIndexSpec{VPCUID: edgeVPCUID},
	}
	if err := c.Create(ctx, idx); err != nil {
		t.Fatalf("valid EdgeRouteIndex refused: %v", err)
	}
	idx.Spec.VPCUID = otherValue
	if err := c.Update(ctx, idx); err == nil {
		t.Error("EdgeRouteIndex vpcUID changed")
	}

	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "leased", Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			PodName:     "p", PodUID: "u", NodeName: "n",
		},
	}
	if err := c.Create(ctx, inst); err == nil {
		t.Error("EdgeInstance without a boot ID accepted")
	}
	inst.Spec.BootID = "boot"
	if err := c.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}
	inst.Status.Lease = &galacticv1alpha1.EdgeLease{Holder: "h", Incarnation: "i", Epoch: 1, RenewStart: 5}
	if err := c.Status().Update(ctx, inst); err != nil {
		t.Fatalf("lease write refused: %v", err)
	}
}
