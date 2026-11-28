// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	publicListener     = "PublicListener"
	socketAccess       = "SocketAccess"
	prefixReachability = "PrefixReachability"
	listenerIPv6       = "2001:db8:100::10"
	listenerIPv4       = "192.0.2.10"
)

func edgeListener(name string) *galacticv1alpha1.EdgeListener {
	return &galacticv1alpha1.EdgeListener{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: galacticv1alpha1.EdgeListenerSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: edgeProviderName},
			ServiceRef:  galacticv1alpha1.EdgeListenerServiceReference{Namespace: testNamespace, Name: "ingress"},
			Addresses:   []string{listenerIPv6, listenerIPv4},
			Ports: []galacticv1alpha1.EdgeListenerPort{
				{Protocol: galacticv1alpha1.EdgeListenerProtocolUDP, Port: 443, BackendPort: 8443},
				{Protocol: galacticv1alpha1.EdgeListenerProtocolTCP, Port: 443, BackendPort: 8443},
			},
		},
	}
}

// TestEdgeListenerSchema covers the listener's validation: addresses per
// family, ports, the all-UDP health port rule and immutable references.
func TestEdgeListenerSchema(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()

	udpOnly := []galacticv1alpha1.EdgeListenerPort{
		{Protocol: galacticv1alpha1.EdgeListenerProtocolUDP, Port: 443, BackendPort: 8443},
	}
	healthPort := int32(8443)

	creates := []struct {
		name   string
		mutate func(*galacticv1alpha1.EdgeListener)
		want   string // empty when the listener is admitted
	}{
		{"DualStack", func(*galacticv1alpha1.EdgeListener) {}, ""},
		{"IPv6Only", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Addresses = []string{listenerIPv6} }, ""},
		{"NoAddress", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Addresses = nil }, "spec.addresses"},
		{"TwoIPv6", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Addresses = []string{listenerIPv6, "2001:db8:100::11"}
		}, "at most one IPv6 address"},
		{"TwoIPv4", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Addresses = []string{listenerIPv4, "192.0.2.11"}
		}, "at most one IPv4 address"},
		{"NotAnAddress", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Addresses = []string{"2001:db8:100::/64"}
		}, "valid IPv4 or IPv6 addresses"},
		{"IPv4Mapped", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Addresses = []string{"::ffff:192.0.2.10"}
		}, "valid IPv4 or IPv6 addresses"},
		{"NoPort", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Ports = nil }, "spec.ports"},
		{"SCTP", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Ports[0].Protocol = "sctp" }, "spec.ports[0].protocol"},
		{"PortZero", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Ports[0].Port = 0 }, "spec.ports[0].port"},
		{"DuplicatePort", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Ports = append(l.Spec.Ports, galacticv1alpha1.EdgeListenerPort{
				Protocol: galacticv1alpha1.EdgeListenerProtocolTCP, Port: 443, BackendPort: 9443,
			})
		}, "Duplicate value"},
		{"SharedBackendPort", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Ports = append(l.Spec.Ports, galacticv1alpha1.EdgeListenerPort{
				Protocol: galacticv1alpha1.EdgeListenerProtocolTCP, Port: 8443, BackendPort: 8443,
			})
		}, "cannot share a backendPort"},
		{"TooManyPorts", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Ports = nil
			for i := range int32(17) {
				l.Spec.Ports = append(l.Spec.Ports, galacticv1alpha1.EdgeListenerPort{
					Protocol: galacticv1alpha1.EdgeListenerProtocolTCP, Port: 1000 + i, BackendPort: 2000 + i,
				})
			}
		}, "spec.ports"},
		{"UDPOnlyWithoutHealthPort", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Ports = udpOnly
		}, "healthPort is required"},
		{"UDPOnlyWithHealthPort", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.Ports = udpOnly
			l.Spec.HealthPort = &healthPort
		}, ""},
		{"UnknownAffinity", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.SessionAffinity = "Sticky"
		}, "spec.sessionAffinity"},
		{"UnknownFailurePolicy", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.FailurePolicy = "Retry"
		}, "spec.failurePolicy"},
	}
	for i, tt := range creates {
		t.Run("Create"+tt.name, func(t *testing.T) {
			l := edgeListener(fmt.Sprintf("create-%d", i))
			tt.mutate(l)
			err := c.Create(ctx, l)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Create: err = %v, want it to contain %q", err, tt.want)
			}
		})
	}

	t.Run("Defaults", func(t *testing.T) {
		l := edgeListener("defaults")
		if err := c.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
		if l.Spec.SessionAffinity != galacticv1alpha1.EdgeListenerSessionAffinityClientIPAndProtocol {
			t.Errorf("sessionAffinity = %q, want ClientIPAndProtocol", l.Spec.SessionAffinity)
		}
		if l.Spec.FailurePolicy != galacticv1alpha1.EdgeListenerFailOpen {
			t.Errorf("failurePolicy = %q, want FailOpen", l.Spec.FailurePolicy)
		}
	})

	updates := []struct {
		name   string
		mutate func(*galacticv1alpha1.EdgeListener)
		want   string
	}{
		{"Ports", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Ports[0].Port = 4443 }, ""},
		{"Addresses", func(l *galacticv1alpha1.EdgeListener) { l.Spec.Addresses = []string{listenerIPv6} }, ""},
		{"ProviderRef", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.ProviderRef.Name = "tailnet"
		}, "providerRef is immutable"},
		{"ServiceRef", func(l *galacticv1alpha1.EdgeListener) {
			l.Spec.ServiceRef.Name = "other"
		}, "serviceRef is immutable"},
	}
	for i, tt := range updates {
		t.Run("Update"+tt.name, func(t *testing.T) {
			l := edgeListener(fmt.Sprintf("update-%d", i))
			if err := c.Create(ctx, l); err != nil {
				t.Fatal(err)
			}
			tt.mutate(l)
			err := c.Update(ctx, l)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Update: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Update: err = %v, want it to contain %q", err, tt.want)
			}
		})
	}

	// Status is a subresource: a spec write does not change it, and a status
	// write does not change the spec.
	t.Run("StatusSubresource", func(t *testing.T) {
		l := edgeListener("status")
		if err := c.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
		l.Status.Backends = []galacticv1alpha1.EdgeListenerBackend{{Attachment: "edge/ea-1", Serving: true}}
		if err := c.Status().Update(ctx, l); err != nil {
			t.Fatalf("status update: %v", err)
		}
		var got galacticv1alpha1.EdgeListener
		if err := c.Get(ctx, client.ObjectKeyFromObject(l), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Status.Backends) != 1 || !got.Status.Backends[0].Serving {
			t.Errorf("backends = %+v, want the one written", got.Status.Backends)
		}
	})
}

// TestPublicListenerCapability covers PublicListener on a provider and a
// grant, the grant's limit of four capabilities, and that an attachment still
// cannot request it.
func TestPublicListenerCapability(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()

	provider := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "listener-provider"},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{galacticv1alpha1.GroupVersion.Version},
			Capabilities: []galacticv1alpha1.EdgeCapability{
				{Name: socketAccess, Version: "v1"}, {Name: publicListener, Version: "v1"},
			},
			ServiceAccounts: []galacticv1alpha1.ServiceAccountReference{{Namespace: "edge", Name: "listener"}},
			Configuration:   galacticv1alpha1.ConfigurationKind{Group: "example.com", Kind: "Config"},
		},
	}
	if err := c.Create(ctx, provider); err != nil {
		t.Fatalf("EdgeProvider with PublicListener refused: %v", err)
	}

	all := edgeService("all-capabilities")
	all.Spec.Capabilities = []string{socketAccess, packetAccess, prefixReachability, publicListener}
	if err := c.Create(ctx, all); err != nil {
		t.Fatalf("EdgeService with four capabilities refused: %v", err)
	}

	attachment := edgeAttachment("public-listener")
	attachment.Spec.Capabilities = []galacticv1alpha1.EdgeCapability{{Name: publicListener, Version: "v1"}}
	attachment.Spec.PacketDevice = nil
	err := c.Create(ctx, attachment)
	if err == nil || !strings.Contains(err.Error(), "only SocketAccess and PacketAccess") {
		t.Fatalf("EdgeAttachment requesting PublicListener: err = %v, want refused", err)
	}
}
