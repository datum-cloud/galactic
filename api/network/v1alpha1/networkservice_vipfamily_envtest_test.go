// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// ipv4VIPRuleMarker identifies the vipAddresses rule that refuses IPv4 VIPs
// until galactic serves them.
const ipv4VIPRuleMarker = "ip(v).family() == 6"

// TestNetworkServiceVIPFamilyAdmission covers the IPv4 VIP stopgap against a
// real API server: a new IPv4 VIP is refused and an IPv6 one admitted, and a
// rule that already held an IPv4 VIP before the rule was installed survives
// edits that leave vipAddresses alone, but not an edit to the list.
func TestNetworkServiceVIPFamilyAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_networkservices.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	full := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, full); err != nil {
		t.Fatal(err)
	}
	// The CRD as it was before the rule, to create an object the current
	// schema would refuse.
	legacy := full.DeepCopy()
	if !dropVIPFamilyRule(legacy) {
		t.Fatalf("CRD has no vipAddresses rule containing %q", ipv4VIPRuleMarker)
	}

	environment := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{legacy}}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = apiextensionsv1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const ns = "vip-family"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	rule := func(name string, vips ...string) *networkv1alpha1.NetworkService {
		return &networkv1alpha1.NetworkService{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: networkv1alpha1.NetworkServiceSpec{
				VPCRef:          "vpc-a",
				VIPAddresses:    vips,
				Protocol:        networkv1alpha1.NetworkServiceProtocolTCP,
				Port:            443,
				BackendSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				BackendPort:     8443,
			},
		}
	}

	existing := rule("existing", "2001:db8:1::10", "203.0.113.10")
	if err := c.Create(ctx, existing); err != nil {
		t.Fatalf("create IPv4 rule under the legacy schema: %v", err)
	}
	installSchema(ctx, t, c, full)

	for _, tt := range []struct {
		name      string
		vips      []string
		wantError string
	}{
		{"ipv6", []string{"2001:db8:1::11"}, ""},
		{"ipv4", []string{"203.0.113.11"}, "galactic#705"},
		{"dual-stack", []string{"2001:db8:1::12", "203.0.113.12"}, "galactic#705"},
		// isIP refuses an IPv4-mapped IPv6 address, so the first rule does.
		{"ipv4-mapped", []string{"::ffff:203.0.113.13"}, "valid IPv4 or IPv6"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := c.Create(ctx, rule(tt.name, tt.vips...))
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				return
			}
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("create error = %v, want a schema rejection naming %q", err, tt.wantError)
			}
		})
	}

	t.Run("existing rule keeps an unchanged IPv4 VIP", func(t *testing.T) {
		current := &networkv1alpha1.NetworkService{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(existing), current); err != nil {
			t.Fatal(err)
		}
		current.Labels = map[string]string{"edited": "true"}
		current.Spec.Port = 8443
		if err := c.Update(ctx, current); err != nil {
			t.Fatalf("update leaving vipAddresses unchanged: %v", err)
		}
	})

	t.Run("existing rule cannot edit a list holding an IPv4 VIP", func(t *testing.T) {
		current := &networkv1alpha1.NetworkService{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(existing), current); err != nil {
			t.Fatal(err)
		}
		current.Spec.VIPAddresses = append(current.Spec.VIPAddresses, "2001:db8:1::13")
		err := c.Update(ctx, current)
		if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "galactic#705") {
			t.Fatalf("update adding a VIP beside an IPv4 VIP: err = %v, want the IPv4 VIP rule's rejection", err)
		}
		current.Spec.VIPAddresses = []string{"2001:db8:1::10"}
		if err := c.Update(ctx, current); err != nil {
			t.Fatalf("update dropping the IPv4 VIP: %v", err)
		}
	})
}

// dropVIPFamilyRule removes the IPv4 VIP rule from crd's vipAddresses schema,
// reporting whether it was there.
func dropVIPFamilyRule(crd *apiextensionsv1.CustomResourceDefinition) bool {
	field := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["vipAddresses"]
	kept := field.XValidations[:0]
	for _, v := range field.XValidations {
		if !strings.Contains(v.Rule, ipv4VIPRuleMarker) {
			kept = append(kept, v)
		}
	}
	dropped := len(kept) != len(field.XValidations)
	field.XValidations = kept
	crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["vipAddresses"] = field
	return dropped
}

// installSchema replaces the served NetworkService schema with want's and waits
// until the API server enforces it, which a fresh create of an IPv4 VIP
// shows.
func installSchema(ctx context.Context, t *testing.T, c client.Client, want *apiextensionsv1.CustomResourceDefinition) {
	t.Helper()
	current := &apiextensionsv1.CustomResourceDefinition{}
	if err := c.Get(ctx, client.ObjectKey{Name: want.Name}, current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Versions = want.Spec.Versions
	if err := c.Update(ctx, current); err != nil {
		t.Fatalf("install the current NetworkService schema: %v", err)
	}
	probe := &networkv1alpha1.NetworkService{
		ObjectMeta: metav1.ObjectMeta{Name: "schema-probe", Namespace: "vip-family"},
		Spec: networkv1alpha1.NetworkServiceSpec{
			VPCRef:          "vpc-a",
			VIPAddresses:    []string{"198.51.100.1"},
			Protocol:        networkv1alpha1.NetworkServiceProtocolTCP,
			Port:            443,
			BackendSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			BackendPort:     8443,
		},
	}
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true,
		func(ctx context.Context) (bool, error) {
			p := probe.DeepCopy()
			lastErr = c.Create(ctx, p)
			if lastErr == nil {
				return false, c.Delete(ctx, p)
			}
			return apierrors.IsInvalid(lastErr) && strings.Contains(lastErr.Error(), "galactic#705"), nil
		})
	if err != nil {
		t.Fatalf("API server never enforced the current NetworkService schema: %v (last create: %v)", err, lastErr)
	}
}
