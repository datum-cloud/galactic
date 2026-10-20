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

// vipCountRuleMarker identifies the vipAddresses rules that limit a service
// to one VIP per family.
const vipCountRuleMarker = ".size() <= 1"

// Messages the vipAddresses rules refuse a list with.
const (
	invalidVIPMessage = "IPv4-mapped"
	twoIPv6Message    = "at most one IPv6 address"
	twoIPv4Message    = "at most one IPv4 address"
)

// TestNetworkServiceVIPFamilyAdmission covers the one-VIP-per-family rules
// against a real API server: an IPv4-only, IPv6-only or dual-stack list is
// admitted, a second VIP of a family and an IPv4-mapped address are refused,
// and a service stored with two VIPs of a family before the rules were
// installed survives edits that leave vipAddresses alone, while an edit to
// the list must bring it within the rules.
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
	// The CRD without the per-family limits, to create objects the current
	// schema would refuse.
	legacy := full.DeepCopy()
	if n := dropVIPCountRules(legacy); n != 2 {
		t.Fatalf("CRD has %d vipAddresses rules containing %q, want 2", n, vipCountRuleMarker)
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

	twoIPv4 := rule("existing-two-ipv4", "2001:db8:1::10", "203.0.113.10", "203.0.113.20")
	twoIPv6 := rule("existing-two-ipv6", "2001:db8:1::20", "2001:db8:1::21")
	for _, existing := range []*networkv1alpha1.NetworkService{twoIPv4, twoIPv6} {
		if err := c.Create(ctx, existing); err != nil {
			t.Fatalf("create %s under the legacy schema: %v", existing.Name, err)
		}
	}
	installSchema(ctx, t, c, full)

	for _, tt := range []struct {
		name      string
		vips      []string
		wantError string
	}{
		{"ipv6-only", []string{"2001:db8:1::11"}, ""},
		{"ipv4-only", []string{"203.0.113.11"}, ""},
		{"dual-stack", []string{"2001:db8:1::12", "203.0.113.12"}, ""},
		{"two-ipv4", []string{"203.0.113.13", "203.0.113.14"}, twoIPv4Message},
		{"dual-stack-second-ipv4", []string{"2001:db8:1::15", "203.0.113.15", "203.0.113.16"}, twoIPv4Message},
		{"two-ipv6", []string{"2001:db8:1::17", "2001:db8:1::18"}, twoIPv6Message},
		// isIP refuses an IPv4-mapped IPv6 address; its message says how to
		// write the address instead.
		{"ipv4-mapped", []string{"::ffff:203.0.113.19"}, invalidVIPMessage},
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

	for _, tt := range []struct {
		existing  *networkv1alpha1.NetworkService
		stillBad  []string
		fixed     []string
		wantError string
	}{
		{
			existing:  twoIPv4,
			stillBad:  []string{"2001:db8:1::10", "203.0.113.10", "203.0.113.30"},
			fixed:     []string{"2001:db8:1::10", "203.0.113.10"},
			wantError: twoIPv4Message,
		},
		{
			existing:  twoIPv6,
			stillBad:  []string{"2001:db8:1::20", "2001:db8:1::22"},
			fixed:     []string{"2001:db8:1::20"},
			wantError: twoIPv6Message,
		},
	} {
		t.Run(tt.existing.Name+" keeps an unchanged list", func(t *testing.T) {
			current := &networkv1alpha1.NetworkService{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(tt.existing), current); err != nil {
				t.Fatal(err)
			}
			current.Labels = map[string]string{"edited": "true"}
			current.Spec.Port = 8443
			if err := c.Update(ctx, current); err != nil {
				t.Fatalf("update leaving vipAddresses unchanged: %v", err)
			}
		})
		t.Run(tt.existing.Name+" must fix an edited list", func(t *testing.T) {
			current := &networkv1alpha1.NetworkService{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(tt.existing), current); err != nil {
				t.Fatal(err)
			}
			current.Spec.VIPAddresses = tt.stillBad
			err := c.Update(ctx, current)
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("update keeping two VIPs of a family: err = %v, want a rejection naming %q", err, tt.wantError)
			}
			current.Spec.VIPAddresses = tt.fixed
			if err := c.Update(ctx, current); err != nil {
				t.Fatalf("update to one VIP per family: %v", err)
			}
		})
	}
}

// dropVIPCountRules removes the per-family VIP limits from crd's vipAddresses
// schema and returns how many rules it removed.
func dropVIPCountRules(crd *apiextensionsv1.CustomResourceDefinition) int {
	field := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["vipAddresses"]
	kept := field.XValidations[:0]
	for _, v := range field.XValidations {
		if !strings.Contains(v.Rule, vipCountRuleMarker) {
			kept = append(kept, v)
		}
	}
	dropped := len(field.XValidations) - len(kept)
	field.XValidations = kept
	crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["vipAddresses"] = field
	return dropped
}

// installSchema replaces the served NetworkService schema with want's and waits
// until the API server enforces it, which a fresh create of two IPv4 VIPs
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
			VIPAddresses:    []string{"198.51.100.1", "198.51.100.2"},
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
			return apierrors.IsInvalid(lastErr) && strings.Contains(lastErr.Error(), twoIPv4Message), nil
		})
	if err != nil {
		t.Fatalf("API server never enforced the current NetworkService schema: %v (last create: %v)", err, lastErr)
	}
}
