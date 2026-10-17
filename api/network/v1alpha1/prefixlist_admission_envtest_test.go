// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// TestBGPPrefixListAdmission checks the generated BGPPrefixList schema
// against a real API server: family-aware ge/le bounds, their ordering
// against the prefix length, the full FRR sequence range, and unique
// sequences.
func TestBGPPrefixListAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_bgpprefixlists.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	environment := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{crd}}
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
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const ns = "prefix-lists"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}

	entry := func(seq int64, prefix string, ge, le *int32) networkv1alpha1.BGPPrefixListEntry {
		return networkv1alpha1.BGPPrefixListEntry{
			Sequence: seq, Action: networkv1alpha1.BGPPolicyActionPermit, Prefix: prefix, GE: ge, LE: le,
		}
	}
	for i, tc := range []struct {
		name    string
		entries []networkv1alpha1.BGPPrefixListEntry
		admit   bool
	}{
		{"ipv6 ge 49 through 128", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "2607:ed40:8003::/48", ptr.To[int32](49), ptr.To[int32](128))}, true},
		{"ipv6 ge only", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "2607:ed40:8003::/48", ptr.To[int32](49), nil)}, true},
		{"ipv6 exact", []networkv1alpha1.BGPPrefixListEntry{entry(5, "2607:ed40:10::/44", nil, nil)}, true},
		{"ipv4 le 32", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "10.0.0.0/8", ptr.To[int32](16), ptr.To[int32](32))}, true},
		{"sequence 1", []networkv1alpha1.BGPPrefixListEntry{entry(1, "0.0.0.0/0", nil, nil)}, true},
		{"sequence 4294967295", []networkv1alpha1.BGPPrefixListEntry{entry(4294967295, "0.0.0.0/0", nil, nil)}, true},
		{"ipv4 ge 33", []networkv1alpha1.BGPPrefixListEntry{entry(5, "10.0.0.0/8", ptr.To[int32](33), nil)}, false},
		{"ipv4 le 33", []networkv1alpha1.BGPPrefixListEntry{entry(5, "10.0.0.0/8", nil, ptr.To[int32](33))}, false},
		{"ipv6 ge 129", []networkv1alpha1.BGPPrefixListEntry{entry(5, "2607:ed40::/32", ptr.To[int32](129), nil)}, false},
		{"ge shorter than prefix", []networkv1alpha1.BGPPrefixListEntry{entry(5, "10.0.0.0/8", ptr.To[int32](4), nil)}, false},
		{"le shorter than ge", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "10.0.0.0/8", ptr.To[int32](24), ptr.To[int32](20))}, false},
		{"le shorter than prefix", []networkv1alpha1.BGPPrefixListEntry{entry(5, "10.0.0.0/16", nil, ptr.To[int32](8))}, false},
		{"sequence 0", []networkv1alpha1.BGPPrefixListEntry{entry(0, "0.0.0.0/0", nil, nil)}, false},
		{"sequence above 32 bits", []networkv1alpha1.BGPPrefixListEntry{entry(4294967296, "0.0.0.0/0", nil, nil)}, false},
		{"duplicate sequence", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "10.0.0.0/8", nil, nil), entry(5, "10.1.0.0/16", nil, nil)}, false},
		{"mixed families", []networkv1alpha1.BGPPrefixListEntry{
			entry(5, "10.0.0.0/8", nil, nil), entry(10, "2607:ed40::/32", nil, nil)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := &networkv1alpha1.BGPPrefixList{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("list-%d", i), Namespace: ns},
				Spec:       networkv1alpha1.BGPPrefixListSpec{Entries: tc.entries},
			}
			err := c.Create(ctx, list)
			if tc.admit && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.admit && err == nil {
				t.Fatal("admitted an invalid prefix list")
			}
		})
	}
}
