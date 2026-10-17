// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

// TestImportedObjectsAdmitted: every object the importer produces passes
// the real API server's schema and CEL validation, so the resources can be
// applied as written.
func TestImportedObjectsAdmitted(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	c := startAPI(t)
	files, err := filepath.Glob(filepath.Join("testdata", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv(parityEnv); dir != "" {
		real, err := filepath.Glob(filepath.Join(dir, "*", "*.conf"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, real...)
	}
	ctx := context.Background()
	for _, path := range files {
		node := strings.TrimSuffix(filepath.Base(path), ".conf")
		t.Run(node, func(t *testing.T) {
			text, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Each router gets its own namespace: routers share definition
			// names whose contents differ from router to router.
			objs, err := frrimport.Import(strings.NewReader(string(text)), frrimport.Options{
				Namespace: node, NodeName: node, RouterClassName: fabricClass,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: node}}); err != nil {
				t.Fatal(err)
			}
			params := &networkv1alpha1.FRRRouterParameters{ObjectMeta: metav1.ObjectMeta{Name: node}, Spec: objs.Parameters}
			for _, o := range importedObjects(objs, params) {
				if err := c.Create(ctx, o); err != nil {
					t.Errorf("%T %s refused: %v", o, o.GetName(), err)
				}
			}
		})
	}
}

func importedObjects(o *frrimport.Objects, params *networkv1alpha1.FRRRouterParameters) []client.Object {
	out := make([]client.Object, 0, 2+len(o.Profiles)+len(o.Peers)+len(o.Policies)+len(o.PrefixLists)+
		len(o.CommunitySets)+len(o.Advertisements)+len(o.StaticRoutes))
	out = append(out, params, o.Router)
	for _, x := range o.Profiles {
		out = append(out, x)
	}
	for _, x := range o.Peers {
		out = append(out, x)
	}
	for _, x := range o.Policies {
		out = append(out, x)
	}
	for _, x := range o.PrefixLists {
		out = append(out, x)
	}
	for _, x := range o.CommunitySets {
		out = append(out, x)
	}
	for _, x := range o.Advertisements {
		out = append(out, x)
	}
	for _, x := range o.StaticRoutes {
		out = append(out, x)
	}
	return out
}

func startAPI(t *testing.T) client.Client {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, p := range paths {
		if !strings.Contains(p, "_bgp") && !strings.Contains(p, "_frr") {
			continue
		}
		data, err := os.ReadFile(p)
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
	return c
}
