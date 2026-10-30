// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllertest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/controller"
)

// recordingCache is a fake cache that records the kind of every informer the
// manager asks it for, which is every type a controller watches or indexes.
type recordingCache struct {
	*informertest.FakeInformers

	mu    sync.Mutex
	kinds map[schema.GroupVersionKind]bool
}

func (c *recordingCache) record(obj runtime.Object) error {
	gvk, err := apiutil.GVKForObject(obj, c.Scheme)
	if err != nil {
		return err
	}
	c.kinds[gvk] = true
	return nil
}

func (c *recordingCache) GetInformer(
	ctx context.Context, obj client.Object, opts ...cache.InformerGetOption,
) (cache.Informer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.record(obj); err != nil {
		return nil, err
	}
	// A fresh informer per watch: a fake informer is not safe for the
	// concurrent handler registrations two watches of one kind make.
	return controllertest.NewFakeInformer(controllertest.Synced), nil
}

func (c *recordingCache) GetInformerForKind(
	ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption,
) (cache.Informer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kinds[gvk] = true
	return controllertest.NewFakeInformer(controllertest.Synced), nil
}

func (c *recordingCache) IndexField(
	ctx context.Context, obj client.Object, field string, extract client.IndexerFunc,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.record(obj); err != nil {
		return err
	}
	return c.FakeInformers.IndexField(ctx, obj, field, extract)
}

func (c *recordingCache) recorded() []schema.GroupVersionKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]schema.GroupVersionKind, 0, len(c.kinds))
	for gvk := range c.kinds {
		out = append(out, gvk)
	}
	return out
}

// watchedKinds starts a manager with the field index and controllers
// setupControllers registers, configured by projectServices, ipv4VIPs and
// backendHealth, and returns every kind they watch.
func watchedKinds(t *testing.T, projectServices, ipv4VIPs, backendHealth bool) []schema.GroupVersionKind {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	rc := &recordingCache{
		FakeInformers: &informertest.FakeInformers{Scheme: scheme},
		kinds:         map[schema.GroupVersionKind]bool{},
	}
	// Nothing listens here: the fake cache answers every read, and nothing in
	// this test reaches the API server.
	mgr, err := ctrl.NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
		Metrics:                metricsserver.Options{BindAddress: "0"},
		NewCache:               func(*rest.Config, cache.Options) (cache.Cache, error) { return rc, nil },
		Controller:             config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := controller.ServiceScope{ProjectServices: projectServices}
	if err := setupControllers(ctx, mgr, &controller.NetworkGatewayReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		APIReader:     mgr.GetAPIReader(),
		IPv4VIPs:      ipv4VIPs,
		BackendHealth: backendHealth,
		Scope:         scope,
	}, &controller.NetworkServiceReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		APIReader: mgr.GetAPIReader(),
		Scope:     scope,
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	// Each watch asks for its informer as its controller starts, and every
	// controller starts at once. Wait until no new kind has appeared for a
	// second.
	seen, quiet := 0, 0
	for deadline := time.Now().Add(30 * time.Second); quiet < 10; {
		if time.Now().After(deadline) {
			t.Fatalf("watched kinds still changing after 30s: %v", rc.recorded())
		}
		time.Sleep(100 * time.Millisecond)
		if n := len(rc.recorded()); n != seen {
			seen, quiet = n, 0
		} else if n > 0 {
			quiet++
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("manager: %v", err)
	}
	return rc.recorded()
}

// TestWatchedResourcesMatchControllers fails when the gateway's controllers
// watch a type checkWatchPermissions does not check, or the other way round,
// so a new watch cannot ship without its pre-flight entry.
func TestWatchedResourcesMatchControllers(t *testing.T) {
	for _, tc := range []struct{ projectServices, ipv4VIPs, backendHealth bool }{
		{},
		{ipv4VIPs: true},
		{backendHealth: true},
		{projectServices: true, ipv4VIPs: true, backendHealth: true},
	} {
		t.Run(fmt.Sprintf("projectServices=%t,ipv4VIPs=%t,backendHealth=%t",
			tc.projectServices, tc.ipv4VIPs, tc.backendHealth), func(t *testing.T) {
			want := map[schema.GroupVersionKind]watchedResource{}
			for _, r := range watchedResources(tc.projectServices) {
				want[schema.GroupVersionKind{Group: r.group, Version: r.version, Kind: r.kind}] = r
			}
			got := watchedKinds(t, tc.projectServices, tc.ipv4VIPs, tc.backendHealth)
			for _, gvk := range got {
				if _, ok := want[gvk]; !ok {
					t.Errorf("a controller watches %s, which watchedResources leaves out", gvk)
				}
			}
			for gvk := range want {
				if !slices.Contains(got, gvk) {
					t.Errorf("watchedResources checks %s, which no controller watches", gvk)
				}
			}
		})
	}
}

// TestWatchedResourceNames fails when a pre-flight entry names a resource
// other than its kind's CRD does, which would review access to the wrong
// resource.
func TestWatchedResourceNames(t *testing.T) {
	for _, r := range watchedResources(true) {
		data, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", r.group+"_"+r.resource+".yaml"))
		if err != nil {
			t.Errorf("%s: no CRD for resource %q: %v", r.kind, r.resource, err)
			continue
		}
		var crd struct {
			Spec struct {
				Group string `json:"group"`
				Names struct {
					Kind   string `json:"kind"`
					Plural string `json:"plural"`
				} `json:"names"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(data, &crd); err != nil {
			t.Fatal(err)
		}
		if crd.Spec.Group != r.group || crd.Spec.Names.Kind != r.kind || crd.Spec.Names.Plural != r.resource {
			t.Errorf("%s: pre-flight names %s.%s, CRD names kind %s as %s.%s",
				r.kind, r.resource, r.group, crd.Spec.Names.Kind, crd.Spec.Names.Plural, crd.Spec.Group)
		}
	}
}

// TestShippedRoleGrantsWatches fails when config/galactic-gateway/rbac.yaml
// does not grant list and watch on a type the pre-flight checks, which would
// fail every gateway that runs with the shipped role.
func TestShippedRoleGrantsWatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "galactic-gateway", "rbac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var role *rbacv1.ClusterRole
	for _, doc := range strings.Split(string(data), "\n---\n") {
		var r rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		if r.Kind == "ClusterRole" {
			role = &r
			break
		}
	}
	if role == nil {
		t.Fatal("no ClusterRole in config/galactic-gateway/rbac.yaml")
	}
	grants := func(group, resource, verb string) bool {
		return slices.ContainsFunc(role.Rules, func(rule rbacv1.PolicyRule) bool {
			return slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) &&
				slices.Contains(rule.Verbs, verb)
		})
	}
	for _, r := range watchedResources(true) {
		for _, verb := range informerVerbs {
			if !grants(r.group, r.resource, verb) {
				t.Errorf("config/galactic-gateway/rbac.yaml does not grant %s on %s.%s", verb, r.resource, r.group)
			}
		}
	}
}
