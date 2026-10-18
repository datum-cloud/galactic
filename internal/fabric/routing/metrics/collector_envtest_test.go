// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

// TestCollectorThroughManager runs the collector the way
// fabric-router-controller does: added to a manager, reading its cache,
// against a real API server holding the CRDs and their admission rules.
func TestCollectorThroughManager(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the collector envtest")
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "config", "crd", "galactic.datumapis.com_*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, p := range paths {
		base := filepath.Base(p)
		if !strings.Contains(base, "_bgprouter") && !strings.Contains(base, "_fabric") {
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
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		t.Fatal(err)
	}
	collector := &Collector{Reader: mgr.GetClient(), Rollout: true}
	if err := mgr.Add(collector); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := mgr.Start(ctx); err != nil {
			t.Errorf("manager: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	text, err := os.ReadFile(filepath.Join("..", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := frrimport.Import(strings.NewReader(string(text)), frrimport.Options{
		Namespace: testNS, NodeName: testRouter, RouterClassName: fabricKind,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := o.Router
	dep := &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Name: router.Name, Namespace: testNS},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: router.Name, UID: "router-uid"},
			Target:    networkv1alpha1.FabricNodeIdentity{NodeName: testRouter, NodeUID: "node-uid"},
			Source:    networkv1alpha1.FabricConfigSourceShadow,
		},
	}
	auth := &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: testNS},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: "fabric", FleetReleaseID: "r1",
			FleetSequence: 1,
			Deployments: []networkv1alpha1.FabricReleaseTarget{{
				Deployment: router.Name, DeploymentUID: "dep-uid", Revision: router.Name + "-0123456789",
				ActivationDependencyDigest: strings.Repeat("0", 64),
			}},
		},
	}
	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}},
		&networkv1alpha1.BGPRouterClass{ObjectMeta: metav1.ObjectMeta{Name: fabricKind},
			Spec: networkv1alpha1.BGPRouterClassSpec{ControllerName: networkv1alpha1.FabricRouterControllerName}},
		router, dep, auth,
	} {
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("create %s: %v", obj.GetName(), err)
		}
	}
	meta.SetStatusCondition(&router.Status.Conditions, metav1.Condition{
		Type: networkv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionFalse, Reason: "UnresolvedRef",
		Message: "a peer names a missing profile",
	})
	if err := c.Status().Update(ctx, router); err != nil {
		t.Fatal(err)
	}

	want := map[string]int{
		prefix + "deployment_info":     1,
		prefix + "release_outstanding": 1,
		prefix + "releases":            1,
		prefix + "router_accepted":     1,
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok := true
		for name, n := range want {
			if testutil.CollectAndCount(collector, name) != n {
				ok = false
			}
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			for name, n := range want {
				t.Errorf("%s: %d series, want %d", name, testutil.CollectAndCount(collector, name), n)
			}
			t.FailNow()
		}
		time.Sleep(100 * time.Millisecond)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(collector)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != prefix+"router_accepted" {
			continue
		}
		if v := f.GetMetric()[0].GetGauge().GetValue(); v != 0 {
			t.Errorf("router_accepted = %v for a refused router, want 0", v)
		}
	}
}
