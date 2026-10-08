// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
)

// ipv4 is the address family most test queries use.
const ipv4 fabricapi.AddressFamily = "IPv4"

// TestCRDSchema installs the generated CRD into a real API server and checks
// its structural bounds, CEL rules, immutable spec and status subresource.
// It needs envtest's kube-apiserver and etcd: set KUBEBUILDER_ASSETS (e.g.
// `setup-envtest use -p path`) to run it.
func TestCRDSchema(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "..", "config", "fabric-api", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	s := runtime.NewScheme()
	if err := fabricapi.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	valid := func(name string) *fabricapi.FabricQuery {
		return &fabricapi.FabricQuery{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: fabricapi.FabricQuerySpec{
				RequestID: "req-" + name,
				Source:    fabricapi.PublicQueryReference{UID: "u", Cluster: "p", Namespace: "default", Name: name},
				Query:     fabricapi.QuerySpec{Type: "RouteLookup", Target: "198.51.100.0/24", AddressFamily: ipv4},
				Site:      "dfw", ClusterName: "dfw-edge-1",
				ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute)),
			},
		}
	}
	mustReject := func(name, want string, mutate func(*fabricapi.FabricQuery)) {
		t.Helper()
		fq := valid(name)
		mutate(fq)
		err := c.Create(ctx, fq)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, want)
		}
	}

	fq := valid("ok")
	if err := c.Create(ctx, fq); err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}

	mustReject("summary-target", "target is required, except for BGPSummary", func(f *fabricapi.FabricQuery) {
		f.Spec.Query = fabricapi.QuerySpec{Type: "BGPSummary", Target: "x", AddressFamily: ipv4}
	})
	mustReject("lookup-no-target", "target is required, except for BGPSummary", func(f *fabricapi.FabricQuery) {
		f.Spec.Query.Target = ""
	})
	mustReject("hostname-on-lookup", "hostname is only for probes", func(f *fabricapi.FabricQuery) {
		f.Spec.Query.Hostname = "example.com"
	})
	mustReject("bad-type", "Unsupported value", func(f *fabricapi.FabricQuery) { f.Spec.Query.Type = "Whois" })
	mustReject("bad-family", "Unsupported value", func(f *fabricapi.FabricQuery) { f.Spec.Query.AddressFamily = "ipv4" })
	mustReject("long-target", "Too long", func(f *fabricapi.FabricQuery) {
		f.Spec.Query.Target = strings.Repeat("a", 256)
	})
	mustReject("budget", "less than or equal to 100", func(f *fabricapi.FabricQuery) { f.Spec.Budgets.MaxPrefixes = 1000 })
	mustReject("request-id", "spec.requestID", func(f *fabricapi.FabricQuery) { f.Spec.RequestID = "-bad id" })

	ping := valid("ping")
	ping.Spec.Query = fabricapi.QuerySpec{
		Type: "Ping", Target: "1.1.1.1", AddressFamily: ipv4, Hostname: "one.one.one.one",
	}
	if err := c.Create(ctx, ping); err != nil {
		t.Errorf("ping with display hostname rejected: %v", err)
	}
	summary := valid("summary")
	summary.Spec.Query = fabricapi.QuerySpec{Type: "BGPSummary", AddressFamily: "IPv6"}
	if err := c.Create(ctx, summary); err != nil {
		t.Errorf("summary without target rejected: %v", err)
	}

	// The spec is immutable.
	fq.Spec.Query.Target = "203.0.113.0/24"
	if err := c.Update(ctx, fq); err == nil || !strings.Contains(err.Error(), "spec is immutable") {
		t.Errorf("spec update: %v", err)
	}

	// Status goes through the subresource and is bounded.
	if err := c.Get(ctx, client.ObjectKeyFromObject(fq), fq); err != nil {
		t.Fatal(err)
	}
	m := int32(1)
	fq.Status = fabricapi.FabricQueryStatus{
		RequestID: fq.Spec.RequestID, ProducerCluster: "dfw-edge-1", Attempt: 1,
		Observations: []fabricapi.NodeObservation{{Node: "edge-a", Matched: &m, MatchedIsExact: true,
			Routes: &fabricapi.RouteResult{
				LookupKind: "Exact",
				Prefixes:   []fabricapi.PrefixObservation{{Prefix: "198.51.100.0/24"}},
			}}},
		Conditions: []metav1.Condition{{
			Type:               fabricapi.ConditionComplete,
			Status:             metav1.ConditionTrue,
			Reason:             fabricapi.ReasonSucceeded,
			LastTransitionTime: metav1.Now(),
		}},
	}
	if err := c.Status().Update(ctx, fq); err != nil {
		t.Fatalf("status update: %v", err)
	}
	for i := range 32 {
		name := "n" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		fq.Status.Observations = append(fq.Status.Observations, fabricapi.NodeObservation{Node: name})
	}
	if err := c.Status().Update(ctx, fq); err == nil || !strings.Contains(err.Error(), "must have at most 32 items") {
		t.Errorf("33 observations: %v", err)
	}
}
