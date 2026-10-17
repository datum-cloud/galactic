// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/rbaccheck"
)

// TestControllerRBACCoversEveryCall checks config/fabric-router-controller's
// RBAC grants every call the revision compiler and rollout manager make,
// including the watches, events, leases and pruning the lifecycle test
// cannot exercise, and nothing it should not.
func TestControllerRBACCoversEveryCall(t *testing.T) {
	cfg := rbaccheck.Start(t)
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}}
	if err := admin.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "..", "..", "config", "fabric-router-controller")
	rbaccheck.Apply(t, admin, filepath.Join(dir, "serviceaccount.yaml"), filepath.Join(dir, "rbac.yaml"))

	const (
		g                   = "galactic.datumapis.com"
		deploymentsResource = "fabricrouterdeployments"
	)
	allowed := make([]rbaccheck.Access, 0, 64)
	allowed = append(allowed, rbaccheck.Each(rbaccheck.Read, g, testNS,
		"bgprouters", "bgppeers", "bgppeerprofiles", "bgppolicies", "bgpprefixlists", "bgpcommunitysets",
		"bgpadvertisements", "bgpstaticroutes", "fabricrolloutpolicies", "fabricrouterrevisions",
		deploymentsResource, "fabricreleaseauthorizations")...)
	allowed = append(allowed, rbaccheck.Each(rbaccheck.Read, g, "", "bgprouterclasses", "frrrouterparameters")...)
	allowed = append(allowed, rbaccheck.Each(rbaccheck.Read, "", "", "nodes")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Patch}, g, testNS, "bgprouters/status")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Update}, g, testNS, "bgprouters/finalizers")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Delete}, g, testNS,
		"fabricrouterrevisions")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Update, rbaccheck.Patch}, g,
		testNS, deploymentsResource)...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Patch}, g, testNS, "fabricreleaseauthorizations")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Update}, g, testNS,
		"fabricreleaseauthorizations/status")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Patch}, "events.k8s.io", testNS,
		"events")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Patch}, "", testNS, "events")...)
	all := []string{rbaccheck.Get, rbaccheck.List, rbaccheck.Watch, rbaccheck.Create, rbaccheck.Update,
		rbaccheck.Patch, rbaccheck.Delete}
	allowed = append(allowed, rbaccheck.Each(all,
		"coordination.k8s.io", testNS, "leases")...)

	denied := []rbaccheck.Access{
		{Verb: rbaccheck.Get, Resource: "secrets", Namespace: testNS},
		{Verb: rbaccheck.Update, Group: g, Resource: "fabricrouterrevisions", Namespace: testNS},
		{Verb: rbaccheck.Delete, Group: g, Resource: deploymentsResource, Namespace: testNS},
		{Verb: rbaccheck.Patch, Group: g, Resource: "fabricrouterdeployments/status", Namespace: testNS},
		{Verb: rbaccheck.Create, Group: g, Resource: "fabricreleaseauthorizations", Namespace: testNS},
		{Verb: rbaccheck.Update, Group: g, Resource: "bgprouters", Namespace: testNS},
		{Verb: rbaccheck.Create, Group: "coordination.k8s.io", Resource: "leases", Namespace: "kube-system"},
	}
	user, groups := rbaccheck.ServiceAccount(testNS, "fabric-router-controller")
	rbaccheck.Check(t, admin, user, groups, allowed, denied)
}
