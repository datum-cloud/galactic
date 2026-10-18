// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
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
		secrets             = "secrets"
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
	// Secret metadata, by name, for the credentials a revision uses.
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get}, "", testNS, secrets)...)
	all := []string{rbaccheck.Get, rbaccheck.List, rbaccheck.Watch, rbaccheck.Create, rbaccheck.Update,
		rbaccheck.Patch, rbaccheck.Delete}
	allowed = append(allowed, rbaccheck.Each(all,
		"coordination.k8s.io", testNS, "leases")...)

	denied := []rbaccheck.Access{
		{Verb: rbaccheck.Update, Group: g, Resource: "fabricreleaseauthorizations", Namespace: testNS},
		{Verb: rbaccheck.Patch, Group: g, Resource: "fabricreleaseauthorizations/status", Namespace: testNS},
		{Verb: rbaccheck.Get, Group: g, Resource: "bgprouters/status", Namespace: testNS},
		{Verb: rbaccheck.Update, Group: g, Resource: "bgprouters/status", Namespace: testNS},
		{Verb: rbaccheck.List, Resource: secrets, Namespace: testNS},
		{Verb: rbaccheck.Watch, Resource: secrets, Namespace: testNS},
		{Verb: rbaccheck.Update, Resource: secrets, Namespace: testNS},
		{Verb: rbaccheck.Get, Resource: secrets, Namespace: "kube-system"},
		{Verb: rbaccheck.Get, Resource: secrets},
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

// TestCredentialsWithShippedRBAC: the shipped RBAC lets the rollout
// manager read a credential's Secret metadata by name in its namespace,
// uncached, and nowhere else: a Secret elsewhere is an error, not
// unresolvable, so the release is never promoted past it.
func TestCredentialsWithShippedRBAC(t *testing.T) {
	cfg := rbaccheck.Start(t)
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, n := range []string{testNS, "elsewhere"} {
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: n, Name: secretName},
			StringData: map[string]string{"password": "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	secret := &corev1.Secret{}
	if err := admin.Get(ctx, client.ObjectKey{Namespace: testNS, Name: secretName}, secret); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "..", "..", "config", "fabric-router-controller")
	rbaccheck.Apply(t, admin, filepath.Join(dir, "serviceaccount.yaml"), filepath.Join(dir, "rbac.yaml"))
	as := rest.CopyConfig(cfg)
	user, groups := rbaccheck.ServiceAccount(testNS, "fabric-router-controller")
	as.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
	c, err := client.New(as, client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	rev := routerRevision("edge-cccccccccc", digestC, secretName)
	got, err := Credentials(ctx, c, testNS, rev)
	if err != nil || got[secretName] != string(secret.UID) {
		t.Fatalf("Credentials = %v, %v, want %s's UID %s", got, err, secretName, secret.UID)
	}
	missing := routerRevision("edge-eeeeeeeeee", strings.Repeat("e", 64), "missing")
	if got, err := Credentials(ctx, c, testNS, missing); err != nil || len(got) != 0 {
		t.Errorf("a missing Secret: %v, %v, want it left out", got, err)
	}
	if _, err := Credentials(ctx, c, "elsewhere", rev); err == nil {
		t.Error("read a Secret outside the controller's namespace")
	}
}
