// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/rbaccheck"
)

// TestAgentRBACCoversEveryCall checks config/fabric-router's RBAC and the
// activation Component's grant every call fabric-config-agent makes, and
// none it should not, Secrets above all.
func TestAgentRBACCoversEveryCall(t *testing.T) {
	cfg := rbaccheck.Start(t)
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: depNamespace}}
	if err := admin.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "config", "fabric-router")
	rbaccheck.Apply(t, admin, filepath.Join(root, "serviceaccount.yaml"), filepath.Join(root, "rbac.yaml"),
		filepath.Join(root, "components", "activation", "rbac.yaml"))

	const (
		g                   = "galactic.datumapis.com"
		deploymentsResource = "fabricrouterdeployments"
	)
	allowed := make([]rbaccheck.Access, 0, 64)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get, rbaccheck.List, rbaccheck.Watch}, "",
		depNamespace, "configmaps")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Patch}, "events.k8s.io",
		depNamespace, "events")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get, rbaccheck.List}, g, depNamespace,
		deploymentsResource)...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Patch}, g, depNamespace,
		"fabricrouterdeployments/status")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get}, g, depNamespace,
		"fabricrouterrevisions", "fabricreleaseauthorizations")...)
	allowed = append(allowed,
		rbaccheck.Access{Verb: rbaccheck.Get, Resource: "nodes", Name: depNode},
		rbaccheck.Access{Verb: rbaccheck.Get, Resource: "namespaces", Name: metav1.NamespaceSystem})

	denied := []rbaccheck.Access{
		{Verb: rbaccheck.Get, Resource: "secrets", Namespace: depNamespace},
		{Verb: rbaccheck.List, Resource: "secrets", Namespace: depNamespace},
		{Verb: rbaccheck.Update, Group: g, Resource: deploymentsResource, Namespace: depNamespace},
		{Verb: rbaccheck.Patch, Group: g, Resource: deploymentsResource, Namespace: depNamespace},
		{Verb: rbaccheck.List, Group: g, Resource: "fabricrouterrevisions", Namespace: depNamespace},
		{Verb: rbaccheck.Get, Resource: "namespaces", Name: depNamespace},
		{Verb: rbaccheck.List, Resource: "nodes"},
	}
	user, groups := rbaccheck.ServiceAccount(depNamespace, "fabric-router")
	rbaccheck.Check(t, admin, user, groups, allowed, denied)
}
