// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/rbaccheck"
)

// Resources and modes the RBAC checks name.
const (
	configMapsResource = "configmaps"
	nodesResource      = "nodes"
	secretsResource    = "secrets"
	modeRetired        = "configmap-retired"
)

// The fabric-router base and its components, and the calls the agent's
// RBAC turns on.
var (
	fabricRouterBase    = filepath.Join("..", "..", "config", "fabric-router")
	activationComponent = filepath.Join(fabricRouterBase, "components", "activation")
	retiredComponent    = filepath.Join(fabricRouterBase, "components", "configmap-retired")

	configMapReads = rbaccheck.Each(rbaccheck.Read, "", depNamespace, configMapsResource)
	agentEvents    = rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Patch}, "events.k8s.io", depNamespace,
		"events")
)

// TestConfigMapRetiredComponent checks what components/configmap-retired
// renders: the env on both agent containers, no ConfigMap read in any Role,
// and a failed build unless components/activation comes first.
func TestConfigMapRetiredComponent(t *testing.T) {
	out := rbaccheck.Kustomize(t, []string{fabricRouterBase}, []string{activationComponent, retiredComponent})
	var daemonSets int
	for _, obj := range rbaccheck.Objects(t, out) {
		switch obj.GetKind() {
		case "Role", "ClusterRole":
			rules, _, _ := unstructured.NestedSlice(obj.Object, "rules")
			for _, r := range rules {
				rule, _ := r.(map[string]any)
				resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
				if slices.Contains(resources, configMapsResource) || slices.Contains(resources, "*") {
					t.Errorf("%s %s grants %v", obj.GetKind(), obj.GetName(), rule)
				}
			}
		case "DaemonSet":
			if obj.GetName() != "fabric-router" {
				continue
			}
			daemonSets++
			for _, field := range []string{"initContainers", "containers"} {
				containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", field)
				for _, c := range containers {
					container, _ := c.(map[string]any)
					name, _, _ := unstructured.NestedString(container, "name")
					if name != "frr-init" && name != "config-agent" {
						continue
					}
					env := map[string]string{}
					vars, _, _ := unstructured.NestedSlice(container, "env")
					for _, v := range vars {
						ev, _ := v.(map[string]any)
						n, _, _ := unstructured.NestedString(ev, "name")
						env[n], _, _ = unstructured.NestedString(ev, "value")
					}
					if env["FABRIC_CONFIGMAPS"] != "false" || env["FABRIC_ACTIVATION"] != "true" {
						t.Errorf("%s env FABRIC_CONFIGMAPS=%q FABRIC_ACTIVATION=%q", name, env["FABRIC_CONFIGMAPS"],
							env["FABRIC_ACTIVATION"])
					}
				}
			}
		}
	}
	if daemonSets != 1 {
		t.Errorf("%d fabric-router DaemonSets rendered", daemonSets)
	}

	for name, components := range map[string][]string{
		"without activation": {retiredComponent},
		"before activation":  {retiredComponent, activationComponent},
	} {
		_, err := rbaccheck.Build(t, []string{fabricRouterBase}, components)
		var build *rbaccheck.BuildError
		if !errors.As(err, &build) {
			t.Errorf("built %s: %v", name, err)
		}
	}
}

// TestAgentRBACByMode checks the RBAC the activation overlay renders, with
// and without components/configmap-retired: ConfigMap reads only while the
// ConfigMap path is on, and the Pod events the next-hop check raises in
// both.
func TestAgentRBACByMode(t *testing.T) {
	for _, mode := range []string{"activation", modeRetired} {
		t.Run(mode, func(t *testing.T) {
			components := []string{activationComponent}
			if mode == modeRetired {
				components = append(components, retiredComponent)
			}
			out := rbaccheck.Kustomize(t, []string{fabricRouterBase}, components)
			cfg := rbaccheck.Start(t)
			admin, err := client.New(cfg, client.Options{})
			if err != nil {
				t.Fatal(err)
			}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: depNamespace}}
			if err := admin.Create(context.Background(), ns); err != nil {
				t.Fatal(err)
			}
			rbaccheck.ApplyYAML(t, admin, out, rbaccheck.RBACKinds...)

			allowed := append([]rbaccheck.Access{}, agentEvents...)
			allowed = append(allowed,
				rbaccheck.Access{Verb: rbaccheck.Get, Group: "galactic.datumapis.com",
					Resource: "fabricrouterdeployments", Namespace: depNamespace},
				rbaccheck.Access{Verb: rbaccheck.Get, Resource: nodesResource, Name: depNode})
			denied := []rbaccheck.Access{
				{Verb: rbaccheck.Get, Resource: secretsResource, Namespace: depNamespace},
				{Verb: rbaccheck.Create, Resource: configMapsResource, Namespace: depNamespace},
				{Verb: rbaccheck.Update, Resource: configMapsResource, Namespace: depNamespace},
			}
			if mode == modeRetired {
				denied = append(denied, configMapReads...)
				denied = append(denied, rbaccheck.Access{Verb: rbaccheck.Get, Resource: configMapsResource,
					Namespace: depNamespace, Name: ConfigMapName(depNode)})
			} else {
				allowed = append(allowed, configMapReads...)
			}
			user, groups := rbaccheck.ServiceAccount(depNamespace, "fabric-router")
			rbaccheck.Check(t, admin, user, groups, allowed, denied)
		})
	}
}

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
	allowed = append(allowed, configMapReads...)
	allowed = append(allowed, agentEvents...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get, rbaccheck.List}, g, depNamespace,
		deploymentsResource)...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Patch}, g, depNamespace,
		"fabricrouterdeployments/status")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get}, g, depNamespace,
		"fabricrouterrevisions", "fabricreleaseauthorizations")...)
	allowed = append(allowed,
		rbaccheck.Access{Verb: rbaccheck.Get, Resource: nodesResource, Name: depNode},
		rbaccheck.Access{Verb: rbaccheck.Get, Resource: "namespaces", Name: metav1.NamespaceSystem})

	denied := []rbaccheck.Access{
		{Verb: rbaccheck.Update, Group: g, Resource: deploymentsResource + "/status", Namespace: depNamespace},
		{Verb: rbaccheck.Get, Group: g, Resource: deploymentsResource + "/status", Namespace: depNamespace},
		{Verb: rbaccheck.Get, Resource: secretsResource, Namespace: depNamespace},
		{Verb: rbaccheck.List, Resource: secretsResource, Namespace: depNamespace},
		{Verb: rbaccheck.Update, Group: g, Resource: deploymentsResource, Namespace: depNamespace},
		{Verb: rbaccheck.Patch, Group: g, Resource: deploymentsResource, Namespace: depNamespace},
		{Verb: rbaccheck.List, Group: g, Resource: "fabricrouterrevisions", Namespace: depNamespace},
		{Verb: rbaccheck.Get, Resource: "namespaces", Name: depNamespace},
		{Verb: rbaccheck.List, Resource: nodesResource},
	}
	user, groups := rbaccheck.ServiceAccount(depNamespace, "fabric-router")
	rbaccheck.Check(t, admin, user, groups, allowed, denied)
}
