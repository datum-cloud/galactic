// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rbaccheck checks shipped RBAC manifests against the calls a
// component makes, with SubjectAccessReviews against a test API server.
package rbaccheck

import (
	"context"
	"os"
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

// Verbs.
const (
	Get    = "get"
	List   = "list"
	Watch  = "watch"
	Create = "create"
	Update = "update"
	Patch  = "patch"
	Delete = "delete"
)

// Read is get, list and watch.
var Read = []string{Get, List, Watch}

// Access is one call: a verb on a resource, namespaced or not.
type Access struct {
	Verb, Group, Resource, Namespace, Name string
}

func (a Access) String() string {
	r := a.Resource
	if a.Group != "" {
		r += "." + a.Group
	}
	s := a.Verb + " " + r
	if a.Namespace != "" {
		s += " in " + a.Namespace
	}
	if a.Name != "" {
		s += " named " + a.Name
	}
	return s
}

// Start runs an API server holding no CRDs; RBAC needs none.
func Start(t *testing.T) *rest.Config {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the RBAC check")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	return cfg
}

// Apply creates every object in the YAML files.
func Apply(t *testing.T, c client.Client, paths ...string) {
	t.Helper()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(data), "\n---\n") {
			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				t.Fatal(err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if err := c.Create(context.Background(), obj); err != nil {
				t.Fatalf("apply %s %s: %v", obj.GetKind(), obj.GetName(), err)
			}
		}
	}
}

// Check asks whether user may make each call, and fails the test for each
// allowed call that is denied and each denied call that is allowed.
func Check(t *testing.T, c client.Client, user string, groups []string, allowed, denied []Access) {
	t.Helper()
	ask := func(a Access) bool {
		review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User: user, Groups: groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb: a.Verb, Group: a.Group, Resource: resourceOf(a.Resource), Subresource: subresourceOf(a.Resource),
				Namespace: a.Namespace, Name: a.Name,
			},
		}}
		if err := c.Create(context.Background(), review); err != nil {
			t.Fatalf("review %s: %v", a, err)
		}
		return review.Status.Allowed
	}
	for _, a := range allowed {
		if !ask(a) {
			t.Errorf("%s may not %s", user, a)
		}
	}
	for _, a := range denied {
		if ask(a) {
			t.Errorf("%s may %s", user, a)
		}
	}
}

func resourceOf(r string) string {
	res, _, _ := strings.Cut(r, "/")
	return res
}

func subresourceOf(r string) string {
	_, sub, _ := strings.Cut(r, "/")
	return sub
}

// ServiceAccount is a service account's user name and groups.
func ServiceAccount(namespace, name string) (string, []string) {
	return "system:serviceaccount:" + namespace + ":" + name,
		[]string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"}
}

// Each expands verbs over resources in one group and namespace.
func Each(verbs []string, group string, namespace string, resources ...string) []Access {
	out := make([]Access, 0, len(verbs)*len(resources))
	for _, r := range resources {
		for _, v := range verbs {
			out = append(out, Access{Verb: v, Group: group, Resource: r, Namespace: namespace})
		}
	}
	return out
}
