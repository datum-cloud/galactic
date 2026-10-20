// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rbaccheck checks shipped RBAC manifests against the calls a
// component makes, with SubjectAccessReviews against a test API server.
package rbaccheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
		ApplyYAML(t, c, data)
	}
}

// ApplyYAML creates every object in a YAML stream whose kind is one of
// kinds, or every object when kinds is empty.
func ApplyYAML(t *testing.T, c client.Client, data []byte, kinds ...string) {
	t.Helper()
	for _, obj := range Objects(t, data) {
		if len(kinds) > 0 && !slices.Contains(kinds, obj.GetKind()) {
			continue
		}
		if err := c.Create(context.Background(), obj); err != nil {
			t.Fatalf("apply %s %s: %v", obj.GetKind(), obj.GetName(), err)
		}
	}
}

// Objects decodes a YAML stream.
func Objects(t *testing.T, data []byte) []*unstructured.Unstructured {
	t.Helper()
	var out []*unstructured.Unstructured
	for _, doc := range strings.Split(string(data), "\n---\n") {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
			t.Fatal(err)
		}
		if len(obj.Object) > 0 {
			out = append(out, obj)
		}
	}
	return out
}

// RBACKinds are the kinds that grant access.
var RBACKinds = []string{"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}

// Kustomize builds an overlay of the resources and components directories,
// in that order, with kustomize or kubectl, and returns the YAML stream. It
// skips the test when neither is installed, and fails it when the build
// fails; Build returns that error instead.
func Kustomize(t *testing.T, resources, components []string) []byte {
	t.Helper()
	out, err := Build(t, resources, components)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Build is Kustomize returning the build's error.
func Build(t *testing.T, resources, components []string) ([]byte, error) {
	t.Helper()
	var cmd []string
	if path, err := exec.LookPath("kustomize"); err == nil {
		cmd = []string{path, "build"}
	} else if path, err := exec.LookPath("kubectl"); err == nil {
		cmd = []string{path, "kustomize"}
	} else {
		t.Skip("install kustomize or kubectl for the manifest check")
	}
	dir := t.TempDir()
	rel := func(paths []string) []string {
		out := make([]string, 0, len(paths))
		for _, p := range paths {
			abs, err := filepath.Abs(p)
			if err != nil {
				t.Fatal(err)
			}
			// kustomize refuses an absolute path to another kustomization.
			r, err := filepath.Rel(dir, abs)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	k, err := yaml.Marshal(map[string][]string{"resources": rel(resources), "components": rel(components)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), k, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	build := exec.CommandContext(t.Context(), cmd[0], append(cmd[1:], dir)...)
	build.Stderr = &stderr
	out, err := build.Output()
	if err != nil {
		return nil, &BuildError{Err: err, Stderr: stderr.String()}
	}
	return out, nil
}

// BuildError is a failed kustomize build and what it printed.
type BuildError struct {
	Err    error
	Stderr string
}

func (e *BuildError) Error() string { return e.Err.Error() + ": " + e.Stderr }
func (e *BuildError) Unwrap() error { return e.Err }

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
