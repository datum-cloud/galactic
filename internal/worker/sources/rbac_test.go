// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"os"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// TestWorkerClusterRoleCoversWatchedTypes reads Worker's packaged RBAC and
// requires get, list and watch on every type the sources cache watches. The
// lab runs Worker as a bare process with admin credentials, so a missing
// grant shows only once Worker is deployed from its manifests, where its
// cache never syncs.
func TestWorkerClusterRoleCoversWatchedTypes(t *testing.T) {
	b, err := os.ReadFile("../../../config/galactic-worker/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var role *rbacv1.ClusterRole
	for _, doc := range strings.Split(string(b), "\n---") {
		var meta struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("parse rbac.yaml: %v", err)
		}
		if meta.Kind == "ClusterRole" && meta.Metadata.Name == "galactic-worker" {
			role = &rbacv1.ClusterRole{}
			if err := yaml.Unmarshal([]byte(doc), role); err != nil {
				t.Fatalf("parse the galactic-worker ClusterRole: %v", err)
			}
		}
	}
	if role == nil {
		t.Fatal("rbac.yaml has no galactic-worker ClusterRole")
	}

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	grants := func(group, resource, verb string) bool {
		for _, r := range role.Rules {
			if slices.Contains(r.APIGroups, group) && slices.Contains(r.Resources, resource) &&
				slices.Contains(r.Verbs, verb) {
				return true
			}
		}
		return false
	}
	for _, obj := range WatchedTypes() {
		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil || len(gvks) == 0 {
			t.Fatalf("%T is not in the sources scheme: %v", obj, err)
		}
		gvk := gvks[0]
		resource := strings.ToLower(gvk.Kind) + "s"
		for _, verb := range []string{"get", "list", "watch"} {
			if !grants(gvk.Group, resource, verb) {
				t.Errorf("the galactic-worker ClusterRole does not grant %s on %s/%s, which the sources cache watches",
					verb, gvk.Group, resource)
			}
		}
	}
}
