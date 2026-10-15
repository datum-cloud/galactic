// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// labTenants is the containerlab lab's tenant fixtures, which enforce traffic
// policy (deploy/containerlab/resources/tenants/).
var labTenants = filepath.Join("..", "..", "deploy", "containerlab", "resources", "tenants")

// yamlDocs splits every YAML document in path.
func yamlDocs(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	var out [][]byte
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(bytes.TrimSpace(doc)) > 0 {
			out = append(out, doc)
		}
	}
}

// labPolicies reads every policy set, by set name and policy name.
func labPolicies(t *testing.T) map[string]map[string]galacticv1alpha1.TrafficPolicy {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(labTenants, "policies", "*", "policies.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no lab policy sets under %s: %v", labTenants, err)
	}
	sets := map[string]map[string]galacticv1alpha1.TrafficPolicy{}
	for _, f := range files {
		set := filepath.Base(filepath.Dir(f))
		sets[set] = map[string]galacticv1alpha1.TrafficPolicy{}
		for _, doc := range yamlDocs(t, f) {
			var p galacticv1alpha1.TrafficPolicy
			if err := yaml.UnmarshalStrict(doc, &p); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			sets[set][p.Name] = p
		}
	}
	return sets
}

// TestLabPoliciesAreValid: every policy the lab enforces is admitted by the
// CRD schema and passes the webhook's Go validation and the compiler, so a
// lab deploy never stalls on a fixture the webhook refuses.
func TestLabPoliciesAreValid(t *testing.T) {
	sets := labPolicies(t)
	for set, policies := range sets {
		for name, p := range policies {
			model, errs := trafficpolicy.FromAPI(p.Spec, field.NewPath("spec"))
			if len(errs) > 0 {
				t.Errorf("%s/%s: %v", set, name, errs)
				continue
			}
			if _, err := trafficpolicy.Compile(model); err != nil {
				t.Errorf("%s/%s: %v", set, name, err)
			}
		}
	}

	c, _ := startAPIServer(t)
	for set, policies := range sets {
		for name, p := range policies {
			obj := p.DeepCopy()
			obj.Name = set + "-" + name
			obj.Namespace = testNamespace
			if err := c.Create(context.Background(), obj); err != nil {
				t.Errorf("%s/%s: the API server refused it: %v", set, name, err)
			}
		}
	}
}

// TestLabTenantsAreBound: every galactic attachment a lab tenant defines has
// a binding in that tenant's policy/, naming policies its set defines, so no
// lab tenant comes up denying everything.
func TestLabTenantsAreBound(t *testing.T) {
	sets := labPolicies(t)
	tenants, err := filepath.Glob(filepath.Join(labTenants, "ns*"))
	if err != nil || len(tenants) == 0 {
		t.Fatalf("no lab tenants under %s: %v", labTenants, err)
	}
	for _, dir := range tenants {
		ns := filepath.Base(dir)
		set := policySet(t, filepath.Join(dir, "policy", "kustomization.yaml"))
		policies, ok := sets[set]
		if !ok {
			t.Errorf("%s: policy/ uses set %q, which does not exist", ns, set)
			continue
		}
		bound := map[string]bool{}
		for _, doc := range yamlDocs(t, filepath.Join(dir, "policy", "bindings.yaml")) {
			var b galacticv1alpha1.TrafficPolicyBinding
			if err := yaml.UnmarshalStrict(doc, &b); err != nil {
				t.Fatalf("%s: %v", ns, err)
			}
			bound[b.Name] = true
			for _, ref := range []*galacticv1alpha1.LocalPolicyReference{b.Spec.IngressPolicyRef, b.Spec.EgressPolicyRef} {
				if ref == nil {
					t.Errorf("%s/%s: a direction is unbound, so it denies everything", ns, b.Name)
				} else if _, ok := policies[ref.Name]; !ok {
					t.Errorf("%s/%s: names %q, which set %s does not define", ns, b.Name, ref.Name, set)
				}
			}
		}
		nads := map[string]bool{}
		for _, nad := range galacticNADs(t, dir) {
			nads[nad] = true
			if !bound[nad] {
				t.Errorf("%s: attachment %s has no binding in policy/bindings.yaml", ns, nad)
			}
		}
		for name := range bound {
			if !nads[name] {
				t.Errorf("%s: binding %s names no attachment the tenant defines", ns, name)
			}
		}
	}
}

// policySet is the policy set a tenant's policy/kustomization.yaml pulls in.
// It fails unless the kustomization also applies bindings.yaml.
func policySet(t *testing.T, path string) string {
	t.Helper()
	var k struct {
		Resources []string `json:"resources"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	set := ""
	bindings := false
	for _, r := range k.Resources {
		switch {
		case strings.Contains(r, "policies/"):
			set = filepath.Base(r)
		case r == "bindings.yaml":
			bindings = true
		}
	}
	if set == "" || !bindings {
		t.Fatalf("%s must pull in one policy set and bindings.yaml, has %v", path, k.Resources)
	}
	return set
}

// galacticNADs names every NetworkAttachmentDefinition under a tenant's site
// directories whose chain runs galactic-veth or galactic-tap.
func galacticNADs(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		for _, doc := range yamlDocs(t, f) {
			var nad struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					Config string `json:"config"`
				} `json:"spec"`
			}
			if err := yaml.Unmarshal(doc, &nad); err != nil || nad.Kind != "NetworkAttachmentDefinition" {
				continue
			}
			var conf struct {
				Plugins []struct {
					Type string `json:"type"`
				} `json:"plugins"`
			}
			if err := json.Unmarshal([]byte(nad.Spec.Config), &conf); err != nil {
				t.Fatalf("%s: %s: %v", f, nad.Metadata.Name, err)
			}
			for _, p := range conf.Plugins {
				if (p.Type == "galactic-veth" || p.Type == "galactic-tap") && !seen[nad.Metadata.Name] {
					seen[nad.Metadata.Name] = true
					out = append(out, nad.Metadata.Name)
				}
			}
		}
	}
	return out
}
