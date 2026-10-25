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

// TestLabTenantsAreBound: at every site a lab tenant deploys to, every
// galactic attachment it defines there has a binding in the policy that site
// applies (policy/<site>/ where it exists, else policy/), naming policies its
// set defines, and no binding names an attachment the site lacks, so no lab
// tenant comes up denying everything and no binding waits on an interface that
// never appears.
func TestLabTenantsAreBound(t *testing.T) {
	sets := labPolicies(t)
	tenants, err := filepath.Glob(filepath.Join(labTenants, "ns*"))
	if err != nil || len(tenants) == 0 {
		t.Fatalf("no lab tenants under %s: %v", labTenants, err)
	}
	for _, dir := range tenants {
		ns := filepath.Base(dir)
		sites, err := filepath.Glob(filepath.Join(dir, "*", "kustomization.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		overlays, err := filepath.Glob(filepath.Join(dir, "policy", "*", "kustomization.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range overlays {
			site := filepath.Base(filepath.Dir(o))
			if _, err := os.Stat(filepath.Join(dir, site, "kustomization.yaml")); site != "base" && err != nil {
				t.Errorf("%s: policy/%s names no site the tenant deploys to", ns, site)
			}
		}
		for _, k := range sites {
			site := filepath.Base(filepath.Dir(k))
			if site == "base" || site == "policy" {
				continue
			}
			policyDir := filepath.Join(dir, "policy", site)
			if _, err := os.Stat(policyDir); err != nil {
				policyDir = filepath.Join(dir, "policy")
			}
			checkSiteBound(t, sets, ns+"/"+site, policyDir,
				galacticNADs(t, filepath.Join(dir, "base"), filepath.Join(dir, site)))
		}
	}
}

// checkSiteBound checks one tenant site: the bindings policyDir applies against
// the galactic attachments the site defines.
func checkSiteBound(
	t *testing.T, sets map[string]map[string]galacticv1alpha1.TrafficPolicy, where, policyDir string, attachments []string,
) {
	t.Helper()
	set, files := policyResources(t, policyDir)
	policies, ok := sets[set]
	if !ok {
		t.Errorf("%s: %s uses set %q, which does not exist", where, policyDir, set)
		return
	}
	if len(files) == 0 {
		t.Errorf("%s: %s applies no bindings", where, policyDir)
	}
	bound := map[string]bool{}
	for _, f := range files {
		for _, doc := range yamlDocs(t, f) {
			var b galacticv1alpha1.TrafficPolicyBinding
			if err := yaml.UnmarshalStrict(doc, &b); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			bound[b.Name] = true
			for _, ref := range []*galacticv1alpha1.LocalPolicyReference{b.Spec.IngressPolicyRef, b.Spec.EgressPolicyRef} {
				if ref == nil {
					t.Errorf("%s/%s: a direction is unbound, so it denies everything", where, b.Name)
				} else if _, ok := policies[ref.Name]; !ok {
					t.Errorf("%s/%s: names %q, which set %s does not define", where, b.Name, ref.Name, set)
				}
			}
		}
	}
	defined := map[string]bool{}
	for _, nad := range attachments {
		defined[nad] = true
		if !bound[nad] {
			t.Errorf("%s: attachment %s has no binding in %s", where, nad, policyDir)
		}
	}
	for name := range bound {
		if !defined[name] {
			t.Errorf("%s: binding %s names no attachment the site defines", where, name)
		}
	}
}

// policyResources follows a tenant's policy kustomization through its local
// directories and returns the policy set it pulls in and every bindings file
// it applies. It fails unless it finds exactly one set.
func policyResources(t *testing.T, dir string) (string, []string) {
	t.Helper()
	var k struct {
		Resources []string `json:"resources"`
	}
	path := filepath.Join(dir, "kustomization.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	set := ""
	var files []string
	for _, r := range k.Resources {
		switch {
		case strings.Contains(r, "policies/"):
			if set != "" {
				t.Fatalf("%s pulls in two policy sets", path)
			}
			set = filepath.Base(r)
		case strings.HasSuffix(r, ".yaml"):
			files = append(files, filepath.Join(dir, r))
		default:
			s, f := policyResources(t, filepath.Join(dir, r))
			if set != "" && s != "" {
				t.Fatalf("%s pulls in two policy sets", path)
			}
			if s != "" {
				set = s
			}
			files = append(files, f...)
		}
	}
	return set, files
}

// galacticNADs names every NetworkAttachmentDefinition in dirs whose chain
// runs galactic-veth or galactic-tap.
func galacticNADs(t *testing.T, dirs ...string) []string {
	t.Helper()
	var files []string
	for _, dir := range dirs {
		f, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f...)
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
