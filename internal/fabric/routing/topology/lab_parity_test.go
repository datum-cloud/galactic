// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
)

// labResources is the containerlab lab's resources directory.
var labResources = filepath.Join("..", "..", "..", "..", "deploy", "containerlab", "resources")

// TestLabParity: for every lab cluster, the BGPPeers its FabricTopology
// generates from its FabricEndpoints replace every peer imported from the
// cluster's frr.conf files, and each router compiles to the configuration
// its imported peers compile to.
func TestLabParity(t *testing.T) {
	sites, err := filepath.Glob(filepath.Join(labResources, "fabric-router", "*", "frr.conf.*"))
	if err != nil {
		t.Fatal(err)
	}
	bySite := map[string][]string{}
	for _, conf := range sites {
		site := filepath.Base(filepath.Dir(conf))
		bySite[site] = append(bySite[site], conf)
	}
	if len(bySite) == 0 {
		t.Fatal("no lab frr.conf files")
	}
	for site, confs := range bySite {
		t.Run(site, func(t *testing.T) { checkSiteParity(t, site, confs) })
	}
}

func checkSiteParity(t *testing.T, site string, confs []string) {
	topo, endpoints := readFixtures(t, filepath.Join(labResources, "fabric-topology", site))
	inputs := map[string]compile.Input{}
	routers := map[string]*networkv1alpha1.BGPRouter{}
	for _, conf := range confs {
		node := strings.TrimPrefix(filepath.Base(conf), "frr.conf.")
		in := importRouter(t, conf, node)
		inputs[node] = in
		routers[node] = in.Router
	}
	states := Analyze(endpoints, map[string]bool{topo.Spec.Cell: true}, routers)
	for name, s := range states {
		if !s.Usable {
			t.Errorf("endpoint %s unusable: %s", name, s.ReadyMessage)
		}
	}
	plan, err := Generate(Input{Topology: topo, Endpoints: states, Routers: routers})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.MissingEndpoints) > 0 || len(plan.Overlaps) > 0 || len(plan.OverLimit) > 0 {
		t.Fatalf("missing %v, overlaps %v, over limit %v", plan.MissingEndpoints, plan.Overlaps, plan.OverLimit)
	}
	generated := map[string][]networkv1alpha1.BGPPeer{}
	for _, s := range plan.Sessions {
		generated[s.Peer.Spec.RouterRef.Name] = append(generated[s.Peer.Spec.RouterRef.Name], *s.Peer)
	}
	for node, in := range inputs {
		for _, p := range plan.Policies {
			if in.Policies[p] == nil && len(generatedFor(generated[node], p)) > 0 {
				t.Errorf("%s: generated peers reference policy %s the router does not have", node, p)
			}
		}
		if got, want := addresses(generated[node]), addresses(in.Peers); got != want {
			t.Errorf("%s: generated peers toward %s, imported toward %s", node, got, want)
		}
		imported, err := compile.Compile(in)
		if err != nil {
			t.Fatalf("%s: compile imported: %v", node, err)
		}
		in.Peers = generated[node]
		gen, err := compile.Compile(in)
		if err != nil {
			t.Fatalf("%s: compile generated: %v", node, err)
		}
		if diff := frrtext.Diff(frrtext.Normalize(imported.Config), frrtext.Normalize(gen.Config)); len(diff) > 0 {
			t.Errorf("%s: generated peers compile differently:\n%s", node, strings.Join(diff, "\n"))
		}
	}
}

// generatedFor are the peers in peers that reference policy.
func generatedFor(peers []networkv1alpha1.BGPPeer, policy string) []string {
	var out []string
	for _, p := range peers {
		for _, f := range p.Spec.FamilySettings {
			if (f.ImportPolicyRef != nil && f.ImportPolicyRef.Name == policy) ||
				(f.ExportPolicyRef != nil && f.ExportPolicyRef.Name == policy) {
				out = append(out, p.Name)
			}
		}
	}
	return out
}

func addresses(peers []networkv1alpha1.BGPPeer) string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.Spec.Address)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// importRouter imports one frr.conf as deploy-fabric-routing.sh does, and
// returns the router's compile input.
func importRouter(t *testing.T, path, node string) compile.Input {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	objs, err := frrimport.Import(f, frrimport.Options{Namespace: unitNS, NodeName: node, RouterClassName: "fabric-frr"})
	if err != nil {
		t.Fatalf("import %s: %v", path, err)
	}
	in, err := bundle.FromImport(objs, "fabric-frr").Input(node)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// readFixtures reads a site's FabricTopology and FabricEndpoints, with the
// defaults the API server would apply.
func readFixtures(t *testing.T, dir string) (*networkv1alpha1.FabricTopology, []networkv1alpha1.FabricEndpoint) {
	t.Helper()
	var topo *networkv1alpha1.FabricTopology
	var endpoints []networkv1alpha1.FabricEndpoint
	for _, file := range []string{"endpoints.yaml", "topology.yaml"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(data), "\n---\n") {
			var meta struct{ Kind string }
			if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
				t.Fatal(err)
			}
			switch meta.Kind {
			case "FabricEndpoint":
				ep := networkv1alpha1.FabricEndpoint{}
				if err := yaml.UnmarshalStrict([]byte(doc), &ep); err != nil {
					t.Fatal(err)
				}
				endpoints = append(endpoints, ep)
			case "FabricTopology":
				topo = &networkv1alpha1.FabricTopology{}
				if err := yaml.UnmarshalStrict([]byte(doc), topo); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("%s: unexpected kind %q", file, meta.Kind)
			}
		}
	}
	if topo == nil || len(endpoints) == 0 {
		t.Fatalf("%s: no topology or no endpoints", dir)
	}
	if topo.Spec.MaxSessionsPerRouter == 0 {
		topo.Spec.MaxSessionsPerRouter = 64
	}
	return topo, endpoints
}
