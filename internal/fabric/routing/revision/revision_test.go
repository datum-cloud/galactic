// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package revision

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

// configs is the synthetic fixtures plus, when FABRIC_PARITY_DIR is set,
// every <cluster>/<node>.conf below it.
func configs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "testdata", "*.conf"))
	if err != nil || len(files) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	if dir := os.Getenv("FABRIC_PARITY_DIR"); dir != "" {
		real, _ := filepath.Glob(filepath.Join(dir, "*", "*.conf"))
		files = append(files, real...)
	}
	return files
}

func input(t *testing.T, path string) compile.Input {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	node := strings.TrimSuffix(filepath.Base(path), ".conf")
	o, err := frrimport.Import(strings.NewReader(string(text)), frrimport.Options{
		Namespace: "galactic-system", NodeName: node, RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Router.UID = types.UID("router-" + node)
	in, err := bundle.FromImport(o, "fabric-frr").Input(node)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TestBuildVerify: every revision recompiles, from its own content alone,
// to the frr.conf it records, and stays far under the size cap.
func TestBuildVerify(t *testing.T) {
	for _, path := range configs(t) {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			rev, built, err := Build(input(t, path), "node-uid")
			if err != nil {
				t.Fatal(err)
			}
			res, err := Verify(rev)
			if err != nil {
				t.Fatal(err)
			}
			if res.Config != built.Config {
				t.Error("the revision recompiles to different text")
			}
			data, err := json.Marshal(rev)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > MaxBytes/4 {
				t.Errorf("revision is %d bytes, over a quarter of the cap", len(data))
			}
		})
	}
}

// Pinned digests of the synthetic edge router; see TestGoldenDigests.
const (
	goldenSemantics = "3c1aa5c0313416989cdb5227d8fec924080a6d7835bbef6e78c9b642a74fe2c8"
	goldenRendered  = "cc6107edc09c5f6b3152221c205da16de49b699c4c9603fac359d2494a4b67e0"
)

const (
	kindDependency = "dependency"
	kindSemantics  = "semantics"
	unrelated      = "unrelated"
)

// TestRevisionIdentity: identical inputs name the same revision; any change
// to the configuration, the target or the parameters names a new one.
func TestRevisionIdentity(t *testing.T) {
	path := filepath.Join("..", "testdata", "edge-a.conf")
	first, _, err := Build(input(t, path), "node-uid")
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := Build(input(t, path), "node-uid")
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != again.Name || first.Spec.ActivationDependencyDigest != again.Spec.ActivationDependencyDigest {
		t.Fatalf("identical inputs named %s and %s", first.Name, again.Name)
	}
	if !regexp.MustCompile(`^edge-a-[0-9a-f]{10}$`).MatchString(first.Name) {
		t.Errorf("revision name %q", first.Name)
	}

	for name, change := range map[string]func(*compile.Input) string{
		"policy term": func(in *compile.Input) string {
			in.Policies["originate"].Spec.Terms[0].Description = "changed"
			return kindSemantics
		},
		"router ID":     func(in *compile.Input) string { in.Router.Spec.RouterID = "192.0.2.99"; return kindSemantics },
		"node replaced": func(*compile.Input) string { return kindDependency },
		"router recreated": func(in *compile.Input) string {
			in.Router.UID = "recreated"
			return kindDependency
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := input(t, path)
			kind := change(&in)
			nodeUID := "node-uid"
			if name == "node replaced" {
				nodeUID = "new-node-uid"
			}
			rev, _, err := Build(in, nodeUID)
			if err != nil {
				t.Fatal(err)
			}
			if rev.Name == first.Name {
				t.Error("a changed input kept the revision name")
			}
			if kind == kindDependency && rev.Spec.SemanticsDigest != first.Spec.SemanticsDigest {
				t.Error("an identity change altered the configuration digest")
			}
		})
	}
}

// TestRevisionHoldsOnlyRenderedDefinitions: definitions in the namespace
// that the router neither references nor retains stay out of its revision.
func TestRevisionHoldsOnlyRenderedDefinitions(t *testing.T) {
	in := input(t, filepath.Join("..", "testdata", "reflector-a.conf"))
	extra := *in.Policies["allow"].DeepCopy()
	extra.Name = unrelated
	in.Policies[unrelated] = &extra
	rev, _, err := Build(in, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rev.Spec.Configuration.Policies {
		if p.Name == unrelated {
			t.Error("an unreferenced policy entered the revision")
		}
	}
	for _, i := range rev.Spec.Inputs {
		if i.Name == unrelated {
			t.Error("an unreferenced policy is listed as an input")
		}
	}
}

// TestVerifyRefusesTampering: a revision whose configuration no longer
// matches its digests is refused.
func TestVerifyRefusesTampering(t *testing.T) {
	rev, _, err := Build(input(t, filepath.Join("..", "testdata", "edge-a.conf")), "")
	if err != nil {
		t.Fatal(err)
	}
	rev.Spec.Configuration.Router.RouterID = "192.0.2.250"
	if _, err := Verify(rev); err == nil {
		t.Error("a tampered configuration verified")
	}
	rev, _, _ = Build(input(t, filepath.Join("..", "testdata", "edge-a.conf")), "")
	rev.Spec.RenderedDigest = strings.Repeat("0", 64)
	if _, err := Verify(rev); err == nil {
		t.Error("a wrong rendered digest verified")
	}
}

// TestFRRVersionMatchesImage: revisions name the FRR build fabric-router
// actually runs.
func TestFRRVersionMatchesImage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "containers", "fabric-router", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ARG FRR_VERSION=(\S+)$`).FindSubmatch(data)
	if m == nil || string(m[1]) != compile.FRRVersion {
		t.Errorf("compile.FRRVersion = %s, Dockerfile pins %s", compile.FRRVersion, m)
	}
}

// TestGoldenDigests pins the digests of the synthetic edge router. A change
// to the API types or the compiler that alters them must bump
// compile.SemanticsVersion and update these values deliberately.
func TestGoldenDigests(t *testing.T) {
	rev, _, err := Build(input(t, filepath.Join("..", "testdata", "edge-a.conf")), "node-uid")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("semantics %s rendered %s", rev.Spec.SemanticsDigest, rev.Spec.RenderedDigest)
	if rev.Spec.SemanticsDigest != goldenSemantics || rev.Spec.RenderedDigest != goldenRendered {
		t.Errorf("edge-a digests changed:\n semantics %s, pinned %s\n rendered  %s, pinned %s\n"+
			"bump compile.SemanticsVersion and update the pinned values if the change is intended",
			rev.Spec.SemanticsDigest, goldenSemantics, rev.Spec.RenderedDigest, goldenRendered)
	}
}

// TestDigestIgnoresEncodingDetails: empty lists, empty objects and nulls,
// and the order fields are written in, do not change a digest; a pointer to
// zero still differs from an unset one.
func TestDigestIgnoresEncodingDetails(t *testing.T) {
	type a struct {
		X int      `json:"x"`
		Y []string `json:"y"`
		Z *int     `json:"z"`
	}
	type b struct {
		Y []string          `json:"y,omitempty"`
		X int               `json:"x"`
		W map[string]string `json:"w"`
	}
	da, _ := digest(a{X: 1, Y: []string{}})
	db, _ := digest(b{X: 1})
	if da != db {
		t.Error("encoding details changed the digest")
	}
	zero := 0
	dz, _ := digest(a{X: 1, Z: &zero})
	if dz == da {
		t.Error("a pointer to zero digests like an unset pointer")
	}
}

func TestVerifyRefusesOtherCompiler(t *testing.T) {
	rev, _, err := Build(input(t, filepath.Join("..", "testdata", "edge-a.conf")), "")
	if err != nil {
		t.Fatal(err)
	}
	rev.Spec.Compiler.SemanticsVersion = "0"
	if _, err := Verify(rev); !errors.Is(err, ErrIncompatible) {
		t.Errorf("Verify = %v, want ErrIncompatible", err)
	}
}
