// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

// TestPreviewRevision: preview --revision prints a stored revision's
// frr.conf, and refuses a revision whose content no longer matches its
// digests.
func TestPreviewRevision(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "internal", "fabric", "routing", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	o, err := frrimport.Import(f, frrimport.Options{
		Namespace: "galactic-system", NodeName: "edge-a", RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := bundle.FromImport(o, "fabric-frr").Input("edge-a")
	if err != nil {
		t.Fatal(err)
	}
	rev, want, err := revision.Build(in, "node-uid")
	if err != nil {
		t.Fatal(err)
	}
	rev.APIVersion, rev.Kind = networkv1alpha1.GroupVersion.String(), "FabricRouterRevision"

	write := func(r *networkv1alpha1.FabricRouterRevision) string {
		data, err := yaml.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "revision.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	preview := func(args ...string) (string, error) {
		cmd := newRootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append([]string{"preview"}, args...))
		err := cmd.Execute()
		return out.String(), err
	}

	got, err := preview("--revision", write(rev))
	if err != nil || got != want.Config {
		t.Fatalf("preview --revision = %v, output matches: %t", err, got == want.Config)
	}

	tampered := rev.DeepCopy()
	tampered.Spec.RenderedDigest = "0000"
	if _, err := preview("--revision", write(tampered)); err == nil {
		t.Error("previewed a revision whose rendered digest does not match")
	}
	for _, args := range [][]string{
		{"--revision", write(rev), "--router", "edge-a"},
		{"resources.yaml"},
		{},
	} {
		if _, err := preview(args...); err == nil {
			t.Errorf("preview %v ran", args)
		}
	}
}
