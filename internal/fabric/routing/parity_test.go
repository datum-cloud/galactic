// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package routing_test checks that importing a rendered fabric frr.conf and
// compiling the result reproduces it.
package routing_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
)

// parityEnv names a directory of real rendered configurations, laid out as
// <cluster>/<node>.conf. This repository is public, so production files are
// never checked in; the CI that holds them sets the variable.
const parityEnv = "FABRIC_PARITY_DIR"

// fabricClass names the class and parameters every imported router uses.
const fabricClass = "fabric-frr"

// parityOutEnv, when set, receives each compiled configuration as
// <dir>/<node>.conf, for the frr-reload check in the frr-tagged test.
const parityOutEnv = "FABRIC_PARITY_OUT"

// TestImportCompileParity: every configuration compiles back, through the
// typed resources, to a configuration FRR treats as identical.
func TestImportCompileParity(t *testing.T) {
	for _, f := range parityFiles(t) {
		t.Run(f.key, func(t *testing.T) {
			original, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			res := compileFile(t, f.path, string(original))
			if out := os.Getenv(parityOutEnv); out != "" {
				if err := os.WriteFile(filepath.Join(out, f.key+".conf"), []byte(res.Config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if diff := frrtext.Diff(frrtext.Normalize(string(original)), frrtext.Normalize(res.Config)); len(diff) > 0 {
				t.Errorf("compiled configuration differs from %s:\n%s", f.path, strings.Join(diff, "\n"))
			}
		})
	}
}

// parityFile is one configuration to check, keyed uniquely across clusters.
type parityFile struct{ key, path string }

// parityFiles is the synthetic fixtures plus, when parityEnv is set, every
// <cluster>/<node>.conf below it.
func parityFiles(t *testing.T) []parityFile {
	t.Helper()
	var files []parityFile
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range fixtures {
		files = append(files, parityFile{key: strings.TrimSuffix(filepath.Base(p), ".conf"), path: p})
	}
	if len(files) == 0 {
		t.Fatal("no synthetic fixtures")
	}
	if dir := os.Getenv(parityEnv); dir != "" {
		real, err := filepath.Glob(filepath.Join(dir, "*", "*.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if len(real) == 0 {
			t.Fatalf("%s=%s holds no <cluster>/<node>.conf files", parityEnv, dir)
		}
		for _, p := range real {
			cluster := filepath.Base(filepath.Dir(p))
			files = append(files, parityFile{key: cluster + "_" + strings.TrimSuffix(filepath.Base(p), ".conf"), path: p})
		}
	}
	return files
}

// compileFile imports one rendered configuration, writes the objects as
// YAML, reads them back, and compiles the result, so the parity check also
// covers serialization.
func compileFile(t *testing.T, path, text string) compile.Result {
	t.Helper()
	node := strings.TrimSuffix(filepath.Base(path), ".conf")
	objs, err := frrimport.Import(strings.NewReader(text), frrimport.Options{
		Namespace: "galactic-system", NodeName: node, RouterClassName: fabricClass,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	var buf bytes.Buffer
	if err := bundle.FromImport(objs, fabricClass).Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := bundle.Read(&buf)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	in, err := b.Input(node)
	if err != nil {
		t.Fatal(err)
	}
	res, err := compile.Compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return res
}
