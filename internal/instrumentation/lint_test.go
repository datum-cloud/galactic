// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package instrumentation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"

	// Every package that creates a metric through the library, so Lint sees
	// the ones a package creates when it loads; each command's scrape test
	// lints the ones created at startup. TestLintLinksEveryMetric keeps this
	// list complete.
	_ "go.datum.net/galactic/internal/edge/connectip"
	_ "go.datum.net/galactic/internal/edge/diag"
	_ "go.datum.net/galactic/internal/edge/masque"
	_ "go.datum.net/galactic/internal/fabric/gateway"
	_ "go.datum.net/galactic/internal/fabric/node"
	_ "go.datum.net/galactic/internal/fabricconfig"
	_ "go.datum.net/galactic/internal/gateway"
	_ "go.datum.net/galactic/internal/ingresssidecar"
	_ "go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	_ "go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	_ "go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	_ "go.datum.net/galactic/internal/plumbing/nldump"
	_ "go.datum.net/galactic/internal/runtime/gobgp"
	_ "go.datum.net/galactic/internal/serviceroute"
)

const (
	modulePath  = "go.datum.net/galactic"
	metricsPath = "go.miloapis.com/instrumentation/metrics"
)

// TestMetricsLint checks every metric created through the library against
// Prometheus naming conventions.
func TestMetricsLint(t *testing.T) {
	instrumenttest.Lint(t)
}

// TestLintLinksEveryMetric fails when a package creates a metric through the
// library but this package doesn't import it, so Lint would never see the
// metric. A command's own metrics can't be linked from here, so they belong
// in a package the command imports.
func TestLintLinksEveryMetric(t *testing.T) {
	linked := blankImports(t, "lint_test.go")
	fset := token.NewFileSet()
	walkSource(t, func(rel string, f *ast.File) {
		// metrics.MustRegister doesn't count: Lint checks only the metrics
		// the library's constructors create, never a custom collector.
		creates := slices.ContainsFunc(selectors(f, metricsPath), func(sel *ast.SelectorExpr) bool {
			return strings.HasPrefix(sel.Sel.Name, "New")
		})
		if !creates {
			return
		}
		pkg := path.Join(modulePath, filepath.ToSlash(filepath.Dir(rel)))
		switch {
		case f.Name.Name == "main":
			t.Errorf("%s creates a metric in package main, which Lint can't link; move it to a package the command imports", rel)
		case !linked[pkg]:
			t.Errorf("%s creates a metric, but lint_test.go doesn't import %s", rel, pkg)
		}
	}, fset)
}

// noMetricsEndpoint lists the commands that serve no metrics: the CNI
// plugins, exec'd once per call by the container runtime, the one-shot
// galactic-usid codec, and the masque-authority grant service.
var noMetricsEndpoint = []string{
	"galactic-bgp",
	"galactic-ipam",
	"galactic-route",
	"galactic-tap",
	"galactic-usid",
	"galactic-veth",
	"masque-authority",
}

// TestEveryBinaryHasScrapeTest fails when a command that serves metrics has
// no test calling instrumenttest.AssertScrapes on its handler, which is
// where a series exported by two registries shows up.
func TestEveryBinaryHasScrapeTest(t *testing.T) {
	root := filepath.Join(moduleRoot, "cmd")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		tests, err := filepath.Glob(filepath.Join(root, d.Name(), "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		scrapes := false
		for _, file := range tests {
			f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			scrapes = scrapes || slices.ContainsFunc(selectors(f, "go.miloapis.com/instrumentation/instrumenttest"),
				func(sel *ast.SelectorExpr) bool { return sel.Sel.Name == "AssertScrapes" })
		}
		exempt := slices.Contains(noMetricsEndpoint, d.Name())
		switch {
		case scrapes && exempt:
			t.Errorf("cmd/%s has a scrape test; remove it from noMetricsEndpoint", d.Name())
		case !scrapes && !exempt:
			t.Errorf("cmd/%s has no test calling instrumenttest.AssertScrapes on the handler it serves at /metrics", d.Name())
		}
	}
}

// blankImports returns the import paths file, in this package, imports as _.
func blankImports(t *testing.T, file string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Name != nil && imp.Name.Name == "_" {
			p, _ := strconv.Unquote(imp.Path.Value)
			out[p] = true
		}
	}
	return out
}
