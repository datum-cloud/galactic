// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package instrumentation

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
)

// moduleRoot is the repository root, relative to this package.
const moduleRoot = "../.."

// pending lists the directories, relative to the module root, that still
// create or register metrics outside the instrumentation library. Both
// adoption checks skip them. Remove a directory once it has moved; the
// checks then fail on anything left behind.
var pending = []string{
	// #1149: serve controller-runtime's registry through library metrics.
	"cmd/fabric-api",
	"cmd/fabric-router-controller",
	"cmd/galactic-controller",
	"cmd/galactic-edge",
	"cmd/galactic-vrf",
	// #1149: create metrics with the library's constructors instead of a
	// registry parameter or a private registry.
	"internal/edge/diag",
	"internal/fabric/gateway",
	"internal/fabric/node",
	"internal/fabricconfig",
	"internal/ingresssidecar",
}

// TestAdopted runs the instrumentation library's adoption check over the
// module: nothing registers a metric outside the library, and every logger
// is built by it.
func TestAdopted(t *testing.T) {
	instrumenttest.AssertAdopted(t, instrumenttest.SkipDir(pending...))
}

const promPath = "github.com/prometheus/client_golang/prometheus"

// outsideLibrary names the prometheus identifiers that create a metric or
// a registry to register one on. The library's check only sees registration
// through package-level functions, so a metric built with these and
// registered on a prometheus.Registerer parameter would pass it. Custom
// collectors remain allowed: prometheus.NewDesc is not listed, and the only
// registry left to register them on is the library's.
var outsideLibrary = []string{
	"NewCounter", "NewCounterVec", "NewCounterFunc",
	"NewGauge", "NewGaugeVec", "NewGaugeFunc",
	"NewHistogram", "NewHistogramVec",
	"NewSummary", "NewSummaryVec",
	"NewUntypedFunc",
	"NewRegistry", "NewPedanticRegistry",
	"Registerer", "Registry",
	"WrapRegistererWith", "WrapRegistererWithPrefix",
}

// TestNoMetricsOutsideLibrary fails wherever the module's non-test source
// outside pending creates a metric or a registry with prometheus directly.
func TestNoMetricsOutsideLibrary(t *testing.T) {
	skip := map[string]bool{}
	for _, d := range pending {
		if _, err := os.Stat(filepath.Join(moduleRoot, d)); err != nil {
			t.Errorf("pending directory %s: %v", d, err)
		}
		skip[d] = true
	}
	fset := token.NewFileSet()
	walkSource(t, func(rel string, f *ast.File) {
		if skip[filepath.ToSlash(filepath.Dir(rel))] || underAny(rel, skip) {
			return
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == promPath && imp.Name != nil && imp.Name.Name == "." {
				t.Errorf("%s:%d: dot import of %s hides its constructors from this check",
					rel, fset.Position(imp.Pos()).Line, promPath)
			}
		}
		for _, sel := range selectors(f, promPath) {
			if slices.Contains(outsideLibrary, sel.Sel.Name) {
				t.Errorf("%s:%d: prometheus.%s creates a metric or registry outside %s; "+
					"use its constructors, or metrics.MustRegister for a custom collector",
					rel, fset.Position(sel.Pos()).Line, sel.Sel.Name, metricsPath)
			}
		}
	}, fset)
}

// underAny reports whether rel lies under one of dirs.
func underAny(rel string, dirs map[string]bool) bool {
	rel = filepath.ToSlash(rel)
	for d := range dirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// walkSource parses every non-test Go file in the module, skipping nested
// modules, testdata, hidden directories and files built only with the ignore
// tag, and passes each to fn with its path relative to the module root.
func walkSource(t *testing.T, fn func(rel string, f *ast.File), fset *token.FileSet) {
	t.Helper()
	err := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == moduleRoot {
				return nil
			}
			name := d.Name()
			// Hidden directories include .worktrees, which holds other
			// checkouts of this module.
			if strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if ignored(f) {
			return nil
		}
		rel, err := filepath.Rel(moduleRoot, path)
		if err != nil {
			return err
		}
		fn(rel, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ignored reports whether f is built only with the ignore tag.
func ignored(f *ast.File) bool {
	for _, g := range f.Comments {
		if g.Pos() >= f.Package {
			break
		}
		for _, c := range g.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err == nil && !expr.Eval(func(tag string) bool { return tag != "ignore" }) {
				return true
			}
		}
	}
	return false
}

// selectors returns every pkg.Name expression in f where pkg is the name f
// imports path under.
func selectors(f *ast.File, path string) []*ast.SelectorExpr {
	var names []string
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p != path {
			continue
		}
		switch {
		case imp.Name == nil:
			names = append(names, path[strings.LastIndex(path, "/")+1:])
		case imp.Name.Name != "_" && imp.Name.Name != ".":
			names = append(names, imp.Name.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	var out []*ast.SelectorExpr
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && slices.Contains(names, id.Name) {
				out = append(out, sel)
			}
		}
		return true
	})
	return out
}
