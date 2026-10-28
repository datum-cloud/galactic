// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package instrumentation

import (
	"go/ast"
	"go/constant"
	"go/types"
	"path/filepath"
	"testing"

	"go.miloapis.com/instrumentation/labels"
	"golang.org/x/tools/go/packages"
)

// TestCustomCollectorLabels fails when a prometheus.NewDesc in the module
// names a label the collection pipeline reserves. The library's constructors
// refuse those names at startup, but a custom collector builds its own
// descriptors and registers them unchecked.
//
// Each descriptor's variable and constant label names must resolve statically:
// string constants, []string literals, prometheus.Labels literals, variables
// initialized once from those, append, and slices.Clone. A descriptor built
// any other way fails the test, since its names can't be checked. Conversions
// such as []string(nil) are followed too.
func TestCustomCollectorLabels(t *testing.T) {
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo,
		Dir: moduleRoot,
	}, modulePath+"/...")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("packages failed to load")
	}

	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	r := resolver{inits: map[types.Object]initializer{}, assigned: map[types.Object]int{}}
	for _, p := range pkgs {
		r.addInits(p)
	}
	r.dropReassigned()
	descs := 0
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isFunc(p.TypesInfo, call.Fun, promPath, "NewDesc") || len(call.Args) != 4 {
					return true
				}
				descs++
				pos := p.Fset.Position(call.Pos())
				if rel, err := filepath.Rel(root, pos.Filename); err == nil {
					pos.Filename = rel
				}
				variable, ok := r.strings(p.TypesInfo, call.Args[2])
				if !ok {
					t.Errorf("%s: can't resolve the descriptor's variable label names", pos)
				}
				constant, ok := r.labelKeys(p.TypesInfo, call.Args[3])
				if !ok {
					t.Errorf("%s: can't resolve the descriptor's constant label names", pos)
				}
				for _, l := range append(variable, constant...) {
					if description, reserved := labels.IsReserved(l); reserved {
						t.Errorf("%s: label %q is reserved for the collection pipeline (%s); "+
							"use a constant from go.miloapis.com/instrumentation/labels or a Galactic-specific name",
							pos, l, description)
					}
					if l == labels.BuildVersion || l == labels.InstrumentationVersion {
						t.Errorf("%s: label %q is set by the instrumentation library", pos, l)
					}
				}
				return true
			})
		}
	}
	if descs == 0 {
		t.Fatal("found no prometheus.NewDesc calls; the search is broken")
	}
}

// resolver evaluates label name expressions to their string values.
type resolver struct {
	// inits maps each variable assigned exactly once to its initializer.
	inits map[types.Object]initializer
	// assigned counts the writes to each variable.
	assigned map[types.Object]int
}

// initializer is a variable's initializing expression and the type
// information of the package declaring it.
type initializer struct {
	expr ast.Expr
	info *types.Info
}

// addInits records the initializer of every variable p declares with one
// value per name. A variable assigned again, in any package, or written
// through an element, a pointer or copy has no single initializer;
// dropReassigned removes it once every package is added.
func (r *resolver) addInits(p *packages.Package) {
	info := p.TypesInfo
	record := func(names []ast.Expr, values []ast.Expr) {
		for i, n := range names {
			obj, whole := assignedObject(info, n)
			if obj == nil {
				continue
			}
			if !whole {
				r.assigned[obj] += 2
				continue
			}
			r.assigned[obj]++
			if len(values) == len(names) {
				r.inits[obj] = initializer{values[i], info}
			}
		}
	}
	for _, f := range p.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(n.Names))
				for i, id := range n.Names {
					names[i] = id
				}
				record(names, n.Values)
			case *ast.AssignStmt:
				record(n.Lhs, n.Rhs)
			case *ast.CallExpr:
				if isBuiltin(info, n.Fun, "copy") && len(n.Args) == 2 {
					if obj, _ := assignedObject(info, n.Args[0]); obj != nil {
						r.assigned[obj] += 2
					}
				}
			}
			return true
		})
	}
}

// dropReassigned forgets the initializer of every variable assigned more
// than once.
func (r *resolver) dropReassigned() {
	for obj, n := range r.assigned {
		if n > 1 {
			delete(r.inits, obj)
		}
	}
}

// assignedObject returns the variable an assignment to e writes, and
// whether it replaces the whole variable rather than an element of it or
// what it points to.
func assignedObject(info *types.Info, e ast.Expr) (types.Object, bool) {
	whole := true
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.IndexExpr:
			e, whole = x.X, false
			continue
		case *ast.SliceExpr:
			e, whole = x.X, false
			continue
		case *ast.StarExpr:
			e, whole = x.X, false
			continue
		}
		break
	}
	obj, ok := objectOf(info, e).(*types.Var)
	if !ok {
		return nil, false
	}
	return obj, whole
}

// strings evaluates e, a []string expression or nil.
func (r *resolver) strings(info *types.Info, e ast.Expr) ([]string, bool) {
	e = ast.Unparen(e)
	if tv, ok := info.Types[e]; ok && tv.IsNil() {
		return nil, true
	}
	switch e := e.(type) {
	case *ast.CompositeLit:
		out := make([]string, 0, len(e.Elts))
		for _, elt := range e.Elts {
			s, ok := constString(info, elt)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case *ast.Ident, *ast.SelectorExpr:
		if init, ok := r.inits[objectOf(info, e)]; ok {
			return r.strings(init.info, init.expr)
		}
	case *ast.CallExpr:
		switch {
		case isBuiltin(info, e.Fun, "append") && len(e.Args) > 0:
			out, ok := r.strings(info, e.Args[0])
			if !ok {
				return nil, false
			}
			if e.Ellipsis.IsValid() {
				rest, ok := r.strings(info, e.Args[1])
				return append(out, rest...), ok
			}
			for _, a := range e.Args[1:] {
				s, ok := constString(info, a)
				if !ok {
					return nil, false
				}
				out = append(out, s)
			}
			return out, true
		case isFunc(info, e.Fun, "slices", "Clone") && len(e.Args) == 1,
			info.Types[e.Fun].IsType() && len(e.Args) == 1:
			return r.strings(info, e.Args[0])
		}
	}
	return nil, false
}

// labelKeys evaluates the keys of e, a prometheus.Labels expression or nil.
func (r *resolver) labelKeys(info *types.Info, e ast.Expr) ([]string, bool) {
	e = ast.Unparen(e)
	if tv, ok := info.Types[e]; ok && tv.IsNil() {
		return nil, true
	}
	switch e := e.(type) {
	case *ast.CompositeLit:
		var out []string
		for _, elt := range e.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return nil, false
			}
			s, ok := constString(info, kv.Key)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case *ast.Ident, *ast.SelectorExpr:
		if init, ok := r.inits[objectOf(info, e)]; ok {
			return r.labelKeys(init.info, init.expr)
		}
	}
	return nil, false
}

func constString(info *types.Info, e ast.Expr) (string, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

func objectOf(info *types.Info, e ast.Expr) types.Object {
	switch e := e.(type) {
	case *ast.Ident:
		return info.ObjectOf(e)
	case *ast.SelectorExpr:
		return info.ObjectOf(e.Sel)
	}
	return nil
}

// isFunc reports whether fun names the package-level function name in the
// package with import path pkg.
func isFunc(info *types.Info, fun ast.Expr, pkg, name string) bool {
	fn, ok := objectOf(info, ast.Unparen(fun)).(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == pkg && fn.Name() == name
}

func isBuiltin(info *types.Info, fun ast.Expr, name string) bool {
	b, ok := objectOf(info, ast.Unparen(fun)).(*types.Builtin)
	return ok && b.Name() == name
}
