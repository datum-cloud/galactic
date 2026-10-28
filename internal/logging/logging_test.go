// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

// emitEnv makes the test binary run emitLines instead of its tests.
// controller-runtime keeps the first logger it is given, so the lines are
// written by a fresh process each time, whatever -count or -shuffle says.
const emitEnv = "GALACTIC_LOGGING_TEST_EMIT"

func TestMain(m *testing.M) {
	if os.Getenv(emitEnv) != "" {
		emitLines()
		return
	}
	os.Exit(m.Run())
}

// emitLines installs the production logger on stdout and writes one line
// through each logger Setup covers.
func emitLines() {
	if err := Setup(os.Stdout, "info", FormatJSON); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	slog.Info("from slog", "k", "v")
	ctrl.Log.WithName("controller-runtime").Info("from controller-runtime", "k", "v")
	ctrl.Log.V(1).Info("controller-runtime debug")
	ctrl.Log.Error(errors.New("boom"), "from controller-runtime error")
	log.Print("from the log package")
	klog.InfoS("from klog", "k", "v")
	klog.Flush()
}

func TestSetupRoutesEveryLoggerThroughOneJSONHandler(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = append(os.Environ(), emitEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("emitting process: %v", err)
	}
	buf := bytes.NewBuffer(out)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	info, errLevel := slog.LevelInfo.String(), slog.LevelError.String()
	want := []struct{ msg, level string }{
		{"from slog", info},
		{"from controller-runtime", info},
		{"from controller-runtime error", errLevel},
		{"from the log package", info},
		{"from klog", info},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d (V(1) must be dropped at info):\n%s", len(lines), len(want), buf.String())
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		for _, key := range []string{slog.TimeKey, slog.LevelKey, slog.MessageKey} {
			if _, ok := rec[key]; !ok {
				t.Errorf("line %d has no %q field: %s", i, key, line)
			}
		}
		if rec[slog.MessageKey] != want[i].msg || rec[slog.LevelKey] != want[i].level {
			t.Errorf("line %d = %s %q, want %s %q", i, rec[slog.LevelKey], rec[slog.MessageKey], want[i].level, want[i].msg)
		}
	}
}

func TestSetupDebugTextShowsVerboseLines(t *testing.T) {
	t.Cleanup(restoreDefaults(t))
	var buf bytes.Buffer
	if err := Setup(&buf, "debug", FormatText); err != nil {
		t.Fatal(err)
	}

	// controller-runtime keeps the first logger it is given, so this checks
	// the installed handler through the same slog-to-logr bridge.
	logr.FromSlogHandler(slog.Default().Handler()).V(1).Info("controller-runtime debug")
	if got := buf.String(); !strings.Contains(got, `msg="controller-runtime debug"`) {
		t.Errorf("debug text output missing the V(1) line: %q", got)
	}
}

func TestSetupRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct{ level, format string }{
		{"loud", FormatJSON},
		{"info", "console"},
	} {
		if err := Setup(&bytes.Buffer{}, tc.level, tc.format); err == nil {
			t.Errorf("Setup(%q, %q) succeeded, want an error", tc.level, tc.format)
		}
	}
}

func TestValidateMatchesSetup(t *testing.T) {
	for _, level := range append(slices.Clone(Levels), "INFO", "info+2") {
		if err := ValidateLevel(level); err != nil {
			t.Errorf("ValidateLevel(%q) = %v, want nil", level, err)
		}
	}
	for _, format := range Formats {
		if err := ValidateFormat(format); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", format, err)
		}
	}
	for _, level := range []string{"loud", "verbose", "", "trace"} {
		if ValidateLevel(level) == nil {
			t.Errorf("ValidateLevel(%q) = nil, want an error", level)
		}
	}
	for _, format := range []string{"console", "JSON", ""} {
		if ValidateFormat(format) == nil {
			t.Errorf("ValidateFormat(%q) = nil, want an error", format)
		}
	}
}

// TestBinariesListsEveryCaller keeps Binaries, which the manifest check uses
// to find Galactic containers, in step with the commands that import this
// package.
func TestBinariesListsEveryCaller(t *testing.T) {
	const self = "go.datum.net/galactic/internal/logging"
	root := filepath.Join("..", "..", "cmd")
	callers := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				rel, _ := filepath.Rel(root, path)
				callers[strings.Split(filepath.ToSlash(rel), "/")[0]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(callers))
	want := slices.Sorted(slices.Values(Binaries))
	if !slices.Equal(got, want) {
		t.Errorf("commands importing %s = %v, Binaries = %v", self, got, want)
	}
}

// TestBinariesUseThisPackage fails when a command builds controller-runtime's
// logger itself, such as a zap logger in development mode, instead of through
// Setup.
func TestBinariesUseThisPackage(t *testing.T) {
	root := filepath.Join("..", "..", "cmd")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "sigs.k8s.io/controller-runtime/pkg/log/zap" {
				t.Errorf("%s imports %s; call logging.Setup instead", fset.Position(imp.Pos()), p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetLogger" {
				t.Errorf("%s calls SetLogger; call logging.Setup instead", fset.Position(sel.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// unmanagedBinaries are the commands under cmd/ that don't install the shared
// handler. The CNI plugins are exec'd per call by the container runtime, and
// galactic-usid is a one-shot codec command.
var unmanagedBinaries = map[string]bool{
	"galactic-bgp":   true,
	"galactic-ipam":  true,
	"galactic-route": true,
	"galactic-tap":   true,
	"galactic-veth":  true,
	"galactic-usid":  true,
}

// TestLongRunningBinariesInstallTheHandler fails when a command under cmd/
// doesn't import this package, so a new long-running binary can't log through
// slog's unconfigured default. A binary that needs no shared handler is added
// to unmanagedBinaries with the reason.
func TestLongRunningBinariesInstallTheHandler(t *testing.T) {
	const pkg = "go.datum.net/galactic/internal/logging"
	root := filepath.Join("..", "..", "cmd")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := filepath.Glob(filepath.Join(root, d.Name(), "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		uses := false
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				if path, _ := strconv.Unquote(imp.Path.Value); path == pkg {
					uses = true
				}
			}
		}
		switch {
		case uses && unmanagedBinaries[d.Name()]:
			t.Errorf("cmd/%s imports %s; remove it from unmanagedBinaries", d.Name(), pkg)
		case !uses && !unmanagedBinaries[d.Name()]:
			t.Errorf("cmd/%s doesn't import %s; call logging.Setup from its root command", d.Name(), pkg)
		}
	}
}

// restoreDefaults returns a function that puts slog's default logger back, so
// one test's handler doesn't receive another package's output.
func restoreDefaults(t *testing.T) func() {
	t.Helper()
	prev := slog.Default()
	return func() {
		slog.SetDefault(prev)
		klog.ClearLogger()
	}
}
