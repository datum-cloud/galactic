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
	"time"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"go.datum.net/galactic/internal/metadata"
)

// emitEnv makes the test binary run emitLines at the level it names instead
// of its tests. controller-runtime keeps the first logger it is given, so the
// lines are written by a fresh process each time, whatever -count or -shuffle
// says.
const emitEnv = "GALACTIC_LOGGING_TEST_EMIT"

func TestMain(m *testing.M) {
	if level := os.Getenv(emitEnv); level != "" {
		emitLines(level)
		return
	}
	os.Exit(m.Run())
}

// emitLines installs the logger at level on stdout and writes lines through
// each logger Setup covers.
func emitLines(level string) {
	o := Options{Level: level}
	if err := o.setup(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	slog.Debug("slog debug")
	slog.Info("from slog", "k", "v")
	ctrl.Log.WithName("controller-runtime").Info("from controller-runtime", "k", "v")
	ctrl.Log.V(1).Info("controller-runtime debug")
	ctrl.Log.Error(errors.New("boom"), "from controller-runtime error")
	log.Print("from the log package")
	klog.InfoS("from klog", "k", "v")
	klog.Flush()
}

// emitted runs emitLines at level in a fresh process and returns its lines,
// each parsed as JSON.
func emitted(t *testing.T, level string) []map[string]any {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = append(os.Environ(), emitEnv+"="+level)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("emitting process: %v", err)
	}
	split := strings.Split(strings.TrimSpace(string(out)), "\n")
	recs := make([]map[string]any, 0, len(split))
	for i, line := range split {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		recs = append(recs, rec)
	}
	return recs
}

// The level names a line carries, which are also the --log-level values.
const (
	lvDebug = "debug"
	lvInfo  = "info"
	lvWarn  = "warn"
	lvError = "error"
)

type line struct{ msg, level string }

func lines(recs []map[string]any) []line {
	out := make([]line, 0, len(recs))
	for _, rec := range recs {
		msg, _ := rec["msg"].(string)
		level, _ := rec["level"].(string)
		out = append(out, line{msg, level})
	}
	return out
}

func TestSetupRoutesEveryLoggerThroughTheLibrary(t *testing.T) {
	recs := emitted(t, lvInfo)

	want := []line{
		{"from slog", lvInfo},
		{"from controller-runtime", lvInfo},
		{"from controller-runtime error", lvError},
		{"from the log package", lvInfo},
		{"from klog", lvInfo},
	}
	if got := lines(recs); !slices.Equal(got, want) {
		t.Fatalf("lines = %v, want %v (debug lines must be dropped at info)", got, want)
	}
	for i, rec := range recs {
		if rec["build_version"] != metadata.Version {
			t.Errorf("line %d build_version = %v, want %q", i, rec["build_version"], metadata.Version)
		}
		if v, _ := rec["instrumentation_version"].(string); v == "" {
			t.Errorf("line %d has no instrumentation_version", i)
		}
		ts, _ := rec["ts"].(string)
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil || !strings.HasSuffix(ts, "Z") {
			t.Errorf("line %d ts = %q, want an RFC 3339 UTC timestamp", i, ts)
		}
	}
	if _, ok := recs[2]["stacktrace"]; !ok {
		t.Error("error line has no stacktrace")
	}
}

func TestSetupDebugShowsVerboseLinesAsDebug(t *testing.T) {
	want := []line{
		{"slog debug", lvDebug},
		{"from slog", lvInfo},
		{"from controller-runtime", lvInfo},
		{"controller-runtime debug", lvDebug},
		{"from controller-runtime error", lvError},
		{"from the log package", lvInfo},
		{"from klog", lvInfo},
	}
	if got := lines(emitted(t, lvDebug)); !slices.Equal(got, want) {
		t.Errorf("lines = %v, want %v", got, want)
	}
}

func TestSetupLevels(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{nil, []string{lvInfo, lvWarn, lvError}},
		{[]string{"--log-level=warn"}, []string{lvWarn, lvError}},
		{[]string{"--log-level=ERROR"}, []string{lvError}},
		{[]string{"--log-level=debug", "--zap-log-level=error"}, []string{lvError}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Cleanup(restoreDefaults(t))
			t.Setenv(EnvLevel, "")
			var o Options
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			o.BindFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := o.setup(&buf); err != nil {
				t.Fatal(err)
			}
			slog.Debug(lvDebug)
			slog.Info(lvInfo)
			slog.Warn(lvWarn)
			slog.Error(lvError)

			split := strings.Split(strings.TrimSpace(buf.String()), "\n")
			got := make([]string, 0, len(split))
			for _, l := range split {
				var rec map[string]any
				if err := json.Unmarshal([]byte(l), &rec); err != nil {
					t.Fatalf("line is not JSON: %v\n%s", err, l)
				}
				got = append(got, rec["msg"].(string))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("lines = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetupFileWritesJSON(t *testing.T) {
	t.Cleanup(restoreDefaults(t))
	var buf bytes.Buffer
	SetupFile(&buf, slog.LevelWarn)
	slog.Info("dropped")
	slog.Warn("kept", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not one JSON line: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "kept" || rec["level"] != lvWarn || rec["build_version"] != metadata.Version {
		t.Errorf("line = %v, want kept at warn with build_version %q", rec, metadata.Version)
	}
}

func TestSetupRejectsInvalidLevel(t *testing.T) {
	o := Options{Level: "loud"}
	if err := o.setup(&bytes.Buffer{}); err == nil {
		t.Error("setup with --log-level=loud succeeded, want an error")
	}
}

func TestValidateLevel(t *testing.T) {
	for _, level := range append(slices.Clone(Levels), "INFO", "info+2") {
		if err := ValidateLevel(level); err != nil {
			t.Errorf("ValidateLevel(%q) = %v, want nil", level, err)
		}
	}
	for _, level := range []string{"loud", "verbose", "", "trace"} {
		if ValidateLevel(level) == nil {
			t.Errorf("ValidateLevel(%q) = nil, want an error", level)
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
			t.Errorf("cmd/%s doesn't import %s; call Options.Setup from its root command", d.Name(), pkg)
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
