// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command check-log-settings fails when a manifest gives a Galactic container
// a LOG_LEVEL or --log-level value that internal/logging rejects, or the
// removed --log-format flag, either of which would stop the binary at startup.
// It also fails on the removed LOG_FORMAT variable, which no binary reads, and
// on --zap-devel, the local-only console format.
//
// It reads YAML streams from the named files, or from stdin for "-": rendered
// kustomize output, or source YAML such as a patch file or a kustomization
// with inline patches. A container is a Galactic one when its image
// repository, or, in a patch without an image, its name, is one of
// logging.Binaries, or when its command runs one of them, directly or from a
// shell script. Only literal values are checked; one taken from a
// ConfigMap, a Secret or a $(VAR) reference is not.
//
//	kustomize build config/galactic-router/overlays/router | check-log-settings -label galactic-router -
//	check-log-settings deploy/containerlab/resources/fabric-router/base/fabric-lab-patch.yaml
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"go.datum.net/galactic/internal/logging"
)

func main() {
	label := flag.String("label", "stdin", "name to report for input read from stdin")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: check-log-settings [-label NAME] FILE... (- for stdin)")
		os.Exit(2)
	}
	failed := false
	for _, name := range flag.Args() {
		source := name
		if name == "-" {
			source = *label
		}
		findings, err := checkFile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", source, err)
			os.Exit(2)
		}
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "%s: %s\n", source, f)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func checkFile(name string) ([]string, error) {
	if name == "-" {
		return check(os.Stdin)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return check(f)
}

// check returns one finding per unsupported value in the YAML stream r.
func check(r io.Reader) ([]string, error) {
	docs, err := decode(r)
	if err != nil {
		return nil, err
	}
	var findings []string
	for _, doc := range docs {
		findings = append(findings, checkDoc(doc)...)
	}
	// Maps are walked in random order; sort for stable output.
	slices.Sort(findings)
	return findings, nil
}

func decode(r io.Reader) ([]any, error) {
	yr := utilyaml.NewYAMLReader(bufio.NewReader(r))
	var docs []any
	for {
		raw, err := yr.Read()
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}

// checkDoc checks every container in doc and in the inline patches doc
// carries if it is a kustomization.
func checkDoc(doc any) []string {
	where := ""
	if m, ok := doc.(map[string]any); ok {
		kind, _ := m["kind"].(string)
		meta, _ := m["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		where = strings.TrimSpace(kind + " " + name)
	}
	var findings []string
	walk(doc, func(c map[string]any) {
		for _, f := range checkContainer(c) {
			if where != "" {
				f = where + ": " + f
			}
			findings = append(findings, f)
		}
	})
	for _, patch := range inlinePatches(doc) {
		docs, err := decode(strings.NewReader(patch))
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: inline patch: %v", where, err))
			continue
		}
		for _, d := range docs {
			for _, f := range checkDoc(d) {
				findings = append(findings, "inline patch: "+f)
			}
		}
	}
	return findings
}

// walk calls fn for every container, init container and ephemeral container
// under n.
func walk(n any, fn func(map[string]any)) {
	switch v := n.(type) {
	case map[string]any:
		for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
			list, _ := v[key].([]any)
			for _, c := range list {
				if c, ok := c.(map[string]any); ok {
					fn(c)
				}
			}
		}
		for _, child := range v {
			walk(child, fn)
		}
	case []any:
		for _, child := range v {
			walk(child, fn)
		}
	}
}

// inlinePatches returns the strategic-merge patches a kustomization holds as
// strings. JSON 6902 patches name no container, so they are checked only in
// rendered output, never in an overlay that isn't rendered.
func inlinePatches(doc any) []string {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	var patches []string
	if list, ok := m["patches"].([]any); ok {
		for _, p := range list {
			if p, ok := p.(map[string]any); ok {
				if s, ok := p["patch"].(string); ok {
					patches = append(patches, s)
				}
			}
		}
	}
	if list, ok := m["patchesStrategicMerge"].([]any); ok {
		for _, p := range list {
			if s, ok := p.(string); ok && strings.Contains(s, "\n") {
				patches = append(patches, s)
			}
		}
	}
	return patches
}

// envFormat is the variable that chose JSON or text output before the
// binaries moved to the instrumentation library's logger.
const envFormat = "LOG_FORMAT"

var (
	errFormatRemoved = errors.New(
		"removed: production output is always JSON; use --zap-devel for console output in local runs")
	errDevel = errors.New("console output at debug level is for local runs only")
)

func checkContainer(c map[string]any) []string {
	name, _ := c["name"].(string)
	image, _ := c["image"].(string)
	command, _ := c["command"].([]any)
	if !isGalactic(name, image) && !runsGalactic(command) {
		return nil
	}
	var findings []string
	report := func(setting, value string, err error) {
		findings = append(findings, fmt.Sprintf("container %s: %s %q: %v", name, setting, value, err))
	}
	env, _ := c["env"].([]any)
	for _, e := range env {
		e, _ := e.(map[string]any)
		key, _ := e["name"].(string)
		value, ok := e["value"].(string)
		// The binary treats an empty variable as unset.
		if !ok || value == "" || strings.Contains(value, "$(") {
			continue
		}
		switch key {
		case logging.EnvLevel:
			if err := logging.ValidateLevel(value); err != nil {
				report(key, value, err)
			}
		case envFormat:
			report(key, value, errFormatRemoved)
		}
	}
	for _, key := range []string{"command", "args"} {
		list, _ := c[key].([]any)
		for i, a := range list {
			arg, _ := a.(string)
			flagName, value, found := strings.Cut(arg, "=")
			if flagName == "--"+logging.DevelFlag {
				if value != "false" {
					findings = append(findings, fmt.Sprintf("container %s: %s: %v", name, arg, errDevel))
				}
				continue
			}
			if flagName != "--log-level" && flagName != "--log-format" {
				continue
			}
			if !found {
				if i+1 >= len(list) {
					continue
				}
				value, _ = list[i+1].(string)
			}
			if strings.Contains(value, "$(") {
				continue
			}
			if flagName == "--log-format" {
				report(flagName, value, errFormatRemoved)
				continue
			}
			if err := logging.ValidateLevel(value); err != nil {
				report(flagName, value, err)
			}
		}
	}
	return findings
}

// isGalactic reports whether a container's image, or its name in a patch
// without an image, is a binary that calls logging.Setup.
func isGalactic(name, image string) bool {
	if image == "" {
		return slices.Contains(logging.Binaries, name)
	}
	repo, _, _ := strings.Cut(image, "@")
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	return slices.Contains(logging.Binaries, path.Base(repo))
}

// runsGalactic reports whether command runs a binary that calls
// logging.Setup, such as fabric-config-agent, which ships in the
// fabric-router image and runs from a shell script in frr-init.
func runsGalactic(command []any) bool {
	for _, a := range command {
		arg, _ := a.(string)
		for _, word := range strings.Fields(arg) {
			if slices.Contains(logging.Binaries, path.Base(word)) {
				return true
			}
		}
	}
	return false
}
