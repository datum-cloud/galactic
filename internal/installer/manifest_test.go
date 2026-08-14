// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

// TestDaemonsetManifest_RunContainerMountsHostConflistDir is a regression
// test for a manifest/code mismatch that shipped silently: startEBPFDatapath
// (and getLogFileHostPath) call hostconf.Load(HostConflist, ...) from inside
// whichever container runs the installer's "run" command
// (credential-refresh in config/cni/daemonset.yaml). If that container's
// volumeMounts don't cover the host directory HostConflist lives under,
// hostconf.Load fails on every node, and the eBPF vrf_table GC sweep (and
// log-rotation's host-path lookup) permanently disables itself with only a
// slog.Warn("eBPF vrf_table GC sweep disabled: ...") to show for it --
// config/cni/daemonset.yaml previously mounted cni-net-dir into the
// install-cni init container only, never into credential-refresh, so this
// went unnoticed until it was confirmed live on production infra.
//
// This test parses the real manifest rather than a copy, so it can't drift
// from what actually gets applied to a cluster.
//
// hostConflistDefault captures HostConflist's production default at
// package-variable-initialization time -- before any test body runs. Other
// tests in this package (e.g. TestRun) repoint the HostConflist package var
// at a t.TempDir() path for the duration of the test and never restore it,
// so reading the live HostConflist var here would make this test's outcome
// depend on test execution order within the package.
var hostConflistDefault = HostConflist

func TestDaemonsetManifest_RunContainerMountsHostConflistDir(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "config", "cni", "daemonset.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read %s: %v", manifestPath, err)
	}

	var ds appsv1.DaemonSet
	if err := yaml.Unmarshal(data, &ds); err != nil {
		t.Fatalf("unmarshal %s: %v", manifestPath, err)
	}

	// Find the container that invokes `/galactic-cni run` -- that's the one
	// that calls hostconf.Load(HostConflist, ...) at runtime.
	var runContainerName string
	var mountPaths []string
	found := false
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, arg := range c.Command {
			if arg != "run" {
				continue
			}
			runContainerName = c.Name
			for _, vm := range c.VolumeMounts {
				mountPaths = append(mountPaths, vm.MountPath)
			}
			found = true
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("no container in %s runs the installer's \"run\" command", manifestPath)
	}

	hostConflistDir := filepath.Dir(hostConflistDefault)
	if !slices.Contains(mountPaths, hostConflistDir) {
		t.Errorf("container %q in %s does not mount %s (needed to read HostConflist=%s via "+
			"hostconf.Load; without it the eBPF vrf_table GC sweep and log-rotation host-path "+
			"lookup silently disable themselves on every node); mounted paths: %v",
			runContainerName, manifestPath, hostConflistDir, hostConflistDefault, mountPaths)
	}
}
