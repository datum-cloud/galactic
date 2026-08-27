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

	"go.datum.net/galactic/internal/plumbing/radv"
)

// TestDaemonsetManifest_RunContainerMountsHostConflistDir is a regression
// test for a manifest/code mismatch that shipped silently: startEBPFDatapath
// (and getLogFileHostPath) call hostconf.Load(HostConflist, ...) from inside
// whichever container runs the installer's "run" command
// (credential-refresh in config/galactic-cni/daemonset.yaml). If that container's
// volumeMounts don't cover the host directory HostConflist lives under,
// hostconf.Load fails on every node, and the eBPF vrf_table GC sweep (and
// log-rotation's host-path lookup) permanently disables itself with only a
// slog.Warn("eBPF vrf_table GC sweep disabled: ...") to show for it --
// config/galactic-cni/daemonset.yaml previously mounted cni-net-dir into the
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

// manifestPath is the real, applied-to-a-cluster manifest every test in
// this file parses -- shared so a path typo can't diverge between tests.
var manifestPath = filepath.Join("..", "..", "config", "galactic-cni", "daemonset.yaml")

func TestDaemonsetManifest_RunContainerMountsHostConflistDir(t *testing.T) {
	runContainerName, mountPaths := runContainerMountPaths(t)

	hostConflistDir := filepath.Dir(hostConflistDefault)
	if !slices.Contains(mountPaths, hostConflistDir) {
		t.Errorf("container %q in %s does not mount %s (needed to read HostConflist=%s via "+
			"hostconf.Load; without it the eBPF vrf_table GC sweep and log-rotation host-path "+
			"lookup silently disable themselves on every node); mounted paths: %v",
			runContainerName, manifestPath, hostConflistDir, hostConflistDefault, mountPaths)
	}
}

// TestDaemonsetManifest_RunContainerMountsRadvStateDir is a regression test
// for the same class of manifest/code mismatch as
// TestDaemonsetManifest_RunContainerMountsHostConflistDir above, this time
// for radv.DefaultStateDir ("/var/lib/cni/ra"): reconcileRadvActors calls
// radv.ListAttachments(radv.DefaultStateDir) from inside the run container
// on every radvReconcileTicker tick. That directory is populated by
// galactic-tap's cmdAdd/cmdDel (internal/cnitap/ops_add.go,
// internal/cnitap/ops_del.go) -- a separate binary invoked directly on the
// host by the kubelet's own CNI exec, not inside this or any other
// container -- so radv.DefaultStateDir is deliberately the real
// host-absolute path, unlike HostBinDir/HostConflist/HostEtcDir above which
// are all under /host/... on purpose. Without a volumeMount covering it,
// the run container always lists an empty/missing directory: every tap
// attachment galactic-tap ever records is invisible to it, so no RunActor
// starts and no guest gets an RA or a Router Solicitation reply -- silently,
// on every node, with nothing in the logs to show for it. This shipped
// unnoticed the same way HostConflist's own gap did, confirmed live on
// staging infra.
func TestDaemonsetManifest_RunContainerMountsRadvStateDir(t *testing.T) {
	runContainerName, mountPaths := runContainerMountPaths(t)

	radvStateDir := filepath.Dir(radv.DefaultStateDir)
	if !slices.Contains(mountPaths, radvStateDir) {
		t.Errorf("container %q in %s does not mount %s (needed to read radv.DefaultStateDir=%s via "+
			"radv.ListAttachments; without it no tap attachment's Router Advertisement/Solicitation "+
			"actor ever starts on any node); mounted paths: %v",
			runContainerName, manifestPath, radvStateDir, radv.DefaultStateDir, mountPaths)
	}
}

// runContainerMountPaths parses the real daemonset.yaml (not a copy, so it
// can't drift from what actually gets applied to a cluster), finds the
// container that invokes `/galactic-cni run` -- credential-refresh, the one
// that calls installer.Run -- and returns its name plus every path in its
// own volumeMounts.
func runContainerMountPaths(t *testing.T) (string, []string) {
	t.Helper()

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read %s: %v", manifestPath, err)
	}

	var ds appsv1.DaemonSet
	if err := yaml.Unmarshal(data, &ds); err != nil {
		t.Fatalf("unmarshal %s: %v", manifestPath, err)
	}

	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, arg := range c.Command {
			if arg != "run" {
				continue
			}
			mountPaths := make([]string, 0, len(c.VolumeMounts))
			for _, vm := range c.VolumeMounts {
				mountPaths = append(mountPaths, vm.MountPath)
			}
			return c.Name, mountPaths
		}
	}

	t.Fatalf("no container in %s runs the installer's \"run\" command", manifestPath)
	return "", nil
}
