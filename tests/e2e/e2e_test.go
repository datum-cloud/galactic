// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package e2e contains end-to-end tests for the galactic binary running inside
// a Kind cluster. The tests assume:
//   - A Kind cluster named "galactic-e2e" (or $CLUSTER_NAME) is already running.
//   - The image "galactic:e2e" (or $IMG) has already been loaded into the cluster.
//   - kubectl is on PATH and its context points at that cluster.
//
// These preconditions are set up by the e2etest target in scripts/ci.sh.
package e2e_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	defaultImg      = "galactic:e2e"
	podReadyTimeout = 60 * time.Second
	podPollInterval = 2 * time.Second
)

func image() string {
	if v := os.Getenv("IMG"); v != "" {
		return v
	}
	return defaultImg
}

// TestMain verifies that kubectl is available and the cluster is reachable
// before running any test. Any missing prerequisite skips the suite rather
// than failing, so a plain `go test ./tests/e2e/...` without a cluster is a
// no-op rather than a hard error.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		fmt.Fprintln(os.Stderr, "SKIP: kubectl not found in PATH")
		os.Exit(0)
	}
	if out, err := kubectl("cluster-info"); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: cluster not reachable: %v\n%s\n", err, out)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestCNIPluginVersionReport invokes the binary with CNI_COMMAND=VERSION, which
// causes it to report the CNI spec versions it supports. The response must be
// valid JSON containing a "cniVersion" key.
func TestCNIPluginVersionReport(t *testing.T) {
	name := "e2e-cni-version"
	t.Cleanup(func() { deletePod(t, name) })
	deletePod(t, name)

	_, err := kubectl(
		"run", name,
		"--image="+image(),
		"--image-pull-policy=Never",
		"--restart=Never",
		"--env=CNI_COMMAND=VERSION",
		"--command", "--",
		"/galactic-cni",
	)
	if err != nil {
		t.Fatalf("kubectl run failed: %v", err)
	}

	if err := waitForPodPhase(t, name, "Succeeded", podReadyTimeout); err != nil {
		t.Fatalf("pod did not succeed: %v", err)
	}

	logs, err := kubectl("logs", name)
	if err != nil {
		t.Fatalf("kubectl logs failed: %v", err)
	}

	// The CNI version report is JSON; find the first '{'.
	jsonStart := strings.Index(logs, "{")
	if jsonStart == -1 {
		t.Fatalf("no JSON found in CNI VERSION output:\n%s", logs)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(logs[jsonStart:]), &report); err != nil {
		t.Fatalf("CNI VERSION output is not valid JSON: %v\noutput:\n%s", err, logs)
	}
	if _, ok := report["cniVersion"]; !ok {
		t.Errorf("CNI VERSION response missing \"cniVersion\" key; got: %v", report)
	}
	if _, ok := report["supportedVersions"]; !ok {
		t.Errorf("CNI VERSION response missing \"supportedVersions\" key; got: %v", report)
	}
}

// TestKernelCapabilities verifies that the Kind node exposes the Linux kernel
// features galactic depends on: VRF devices and SRv6 (SEG6) local routing.
// These checks run as a privileged pod so they can interrogate the host kernel.
func TestKernelCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		command string // shell expression to run inside the privileged pod
	}{
		{
			name:    "vrf_module",
			command: "ip link add vrf-e2e-test type vrf table 9999 && ip link del vrf-e2e-test",
		},
		{
			name:    "ipv6_enabled",
			command: "test -f /proc/sys/net/ipv6/conf/all/disable_ipv6",
		},
		{
			// seg6_local may be a loadable module or compiled into the kernel.
			// When built-in, lsmod and /sys/module won't show it, but the
			// seg6_enabled sysctl is present on any kernel with SEG6 support.
			name: "seg6_local_module",
			command: "modprobe seg6_local 2>/dev/null || lsmod | grep -q seg6 ||" +
				" test -d /sys/module/seg6_local || test -f /proc/sys/net/ipv6/conf/all/seg6_enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := "e2e-kernel-" + strings.ReplaceAll(tt.name, "_", "-")
			t.Cleanup(func() { deletePod(t, name) })
			deletePod(t, name)

			_, err := kubectl(
				"run", name,
				"--image=busybox:stable",
				"--image-pull-policy=IfNotPresent",
				"--restart=Never",
				"--privileged",
				"--command", "--",
				"sh", "-c", tt.command,
			)
			if err != nil {
				t.Fatalf("kubectl run failed: %v", err)
			}

			if err := waitForPodPhase(t, name, "Succeeded", podReadyTimeout); err != nil {
				// Fetch logs to aid debugging before failing.
				if logs, logErr := kubectl("logs", name); logErr == nil && logs != "" {
					t.Logf("pod logs:\n%s", logs)
				}
				t.Fatalf("kernel capability check %q failed: %v", tt.name, err)
			}
		})
	}
}

// kubectl runs kubectl with the given arguments and returns combined output.
func kubectl(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// waitForPodPhase polls until the named pod reaches wantPhase or the timeout
// expires. It returns an error describing the last observed phase on timeout.
func waitForPodPhase(t *testing.T, name, wantPhase string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectl("get", "pod", name, "-o", "jsonpath={.status.phase}")
		if err == nil && out == wantPhase {
			return nil
		}
		if out == "Failed" {
			return fmt.Errorf("pod %s entered Failed phase", name)
		}
		time.Sleep(podPollInterval)
	}
	out, _ := kubectl("get", "pod", name, "-o", "jsonpath={.status.phase}")
	return fmt.Errorf("timed out after %v waiting for phase %q; last phase: %q", timeout, wantPhase, out)
}

// deletePod removes a pod by name, ignoring not-found errors.
func deletePod(t *testing.T, name string) {
	t.Helper()
	kubectl("delete", "pod", name, "--ignore-not-found", "--wait=false") //nolint:errcheck
}
