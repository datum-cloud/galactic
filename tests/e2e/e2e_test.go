// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package e2e contains end-to-end tests for the galactic binary running inside
// a Kind cluster. The tests assume:
//   - A Kind cluster named "galactic-e2e" (or $CLUSTER_NAME) is already running.
//   - The image "galactic-cni:e2e" (or $IMG) has already been loaded into the cluster.
//   - kubectl is on PATH and its context points at that cluster.
//
// These preconditions are set up by the e2etest target in scripts/ci.sh.
package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	defaultImg      = "galactic-cni:e2e"
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
	if out, err := kubectl(context.Background(), "cluster-info"); err != nil {
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
		context.Background(),
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

	if err := waitForPodPhase(t, name, "Succeeded"); err != nil {
		t.Fatalf("pod did not succeed: %v", err)
	}

	logs, err := kubectl(context.Background(), "logs", name)
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
				t.Context(),
				"run", name,
				"--image="+image(),
				"--image-pull-policy=Never",
				"--restart=Never",
				"--privileged",
				"--command", "--",
				"sh", "-c", tt.command,
			)
			if err != nil {
				t.Fatalf("kubectl run failed: %v", err)
			}

			if err := waitForPodPhase(t, name, "Succeeded"); err != nil {
				// Fetch logs to aid debugging before failing.
				if logs, logErr := kubectl(t.Context(), "logs", name); logErr == nil && logs != "" {
					t.Logf("pod logs:\n%s", logs)
				}
				t.Fatalf("kernel capability check %q failed: %v", tt.name, err)
			}
		})
	}
}

// TestCNITapInterface exercises the galactic CNI plugin in tap interface mode.
// It creates a pod that invokes the CNI plugin with CNI_COMMAND=ADD and a tap
// config, then validates the CNI result JSON: a single host interface with an
// empty sandbox and no IP addresses.
//
// This test requires a cluster node with VRF/tap kernel support (the same
// prerequisites checked by TestKernelCapabilities). It will fail rather than
// skip if those features are missing, so a clean run of TestKernelCapabilities
// is a prerequisite.
func TestCNITapInterface(t *testing.T) {
	name := "e2e-cni-tap"
	t.Cleanup(func() { deletePod(t, name) })
	deletePod(t, name)

	// Start a shell so we can later exec the CNI plugin with stdin.
	// The galactic-cni entrypoint is overridden to "sh" so the pod stays
	// running and we can pipe the CNI config via kubectl exec -i.
	_, err := kubectl(
		t.Context(),
		"run", name,
		"--image="+image(),
		"--image-pull-policy=Never",
		"--restart=Never",
		"--privileged",
		"--command", "--",
		"sleep", "infinity",
	)
	if err != nil {
		t.Fatalf("kubectl run failed: %v", err)
	}

	if err := waitForPodPhase(t, name, "Running"); err != nil {
		t.Fatalf("pod did not reach Running phase: %v", err)
	}

	// Write the CNI config to a file inside the pod, then run the plugin
	// with the config piped via stdin.  The plugin reads config from stdin
	// (the CNI protocol) and CNI_NETNS from the environment.
	cniConf := `{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "type": "galactic-cni",
  "vpc": "1",
  "vpcattachment": "1",
  "interface_type": "tap",
  "srv6_locator": "2001:db8:ff01::/48"
}`
	// Step 1: write the CNI config and a wrapper script into the pod.
	script := `#!/bin/sh
ip netns add e2e-tap-ns
CNI_NETNS=/var/run/netns/e2e-tap-ns \
CNI_COMMAND=ADD \
CNI_CONTAINERID=e2e-tap-001 \
CNI_IFNAME=eth0 \
CNI_PATH=/opt/cni/bin \
NODE_NAME=` + nodeName() + ` \
	/galactic-cni < /tmp/cni.json
`
	_, err = kubectl(t.Context(), "exec", name, "--",
		"sh", "-c",
		"echo '"+cniConf+"' > /tmp/cni.json && "+
			"echo '"+script+"' > /tmp/run-cni.sh && "+
			"chmod +x /tmp/run-cni.sh",
	)
	if err != nil {
		t.Fatalf("write cni config and script: %v", err)
	}

	// Step 2: run the wrapper script.
	out, err := kubectl(t.Context(), "exec", name, "-i", "--", "/tmp/run-cni.sh")
	if err != nil {
		// Debug: check what interfaces and sysctl paths exist
		debugCmd := "ip link show 2>&1 && echo '---' && " +
			"ls /proc/sys/net/ipv6/conf/ 2>&1 && echo '---' && " +
			"ls /proc/sys/net/ipv4/conf/ 2>&1"
		if debug, dErr := kubectl(t.Context(), "exec", name, "--", "sh", "-c", debugCmd); dErr == nil {
			t.Logf("debug output:\n%s", debug)
		}
		t.Logf("exec output: %s", out)
		t.Fatalf("CNI ADD failed: %v", err)
	}

	// The CNI result is JSON; find the first '{'.
	jsonStart := strings.Index(out, "{")
	if jsonStart == -1 {
		t.Fatalf("no JSON found in CNI ADD output:\n%s", out)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out[jsonStart:]), &result); err != nil {
		t.Fatalf("CNI ADD output is not valid JSON: %v\noutput:\n%s", err, out)
	}

	// Tap mode produces exactly 1 interface (the host tap) with an empty sandbox.
	ifaces, ok := result["interfaces"].([]any)
	if !ok {
		t.Fatalf("CNI result missing or invalid \"interfaces\" field; got: %v", result)
	}
	if len(ifaces) != 1 {
		t.Errorf("interfaces count = %d, want 1", len(ifaces))
	}

	iface, ok := ifaces[0].(map[string]any)
	if !ok {
		t.Fatalf("interfaces[0] is not an object; got: %T", ifaces[0])
	}
	if sandbox, _ := iface["sandbox"].(string); sandbox != "" {
		t.Errorf("interfaces[0].sandbox = %q, want empty (tap has no guest endpoint)", sandbox)
	}

	// Tap mode does not configure guest IPs.
	if ips, ok := result["ips"]; ok && ips != nil {
		ipsArr, ok := ips.([]any)
		if ok && len(ipsArr) > 0 {
			t.Errorf("CNI result has %d IP(s), want 0 for tap mode", len(ipsArr))
		}
	}
}

// nodeName returns the name of the node this pod runs on, or falls back to
// "kind-worker" for single-node Kind clusters.
func nodeName() string {
	if v := os.Getenv("NODE_NAME"); v != "" {
		return v
	}
	return "kind-worker"
}

// kubectl runs kubectl with the given arguments and returns combined output.
func kubectl(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// waitForPodPhase polls until the named pod reaches wantPhase or the timeout
// expires. It returns an error describing the last observed phase on timeout.
func waitForPodPhase(t *testing.T, name, wantPhase string) error {
	t.Helper()
	deadline := time.Now().Add(podReadyTimeout)
	for time.Now().Before(deadline) {
		out, err := kubectl(t.Context(), "get", "pod", name, "-o", "jsonpath={.status.phase}")
		if err == nil && out == wantPhase {
			return nil
		}
		if out == "Failed" {
			return fmt.Errorf("pod %s entered Failed phase", name)
		}
		time.Sleep(podPollInterval)
	}
	out, _ := kubectl(t.Context(), "get", "pod", name, "-o", "jsonpath={.status.phase}")
	return fmt.Errorf("timed out after %v waiting for phase %q; last phase: %q", podReadyTimeout, wantPhase, out)
}

// deletePod removes a pod by name, ignoring not-found errors.
func deletePod(t *testing.T, name string) {
	t.Helper()
	kubectl(t.Context(), "delete", "pod", name, "--ignore-not-found", "--wait=false") //nolint:errcheck
}
