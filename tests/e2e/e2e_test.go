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

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
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

// TestCNITapInterface exercises galactic-tap-cni, the tap master plugin.
// It creates a pod that invokes the plugin with CNI_COMMAND=ADD and a tap
// config, then validates the CNI result JSON: a single host interface with an
// empty sandbox and the host-side gateway/subnet IPAM allocated for it.
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
	// Run as the galactic-cni ServiceAccount so the CNI plugin's in-cluster
	// client is bound by the galactic-cni ClusterRole (config/cni/rbac.yaml)
	// when it lists/creates BGPRouter, BGPAdvertisement, and BGPVRFInstance.
	// hostNetwork is required too: net.vrf.strict_mode (enabled on the Kind
	// node in scripts/ci.sh) is per-netns, and the SEG6Local VRFTABLE route
	// this test exercises needs it set in whichever netns the route lands in.
	// The bpf-fs hostPath volume mirrors config/cni/daemonset.yaml's own
	// bpf-fs mount: the eBPF uSID datapath's maps can only be pinned under
	// attach.PinDir if the node's real bpffs (mounted onto the Kind node in
	// scripts/ci.sh) is visible inside the pod -- a pod's own mount
	// namespace can't create /sys/fs/bpf itself. The whole container spec
	// (image, command, privileged) has to live in --overrides too, not the
	// usual --image/--command/--privileged flags: kubectl run's overrides
	// merge replaces the generated "containers" list wholesale rather than
	// merging into it, so anything set only via those flags would otherwise
	// be silently dropped the moment "containers" is also set here.
	overrides := fmt.Sprintf(`{"spec":{"serviceAccountName":"galactic-cni","hostNetwork":true,`+
		`"volumes":[{"name":"bpf-fs","hostPath":{"path":"/sys/fs/bpf","type":"Directory"}}],`+
		`"containers":[{"name":%q,"image":%q,"imagePullPolicy":"Never","command":["sleep","infinity"],`+
		`"securityContext":{"privileged":true},`+
		`"volumeMounts":[{"name":"bpf-fs","mountPath":"/sys/fs/bpf"}]}]}}`, name, image())
	runOut, err := kubectl(
		t.Context(),
		"run", name,
		"--image="+image(),
		"--restart=Never",
		"--overrides="+overrides,
	)
	if err != nil {
		t.Fatalf("kubectl run failed: %v\n%s", err, runOut)
	}

	if err := waitForPodPhase(t, name, "Running"); err != nil {
		t.Fatalf("pod did not reach Running phase: %v", err)
	}

	// The eBPF uSID datapath is now the only forwarding path (see
	// internal/cnibgp/bgp.go's registerEBPFDatapath, called inline from
	// galactic-tap-cni's own cmdAdd at this point in the CNI plugin-chain
	// split), so CNI ADD requires this node's locator_table/function_table/
	// vrf_table maps to already be pinned under attach.PinDir. In
	// production that's done ahead of time by the CNI DaemonSet's
	// long-running "credential-refresh" container (config/cni/
	// daemonset.yaml, `/galactic-cni run`); this test runs its own pod
	// instead of relying on that DaemonSet, so it must start the same
	// control daemon itself before exercising CNI ADD below.
	startEBPFControlDaemon(t, name)

	// Write the CNI config to a file inside the pod, then run the plugin
	// with the config piped via stdin.  The plugin reads config from stdin
	// (the CNI protocol) and CNI_NETNS from the environment.
	//
	// The "ipam" block's "type" now names the delegated binary
	// (galactic-ipam), not a pool-vs-static mode selector -- this step
	// rewired IPAM from an in-process call into real CNI IPAM delegation
	// (github.com/containernetworking/plugins/pkg/ipam.ExecAdd), so
	// "pool" is no longer a valid type value; presence of ipv6_subnet
	// alone opts this config into pool IPAM (see internal/cniipam's doc
	// comment and docs/cni/configuration.md).
	cniConf := `{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "type": "galactic-tap-cni",
  "vpc": "1",
  "vpcattachment": "1",
  "ipam": {
    "type": "galactic-ipam",
    "ipv6_subnet": "fd00:e2e:tap::/48"
  }
}`
	// Step 1: write the CNI config and a wrapper script into the pod.
	// CNI_PATH=/ lets IPAM delegation (galactic-tap-cni execs galactic-ipam
	// via ipam.ExecAdd) find the delegate binary: every binary in the
	// chain is copied to the image root by containers/galactic-cni/
	// Dockerfile (not /opt/cni/bin -- that path only exists on the real
	// host once installer.Bootstrap's init container stages it there,
	// which this test's pod never runs).
	script := `#!/bin/sh
ip netns add e2e-tap-ns
CNI_NETNS=/var/run/netns/e2e-tap-ns \
CNI_COMMAND=ADD \
CNI_CONTAINERID=e2e-tap-001 \
CNI_IFNAME=eth0 \
CNI_PATH=/ \
NODE_NAME=` + nodeName() + ` \
	/galactic-tap-cni < /tmp/cni.json
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

	// Tap mode now runs IPAM allocation like veth mode (the guest still
	// configures its own IP; this is the host-side gateway/subnet recorded
	// against the host tap interface).
	ips, ok := result["ips"].([]any)
	if !ok {
		t.Fatalf("CNI result missing or invalid \"ips\" field; got: %v", result)
	}
	if len(ips) != 1 {
		t.Errorf("ips count = %d, want 1", len(ips))
	}
}

// startEBPFControlDaemon runs `/galactic-cni run` inside the already-running
// pod named name and waits for it to load and pin the eBPF uSID datapath's
// maps under attach.PinDir. GALACTIC_CNI_EBPF_INTERFACES pins the attach
// step to the pod's (hostNetwork) eth0 rather than relying on default-route
// auto-detection -- only the pinning (not the attach itself) matters for
// the vrf_table registration TestCNITapInterface exercises.
func startEBPFControlDaemon(t *testing.T, name string) {
	t.Helper()

	_, err := kubectl(t.Context(), "exec", name, "--", "sh", "-c",
		"GALACTIC_CNI_EBPF_INTERFACES=eth0 nohup /galactic-cni run >/tmp/run.log 2>&1 &")
	if err != nil {
		t.Fatalf("start eBPF control daemon: %v", err)
	}

	pinnedVRFTable := attach.PinDir + "/vrf_table"
	deadline := time.Now().Add(podReadyTimeout)
	for time.Now().Before(deadline) {
		if _, err := kubectl(t.Context(), "exec", name, "--", "test", "-e", pinnedVRFTable); err == nil {
			return
		}
		time.Sleep(podPollInterval)
	}

	log, _ := kubectl(t.Context(), "exec", name, "--", "cat", "/tmp/run.log")
	t.Fatalf("timed out waiting for %s to be pinned; control daemon log:\n%s", pinnedVRFTable, log)
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
