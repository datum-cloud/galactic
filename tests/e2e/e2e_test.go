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
	_, err := kubectl(
		t.Context(),
		"run", name,
		"--image="+image(),
		"--image-pull-policy=Never",
		"--restart=Never",
		"--privileged",
		"--overrides={\"spec\":{\"serviceAccountName\":\"galactic-cni\",\"hostNetwork\":true}}",
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
  "srv6_locator": "2001:db8:ff01::/48",
  "ipam": {
    "type": "pool"
  }
}`
	// Step 1: write the CNI config and a wrapper script into the pod.
	// Tap mode now runs IPAM allocation unconditionally (matching veth mode).
	// GALACTIC_CNI_ENABLE_LOCAL_IPAM fills in default pool/subnet_len when
	// omitted, but parseConf still requires an explicit "ipam" block to be
	// present in the config (see docs/cni/configuration.md).
	script := `#!/bin/sh
ip netns add e2e-tap-ns
CNI_NETNS=/var/run/netns/e2e-tap-ns \
CNI_COMMAND=ADD \
CNI_CONTAINERID=e2e-tap-001 \
CNI_IFNAME=eth0 \
CNI_PATH=/opt/cni/bin \
NODE_NAME=` + nodeName() + ` \
GALACTIC_CNI_ENABLE_LOCAL_IPAM=true \
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

// TestCNIVPCAttachmentCreation exercises galactic-cni's VPCAttachment CR
// creation (internal/cni/vpcattachment.go's applyVPCAttachment): a CNI ADD
// with vpc_name set should create the VPCAttachment CR at the same point the
// plugin already creates BGPVRFInstance/BGPAdvertisement, with Spec populated
// from the real IPAM allocation and Status carrying the attach-time facts
// (node, container ID, pod name, interface names, pod subnet).
//
// Runs in tap mode (like TestCNITapInterface) to avoid host-device delegation,
// and uses a distinct (vpc, vpcattachment) pair so its kernel/CRD state never
// collides with that test's.
func TestCNIVPCAttachmentCreation(t *testing.T) {
	const (
		podName       = "e2e-cni-vpcattachment"
		vpc           = "2"
		vpcAttachment = "1"
		vpcName       = "e2e-vpc" // fixture created in scripts/ci.sh
		attachedPod   = "e2e-attached-pod"
		attachmentCR  = vpc + "-" + vpcAttachment
		nadName       = "galactic-vpcattach" // must match cniConf's "name" field below
	)
	// VPCAttachmentStatus.ContainerID requires exactly 46 characters (see
	// internal/cni/vpcattachment.go's containerIDStatusLen) — real container
	// IDs are 64 hex chars and get truncated to fit, but a shorter input like
	// a plain test string would fail that length requirement outright, so
	// this constructs one at the required length instead of guessing.
	containerID := "e2evpcattach001" + strings.Repeat("0", 46-len("e2evpcattach001"))

	t.Cleanup(func() { deletePod(t, podName) })
	deletePod(t, podName)
	t.Cleanup(func() { deleteVPCAttachment(t, attachmentCR) })
	deleteVPCAttachment(t, attachmentCR)
	t.Cleanup(func() { deleteNAD(t, nadName) })
	deleteNAD(t, nadName)

	// In production galactic-webhook creates this NAD before the pod is ever
	// scheduled (see internal/webhook/nad.go). This test exercises
	// galactic-cni's VPCAttachment creation in isolation, so it stands in for
	// that step directly — galactic-cni's annotateNAD (internal/cni/nad.go)
	// still expects the NAD to already exist and hard-fails otherwise.
	nadYAML := `apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: ` + nadName + `
  namespace: galactic-system
spec:
  config: '{}'
`
	if out, err := kubectlApply(t.Context(), nadYAML); err != nil {
		t.Fatalf("create stub NAD: %v\n%s", err, out)
	}

	_, err := kubectl(
		t.Context(),
		"run", podName,
		"--image="+image(),
		"--image-pull-policy=Never",
		"--restart=Never",
		"--privileged",
		"--overrides={\"spec\":{\"serviceAccountName\":\"galactic-cni\",\"hostNetwork\":true}}",
		"--command", "--",
		"sleep", "infinity",
	)
	if err != nil {
		t.Fatalf("kubectl run failed: %v", err)
	}

	if err := waitForPodPhase(t, podName, "Running"); err != nil {
		t.Fatalf("pod did not reach Running phase: %v", err)
	}

	cniConf := `{
  "cniVersion": "1.0.0",
  "name": "galactic-vpcattach",
  "type": "galactic-cni",
  "vpc": "` + vpc + `",
  "vpc_name": "` + vpcName + `",
  "vpcattachment": "` + vpcAttachment + `",
  "interface_type": "tap",
  "ipam": {
    "type": "pool"
  }
}`
	// CNI_ARGS carries K8S_POD_NAME/K8S_POD_NAMESPACE the way Multus populates
	// them for a real invocation — applyVPCAttachment needs both (podNamespace
	// to create the VPCAttachment in, PodName for Status.PodName).
	script := `#!/bin/sh
ip netns add e2e-vpcattach-ns
CNI_NETNS=/var/run/netns/e2e-vpcattach-ns \
CNI_COMMAND=ADD \
CNI_CONTAINERID=` + containerID + ` \
CNI_IFNAME=eth0 \
CNI_PATH=/opt/cni/bin \
CNI_ARGS="K8S_POD_NAME=` + attachedPod + `;K8S_POD_NAMESPACE=galactic-system" \
NODE_NAME=` + nodeName() + ` \
GALACTIC_CNI_ENABLE_LOCAL_IPAM=true \
	/galactic-cni < /tmp/cni-vpcattach.json
`
	_, err = kubectl(t.Context(), "exec", podName, "--",
		"sh", "-c",
		"echo '"+cniConf+"' > /tmp/cni-vpcattach.json && "+
			"echo '"+script+"' > /tmp/run-cni-vpcattach.sh && "+
			"chmod +x /tmp/run-cni-vpcattach.sh",
	)
	if err != nil {
		t.Fatalf("write cni config and script: %v", err)
	}

	if out, err := kubectl(t.Context(), "exec", podName, "-i", "--", "/tmp/run-cni-vpcattach.sh"); err != nil {
		t.Logf("exec output: %s", out)
		t.Fatalf("CNI ADD failed: %v", err)
	}

	raw, err := kubectl(t.Context(), "get", "vpcattachments.cloud.datumapis.com", attachmentCR, "-o", "json")
	if err != nil {
		t.Fatalf("get VPCAttachment %q: %v\n%s", attachmentCR, err, raw)
	}

	var attachment struct {
		Spec struct {
			VPC struct {
				Name string `json:"name"`
			} `json:"vpc"`
			Interface struct {
				Name      string   `json:"name"`
				Addresses []string `json:"addresses"`
			} `json:"interface"`
		} `json:"spec"`
		Status struct {
			VPC            string `json:"vpc"`
			VPCAttachment  string `json:"vpcAttachment"`
			Node           string `json:"node"`
			ContainerID    string `json:"containerID"`
			PodName        string `json:"podName"`
			HostInterface  string `json:"hostInterface"`
			VRFInterface   string `json:"vrfInterface"`
			GuestInterface string `json:"guestInterface"`
			PodSubnet      string `json:"podSubnet"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(raw), &attachment); err != nil {
		t.Fatalf("unmarshal VPCAttachment: %v\n%s", err, raw)
	}

	if attachment.Spec.VPC.Name != vpcName {
		t.Errorf("Spec.VPC.Name = %q, want %q", attachment.Spec.VPC.Name, vpcName)
	}
	if len(attachment.Spec.Interface.Addresses) == 0 {
		t.Error("Spec.Interface.Addresses is empty, want at least one allocated address")
	}
	if attachment.Status.VPC != vpc {
		t.Errorf("Status.VPC = %q, want %q", attachment.Status.VPC, vpc)
	}
	if attachment.Status.VPCAttachment != vpcAttachment {
		t.Errorf("Status.VPCAttachment = %q, want %q", attachment.Status.VPCAttachment, vpcAttachment)
	}
	if attachment.Status.Node != nodeName() {
		t.Errorf("Status.Node = %q, want %q", attachment.Status.Node, nodeName())
	}
	if attachment.Status.ContainerID != containerID {
		t.Errorf("Status.ContainerID = %q, want %q", attachment.Status.ContainerID, containerID)
	}
	if attachment.Status.PodName != attachedPod {
		t.Errorf("Status.PodName = %q, want %q", attachment.Status.PodName, attachedPod)
	}
	if attachment.Status.HostInterface == "" || attachment.Status.VRFInterface == "" {
		t.Errorf("Status host/vrf interface names unexpectedly empty: %+v", attachment.Status)
	}
	if attachment.Status.PodSubnet == "" {
		t.Error("Status.PodSubnet is empty, want an allocated subnet")
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

// kubectlApply runs `kubectl apply -f -`, piping manifest in via stdin.
func kubectlApply(ctx context.Context, manifest string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
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

// deleteVPCAttachment removes a VPCAttachment CR by name, ignoring
// not-found errors. Mirrors deletePod's cleanup pattern.
func deleteVPCAttachment(t *testing.T, name string) {
	t.Helper()
	//nolint:errcheck
	kubectl(t.Context(), "delete", "vpcattachments.cloud.datumapis.com", name, "--ignore-not-found", "--wait=false")
}

// deleteNAD removes a NetworkAttachmentDefinition by name, ignoring
// not-found errors. Mirrors deletePod's cleanup pattern.
func deleteNAD(t *testing.T, name string) {
	t.Helper()
	//nolint:errcheck
	kubectl(t.Context(), "delete", "network-attachment-definitions.k8s.cni.cncf.io", name,
		"--ignore-not-found", "--wait=false")
}
