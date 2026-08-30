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
		"/galactic-veth",
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

// TestCNITapInterface exercises galactic-tap, the tap master plugin in
// the galactic CNI chain (see internal/cnitap). It creates a pod that
// invokes the plugin with CNI_COMMAND=ADD and a tap config, then validates
// the CNI result JSON: a single host interface with an empty sandbox and
// the host-side gateway/subnet IPAM allocated for it.
//
// This exercises galactic-tap's own ADD (VRF + tap creation, IPAM
// delegation to galactic-ipam) directly, then manually chains galactic-bgp
// after it (testChainedGalacticBGP below), feeding it the tap master's own
// CNI result as prevResult exactly as the CNI runtime would — the same
// manual-chaining approach used because a real conflist-driven chain would
// need a BGPRouter fixture and additional RBAC this test doesn't set up.
// It does not chain into galactic-route (this config has no terminations).
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
	// The galactic-cni image's entrypoint is overridden to "sh" so the pod
	// stays running and we can pipe the CNI config via kubectl exec -i.
	// galactic-tap ships in the same image (see containers/galactic-cni/
	// Dockerfile) alongside every other binary in the CNI chain, so no
	// separate image is needed here. Run as the galactic-cni ServiceAccount:
	// galactic-tap's own ADD unconditionally builds an in-cluster k8s
	// client for its chain-completeness check and NAD-annotation step
	// (config/galactic-cni/rbac.yaml grants it), even though both steps no-op here
	// (no CNI_ARGS, so nadpatch.ParsePodNamespace resolves an empty
	// namespace and nadpatch.VerifyChainComplete/AnnotateNAD both treat
	// that as nothing to check/patch). hostNetwork
	// is required too, so the VRF/tap interfaces this test creates land in
	// the same netns production's own hostNetwork DaemonSet would use. The
	// bpf-fs hostPath volume mirrors config/galactic-cni/daemonset.yaml's own bpf-fs
	// mount: this test chains galactic-bgp (testChainedGalacticBGP below),
	// which registers the eBPF uSID datapath, and its maps can only be
	// pinned under attach.PinDir if the node's real bpffs (mounted onto the
	// Kind node in scripts/ci.sh) is visible inside the pod -- a pod's own
	// mount namespace can't create /sys/fs/bpf itself. The whole container
	// spec (image, command, privileged) has to live in --overrides too, not
	// the usual --image/--command/--privileged flags: kubectl run's
	// overrides merge replaces the generated "containers" list wholesale
	// rather than merging into it, so anything set only via those flags
	// would otherwise be silently dropped the moment "containers" is also
	// set here.
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
	// internal/cnibgp/bgp.go's registerEBPFDatapath, called from
	// galactic-bgp's own cmdAdd — a separately chain-invoked binary since
	// the CNI plugin-chain split, not inline in galactic-tap's cmdAdd
	// any more), so CNI ADD requires this node's locator_table/
	// function_table/vrf_table maps to already be pinned under
	// attach.PinDir. In production that's done ahead of time by the CNI
	// DaemonSet's long-running "credential-refresh" container (config/galactic-cni/
	// daemonset.yaml, `/galactic-cni run`); this test runs its own pod
	// instead of relying on that DaemonSet, so it must start the same
	// control daemon itself before exercising CNI ADD below. Required for
	// testChainedGalacticBGP below too: registerEBPFDatapath's
	// usidmap.OpenPinnedRegistry only opens already-pinned maps, it never
	// loads/pins the eBPF program itself.
	startEBPFControlDaemon(t, name)

	// Write the CNI config to a file inside the pod, then run the plugin
	// with the config piped via stdin.  The plugin reads config from stdin
	// (the CNI protocol) and CNI_NETNS from the environment.
	//
	// The "ipam" block's "type" names the delegated binary (galactic-ipam),
	// not a pool-vs-static mode selector — presence of ipv6_subnet alone
	// opts this config into pool IPAM (see internal/cniipam's doc comment
	// and docs/cni/conflist-reference.md).
	cniConf := `{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "type": "galactic-tap",
  "vpc": "1",
  "vpcattachment": "1",
  "ipam": {
    "type": "galactic-ipam",
    "ipv6_subnet": "fd00:e2e::/48"
  }
}`
	// Step 1: write the CNI config and a wrapper script into the pod.
	// CNI_PATH=/ lets IPAM delegation (galactic-tap execs galactic-ipam
	// via github.com/containernetworking/plugins/pkg/ipam.ExecAdd) find the
	// delegate binary: every binary in the chain is copied to the image
	// root by containers/galactic-cni/Dockerfile (not /opt/cni/bin — that
	// path only exists on the real host once installer.Bootstrap's init
	// container stages it there, which this test's pod never runs).
	script := `#!/bin/sh
ip netns add e2e-tap-ns
CNI_NETNS=/var/run/netns/e2e-tap-ns \
CNI_COMMAND=ADD \
CNI_CONTAINERID=e2e-tap-001 \
CNI_IFNAME=eth0 \
CNI_PATH=/ \
NODE_NAME=` + nodeName() + ` \
	/galactic-tap < /tmp/cni.json
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

	// The CNI result is JSON on stdout, but kubectl exec interleaves
	// stderr (slog log lines) into the captured output.  Decode only
	// the first JSON value so trailing log lines are ignored.
	var result map[string]any
	if jsonStart := strings.Index(out, "{"); jsonStart == -1 {
		t.Fatalf("no JSON found in CNI ADD output:\n%s", out)
	} else if err := json.NewDecoder(strings.NewReader(out[jsonStart:])).Decode(&result); err != nil {
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

	// Step 3: chain galactic-bgp — the CNI runtime's next plugin in the
	// conflist — after galactic-tap, feeding it the tap master's own
	// CNI result as prevResult, exactly as the runtime would. Everything
	// up to this point only exercises galactic-tap's own cmdAdd;
	// BGPVRFInstance/BGPAdvertisement CRD creation and eBPF
	// locator_table/function_table/vrf_table registration all moved into
	// galactic-bgp's own cmdAdd with the CNI plugin-chain split (see
	// internal/cnibgp's doc comment), so without this step the whole BGP
	// publish path has no e2e coverage on the ADD path at all.
	testChainedGalacticBGP(t, name, result)
}

// testChainedGalacticBGP runs galactic-bgp's own ADD, chained after the tap
// master's ADD (tapResult is exactly what that ADD printed, fed through as
// prevResult — see internal/cnibgp/prevresult.go's inferFromPrevResult),
// then CHECK. It asserts the BGPVRFInstance/BGPAdvertisement CRDs exist
// after ADD, and — since checkEBPFEntry (internal/cnibgp/ops_check.go) reads
// back the locator_table, function_table, and vrf_table entries
// registerEBPFDatapath wrote and fails if any are missing or inconsistent —
// that CHECK succeeding is itself the assertion that eBPF registration
// happened correctly on ADD; there is no separate bpftool-style dump here.
func testChainedGalacticBGP(t *testing.T, podName string, tapResult map[string]any) {
	t.Helper()

	const vpc, vpcAttachment = "1", "1"
	vrfCRDName := vpc + "-" + nodeName() // BGPVRFInstance keyed by (vpc, node)
	// BGPAdvertisement keyed by (vpc, vpcAttachment, node) -- see
	// crdnames.BGPAdvertisementName's own doc comment for why node is part
	// of this key: two nodes attaching to the same VPCAttachment (e.g. a
	// multi-replica Deployment) must each get their own BGPAdvertisement,
	// not race to overwrite one shared object.
	advCRDName := vpc + "-" + vpcAttachment + "-" + nodeName()
	t.Cleanup(func() {
		//nolint:errcheck // best-effort cleanup, mirrors deletePod
		kubectl(context.Background(), "delete", "bgpvrfinstance", vrfCRDName, "--ignore-not-found")
		//nolint:errcheck // best-effort cleanup, mirrors deletePod
		kubectl(context.Background(), "delete", "bgpadvertisement", advCRDName, "--ignore-not-found")
	})

	prevResultJSON, err := json.Marshal(tapResult)
	if err != nil {
		t.Fatalf("marshal tap ADD result for prevResult: %v", err)
	}
	bgpConf := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "type": "galactic-bgp",
  "vpc": %q,
  "vpcattachment": %q,
  "prevResult": %s
}`, vpc, vpcAttachment, prevResultJSON)

	// galactic-bgp's EndpointSlice publish (ops_add.go) Gets the owning Pod
	// by name+namespace out of K8S_POD_NAME/K8S_POD_NAMESPACE in CNI_ARGS —
	// exactly what a real kubelet-driven invocation always sets for every
	// pod-scoped CNI call, via Multus. This chained-plugin test invokes the
	// binary directly rather than through the CNI runtime, so it has to set
	// CNI_ARGS itself; podName is this test's own workload pod (created
	// above), so its namespace is asked of the API rather than assumed.
	podNamespace := podNamespaceOf(t, podName)

	// Reuses the same netns/containerID/ifname galactic-tap's own step
	// (above) already set up: a real chained plugin sees the identical
	// values across every plugin invoked for one CNI ADD. Unlike the tap
	// step, this one does set CNI_ARGS: the tap config carries an
	// ipv6_subnet, so ADD's ipamResult.IPv6Subnet is non-nil and cmdAdd
	// takes the EndpointSlice-publish branch, which requires
	// nadpatch.ParsePodName(args.Args) to resolve a real K8S_POD_NAME —
	// Multus always sets this on a real invocation, so this mirrors that
	// rather than exercising a standalone/manual-chain invocation the way
	// the tap step above deliberately does for AnnotateNAD/VerifyChainComplete.
	bgpScript := `#!/bin/sh
CNI_NETNS=/var/run/netns/e2e-tap-ns \
CNI_COMMAND=$1 \
CNI_CONTAINERID=e2e-tap-001 \
CNI_IFNAME=eth0 \
CNI_PATH=/ \
CNI_ARGS="K8S_POD_NAME=` + podName + `;K8S_POD_NAMESPACE=` + podNamespace + `" \
NODE_NAME=` + nodeName() + ` \
	/galactic-bgp < /tmp/cni-bgp.json
`
	_, err = kubectl(t.Context(), "exec", podName, "--",
		"sh", "-c",
		"echo '"+bgpConf+"' > /tmp/cni-bgp.json && "+
			"echo '"+bgpScript+"' > /tmp/run-bgp.sh && "+
			"chmod +x /tmp/run-bgp.sh",
	)
	if err != nil {
		t.Fatalf("write galactic-bgp config and script: %v", err)
	}

	addOut, err := kubectl(t.Context(), "exec", podName, "-i", "--", "/tmp/run-bgp.sh", "ADD")
	if err != nil {
		t.Fatalf("galactic-bgp ADD failed: %v\noutput: %s", err, addOut)
	}

	// galactic-bgp is the last plugin in the chain: its own result is
	// prevResult passed through unchanged, not a new one it builds itself.
	// Decode only the first JSON value so trailing log lines are ignored.
	var bgpResult map[string]any
	if jsonStart := strings.Index(addOut, "{"); jsonStart == -1 {
		t.Fatalf("no JSON found in galactic-bgp ADD output:\n%s", addOut)
	} else if err := json.NewDecoder(strings.NewReader(addOut[jsonStart:])).Decode(&bgpResult); err != nil {
		t.Fatalf("galactic-bgp ADD output is not valid JSON: %v\noutput:\n%s", err, addOut)
	}
	if bgpIfaces, _ := bgpResult["interfaces"].([]any); len(bgpIfaces) != 1 {
		t.Errorf("galactic-bgp ADD result interfaces count = %d, want 1 (passed through from prevResult unchanged)",
			len(bgpIfaces))
	}

	if out, err := kubectl(t.Context(), "get", "bgpvrfinstance", vrfCRDName); err != nil {
		t.Errorf("BGPVRFInstance %s not found after galactic-bgp ADD: %v\n%s", vrfCRDName, err, out)
	}
	if out, err := kubectl(t.Context(), "get", "bgpadvertisement", advCRDName); err != nil {
		t.Errorf("BGPAdvertisement %s not found after galactic-bgp ADD: %v\n%s", advCRDName, err, out)
	}

	// CHECK reads back the locator_table/function_table/vrf_table entries
	// registerEBPFDatapath wrote on ADD (see ops_check.go's checkEBPFEntry)
	// — its success is this test's assertion that eBPF registration
	// actually happened, not just that the CRDs exist.
	if checkOut, err := kubectl(t.Context(), "exec", podName, "-i", "--", "/tmp/run-bgp.sh", "CHECK"); err != nil {
		t.Errorf("galactic-bgp CHECK failed: %v\noutput: %s", err, checkOut)
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

// podNamespaceOf returns the namespace of an already-created pod, by
// asking the API rather than assuming it — this suite never passes
// --namespace to kubectl, so the pod actually landed in whatever namespace
// the ambient kubectl context defaults to (scripts/ci.sh points that at
// galactic-system, but nothing here should hard-code that).
func podNamespaceOf(t *testing.T, podName string) string {
	t.Helper()
	out, err := kubectl(t.Context(), "get", "pod", podName, "-o", "jsonpath={.metadata.namespace}")
	if err != nil {
		t.Fatalf("get namespace of pod %s: %v\n%s", podName, err, out)
	}
	return out
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
