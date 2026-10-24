// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package e2e_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// edgeTestBinaryDir is the node directory scripts/ci.sh copies the compiled
// internal/edge/hostattach test binary into.
const edgeTestBinaryDir = "/opt/galactic-e2e"

// TestEdgeAgentCreatesTUN runs hostattach's TUN creation in the galactic-edge
// container exactly as config/galactic-edge/base defines it, replacing only
// the program, so a device or permission the shipped DaemonSet lacks fails
// here. Without the DaemonSet's /dev/net/tun volume the same container must
// fail, which shows the test exercises the device the manifest provides.
func TestEdgeAgentCreatesTUN(t *testing.T) {
	ds := renderEdgeDaemonSet(t)

	t.Run("shipped", func(t *testing.T) {
		phase, logs := runEdgeTUNPod(t, "e2e-edge-tun", ds.Spec.Template.Spec)
		// A binary whose -test.run matches nothing also exits 0.
		if phase != string(corev1.PodSucceeded) || !strings.Contains(logs, "--- PASS: TestContainerCreateTUN") {
			t.Fatalf("TUN creation failed in the shipped galactic-edge container (phase %s):\n%s", phase, logs)
		}
	})

	t.Run("without device", func(t *testing.T) {
		spec := *ds.Spec.Template.Spec.DeepCopy()
		spec.Volumes = slices.DeleteFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == "tun" })
		c := &spec.Containers[0]
		c.VolumeMounts = slices.DeleteFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == "tun" })
		phase, logs := runEdgeTUNPod(t, "e2e-edge-tun-nodev", spec)
		if phase != string(corev1.PodFailed) || !strings.Contains(logs, "create TUN: no such file or directory") {
			t.Fatalf("phase %s, want Failed with a missing /dev/net/tun:\n%s", phase, logs)
		}
	})
}

// renderEdgeDaemonSet renders the shipped galactic-edge DaemonSet.
func renderEdgeDaemonSet(t *testing.T) *appsv1.DaemonSet {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "kubectl", "kustomize", "../../config/galactic-edge/base").Output()
	if err != nil {
		t.Fatalf("kubectl kustomize config/galactic-edge/base: %v", err)
	}
	var ds appsv1.DaemonSet
	if err := yaml.Unmarshal(out, &ds); err != nil {
		t.Fatalf("parse galactic-edge DaemonSet: %v", err)
	}
	if ds.Kind != "DaemonSet" || len(ds.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("config/galactic-edge/base rendered %s with %d containers, want one DaemonSet container",
			ds.Kind, len(ds.Spec.Template.Spec.Containers))
	}
	return &ds
}

// runEdgeTUNPod runs TestContainerCreateTUN in a pod built from spec and
// returns the pod's final phase and its logs. The pod keeps spec's security
// context, host networking and volumes; it drops what only selects or serves
// the real agent (placement, identity, probes) and runs the test binary from
// the node through a read-only mount.
func runEdgeTUNPod(t *testing.T, name string, spec corev1.PodSpec) (string, string) {
	t.Helper()
	deletePod(t, name)
	t.Cleanup(func() { deletePod(t, name) })

	spec = *spec.DeepCopy()
	spec.Affinity = nil
	spec.ServiceAccountName = ""
	spec.RestartPolicy = corev1.RestartPolicyNever
	spec.Volumes = append(spec.Volumes, corev1.Volume{
		Name: "e2e-bin",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
			Path: edgeTestBinaryDir, Type: ptr(corev1.HostPathDirectory),
		}},
	})
	c := &spec.Containers[0]
	c.Image = image()
	c.ImagePullPolicy = corev1.PullNever
	c.Command = []string{"/e2e/hostattach.test", "-test.run=^TestContainerCreateTUN$", "-test.v"}
	c.Args = nil
	c.Env = append(c.Env, corev1.EnvVar{Name: "GALACTIC_EDGE_CONTAINER_TUN", Value: "1"})
	c.LivenessProbe, c.ReadinessProbe = nil, nil
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "e2e-bin", MountPath: "/e2e", ReadOnly: true})

	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	manifest, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply %s: %v\n%s", name, err, out)
	}

	deadline := time.Now().Add(podReadyTimeout)
	phase := ""
	for time.Now().Before(deadline) {
		phase, _ = kubectl(t.Context(), "get", "pod", name, "-o", "jsonpath={.status.phase}")
		if phase == string(corev1.PodSucceeded) || phase == string(corev1.PodFailed) {
			logs, _ := kubectl(t.Context(), "logs", name)
			return phase, logs
		}
		time.Sleep(podPollInterval)
	}
	desc, _ := kubectl(t.Context(), "describe", "pod", name)
	t.Fatalf("pod %s did not finish within %v (phase %q):\n%s", name, podReadyTimeout, phase, desc)
	return "", ""
}

func ptr[T any](v T) *T { return &v }
