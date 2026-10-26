// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// probePath is where edgeprobe is installed on every node under test.
const probePath = "/usr/local/bin/edgeprobe"

// cell is how the suite reaches the cell's nodes and keeps time.
//
// Every time the suite compares is a duration on one reference clock. A
// cell converts each node's CLOCK_BOOTTIME readings (probe events, a
// lease's renew-start) and wall-clock instants (API timestamps) to it.
type cell interface {
	// command returns a command that runs args on node in the node's host
	// network and PID namespaces, where edgeprobe is at probePath.
	command(node string, args ...string) *exec.Cmd
	// install copies the edgeprobe binary at bin onto every node.
	install(bin string) error
	// containerPID returns the host PID of a pod's container, or of a
	// process sharing the pod's network namespace when container is "".
	containerPID(node, namespace, pod, container string) (int, error)
	// now is the current time on the reference clock.
	now() time.Duration
	// wallToRef converts a wall-clock instant to the reference clock.
	wallToRef(w time.Time) time.Duration
	// bootToRef converts a CLOCK_BOOTTIME reading taken on node to the
	// reference clock.
	bootToRef(node string, boot time.Duration) time.Duration
	// versions returns what the run ran against, for the summary.
	versions() map[string]string
}

// run runs a cell's command and returns its trimmed output.
func run(c cell, node string, args ...string) (string, error) {
	out, err := c.command(node, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v: %w: %s", node, args, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// kindCell is the containerlab lab's Kind cluster. Its nodes are
// containers on one host, so they share the host's kernel and its
// CLOCK_BOOTTIME, which is the reference clock.
type kindCell struct{}

func (kindCell) command(node string, args ...string) *exec.Cmd {
	return exec.CommandContext(context.Background(), "docker", append([]string{"exec", node}, args...)...)
}

func (kindCell) install(bin string) error {
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		cp := exec.CommandContext(context.Background(), "docker", "cp", bin, n+":"+probePath)
		if out, err := cp.CombinedOutput(); err != nil {
			return fmt.Errorf("copy edgeprobe to %s: %w: %s", n, err, out)
		}
	}
	return nil
}

func (k kindCell) containerPID(node, namespace, pod, container string) (int, error) {
	sb, err := run(k, node, "crictl", "pods", "--namespace", namespace, "--name", pod, "--state", "ready", "-q")
	if err != nil {
		return 0, err
	}
	ids := strings.Fields(sb)
	if len(ids) != 1 {
		return 0, fmt.Errorf("pod %s/%s has %d ready sandboxes on %s", namespace, pod, len(ids), node)
	}
	if container == "" {
		pid, err := run(k, node, "crictl", "inspectp", "-o", "go-template", "--template", "{{.info.pid}}", ids[0])
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(pid)
	}
	id, err := run(k, node, "crictl", "ps", "--pod", ids[0], "--name", container, "--state", "running", "-q")
	if err != nil {
		return 0, err
	}
	if id == "" {
		return 0, fmt.Errorf("container %s of %s/%s is not running", container, namespace, pod)
	}
	pid, err := run(k, node, "crictl", "inspect", "-o", "go-template", "--template", "{{.info.pid}}",
		strings.Fields(id)[0])
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(pid)
}

func (kindCell) now() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		panic(err)
	}
	return time.Duration(ts.Nano())
}

func (k kindCell) wallToRef(w time.Time) time.Duration { return k.now() - time.Since(w) }

func (kindCell) bootToRef(_ string, boot time.Duration) time.Duration { return boot }

func (kindCell) versions() map[string]string {
	images := map[string]string{}
	for _, img := range []string{"galactic-edge:latest", "galactic-controller:latest", "galactic-router:latest",
		"galactic-cni:latest", "edge-provider:latest"} {
		id, _ := exec.CommandContext(context.Background(), "docker", "image", "inspect", "--format", "{{.Id}}",
			img).Output()
		images[img] = strings.TrimSpace(string(id))
	}
	return images
}

// clusterCell is a cell of real nodes, such as the target Talos/Cilium
// environment. It reaches each node through the fixture's privileged
// edge-conformance-node pod there (talos_test.go), and its reference clock
// is wall time: each node's CLOCK_BOOTTIME is mapped to its own wall clock,
// so cross-node comparisons rest on the nodes' time synchronization, whose
// observed offsets the summary records.
type clusterCell struct {
	l *lab

	mu      sync.Mutex
	offsets map[string]clockSample
}

// clockSample is one reading of a node's two clocks.
type clockSample struct {
	at     time.Time
	offset time.Duration // realtime - boottime on the node
	skew   time.Duration // node realtime - this host's, at the read's midpoint
	rtt    time.Duration
}

// clockTTL bounds how long a node's clock offset is reused; NTP slews a
// node's realtime against its boottime, by at most 500 ppm.
const clockTTL = 30 * time.Second

func (c *clusterCell) command(node string, args ...string) *exec.Cmd {
	pod, err := c.l.toolPod(node)
	if err != nil {
		// Fail at Run with the reason.
		return exec.CommandContext(context.Background(), "false", err.Error())
	}
	return exec.CommandContext(context.Background(), "kubectl",
		append([]string{"--kubeconfig", c.l.kubeconfig, "exec", "-n", toolNamespace, pod, "--"}, args...)...)
}

func (c *clusterCell) install(bin string) error {
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		pod, err := c.l.toolPod(n)
		if err != nil {
			return err
		}
		if _, err := c.l.kubectl("cp", bin, toolNamespace+"/"+pod+":"+probePath); err != nil {
			return fmt.Errorf("copy edgeprobe to %s: %w", n, err)
		}
		if _, err := run(c, n, "chmod", "0755", probePath); err != nil {
			return err
		}
	}
	return nil
}

func (c *clusterCell) containerPID(node, namespace, name, container string) (int, error) {
	var pod corev1.Pod
	if err := c.l.c.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return 0, err
	}
	if pod.Spec.NodeName != node {
		return 0, fmt.Errorf("pod %s/%s is on %s, not %s", namespace, name, pod.Spec.NodeName, node)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if (container == "" || cs.Name == container) && cs.State.Running != nil && cs.ContainerID != "" {
			_, id, _ := strings.Cut(cs.ContainerID, "://")
			out, err := run(c, node, probePath, "pid", "-container", id)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(out)
		}
	}
	return 0, fmt.Errorf("container %q of %s/%s is not running", container, namespace, name)
}

func (*clusterCell) now() time.Duration { return time.Duration(time.Now().UnixNano()) }

func (*clusterCell) wallToRef(w time.Time) time.Duration { return time.Duration(w.UnixNano()) }

func (c *clusterCell) bootToRef(node string, boot time.Duration) time.Duration {
	s, err := c.sample(node)
	if err != nil {
		panic(fmt.Sprintf("read the clocks of %s: %v", node, err))
	}
	return boot + s.offset
}

// sample returns a recent reading of node's clocks.
func (c *clusterCell) sample(node string) (clockSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.offsets[node]; ok && time.Since(s.at) < clockTTL {
		return s, nil
	}
	before := time.Now()
	out, err := run(c, node, probePath, "clock")
	after := time.Now()
	if err != nil {
		return clockSample{}, err
	}
	var r struct{ Boot, Real int64 }
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return clockSample{}, fmt.Errorf("%w: %s", err, out)
	}
	mid := before.Add(after.Sub(before) / 2)
	s := clockSample{at: after, offset: time.Duration(r.Real - r.Boot), rtt: after.Sub(before),
		skew: time.Duration(r.Real - mid.UnixNano())}
	if c.offsets == nil {
		c.offsets = map[string]clockSample{}
	}
	c.offsets[node] = s
	return s, nil
}

func (c *clusterCell) versions() map[string]string {
	v := map[string]string{}
	ctx := context.Background()
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		var node corev1.Node
		if err := c.l.c.Get(ctx, client.ObjectKey{Name: n}, &node); err == nil {
			i := node.Status.NodeInfo
			v["node/"+n] = fmt.Sprintf("os=%q kernel=%s runtime=%s kubelet=%s", i.OSImage, i.KernelVersion,
				i.ContainerRuntimeVersion, i.KubeletVersion)
		}
		if s, err := c.sample(n); err == nil {
			v["clock/"+n] = fmt.Sprintf("realtime %v from this host's, read in %v", s.skew, s.rtt)
		}
	}
	var pods corev1.PodList
	for _, ns := range []string{systemNamespace, "kube-system", tenantA.namespace, tenantB.namespace} {
		if err := c.l.c.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			continue
		}
		for _, p := range pods.Items {
			if !versionedPod(p) {
				continue
			}
			for _, cs := range p.Status.ContainerStatuses {
				v["image/"+ns+"/"+cs.Name] = cs.ImageID
			}
		}
	}
	return v
}

// versionedPod reports whether p runs a component whose version the
// summary records: the core on the nodes under test, Cilium, and the
// providers.
func versionedPod(p corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	switch p.Spec.NodeName {
	case computeNode, edgeNode1, edgeNode2:
	default:
		return strings.HasPrefix(p.Name, "galactic-controller-")
	}
	for _, prefix := range []string{"galactic-", "cilium-", "edge-provider-", "fabric-router-"} {
		if strings.HasPrefix(p.Name, prefix) && !strings.HasPrefix(p.Name, "cilium-operator") {
			return true
		}
	}
	return false
}
