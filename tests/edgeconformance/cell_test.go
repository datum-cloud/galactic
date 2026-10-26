// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
	bootToRef(node string, boot time.Duration) (time.Duration, error)
	// versions returns what the run ran against, for the summary.
	versions() map[string]string
	// checkClocks measures how far apart the clocks behind the reference
	// clock are, for the summary, and fails when a cross-node comparison
	// could be off by more than clockTolerance.
	checkClocks() (map[string]string, error)
}

// run runs a cell's command and returns its trimmed output.
func run(c cell, node string, args ...string) (string, error) {
	out, err := c.command(node, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v: %w: %s", role(node), args, err, out)
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

func (kindCell) bootToRef(_ string, boot time.Duration) (time.Duration, error) { return boot, nil }

// checkClocks has nothing to measure: every Kind node reads the host's
// clock.
func (kindCell) checkClocks() (map[string]string, error) { return nil, nil }

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
// so cross-node comparisons rest on the nodes' time synchronization, which
// checkClocks measures at the start and end of the run.
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
			return fmt.Errorf("copy edgeprobe to %s: %w", role(n), err)
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
		return 0, fmt.Errorf("pod %s/%s is on %s, not %s", namespace, name, role(pod.Spec.NodeName), role(node))
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

func (c *clusterCell) bootToRef(node string, boot time.Duration) (time.Duration, error) {
	var err error
	// A node's pod can be briefly out of reach, as right after its node
	// rejoins, so a failed read is retried before the row fails.
	for range 5 {
		var s clockSample
		if s, err = c.sample(node); err == nil {
			return boot + s.offset, nil
		}
		time.Sleep(2 * time.Second)
	}
	return 0, fmt.Errorf("read the clocks of %s: %w", role(node), err)
}

// sample returns a recent reading of node's clocks.
func (c *clusterCell) sample(node string) (clockSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.offsets[node]; ok && time.Since(s.at) < clockTTL {
		return s, nil
	}
	s, err := c.readClock(node)
	if err != nil {
		return clockSample{}, err
	}
	if c.offsets == nil {
		c.offsets = map[string]clockSample{}
	}
	c.offsets[node] = s
	return s, nil
}

// forget drops node's cached clock reading, which a reboot invalidates:
// CLOCK_BOOTTIME restarts from zero.
func (c *clusterCell) forget(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.offsets, node)
}

// readClock reads node's clocks through its node pod.
func (c *clusterCell) readClock(node string) (clockSample, error) {
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
	return clockSample{at: after, offset: time.Duration(r.Real - r.Boot), rtt: after.Sub(before),
		skew: time.Duration(r.Real - mid.UnixNano())}, nil
}

// clockPort is the UDP port edgeprobe clockserve answers on, in an edge
// node's host network namespace.
const clockPort = 7779

// clockDiff is one clock's offset from another and the uncertainty of the
// measurement: half the round trip of the exchange that measured it.
type clockDiff struct{ offset, uncertainty time.Duration }

func (d clockDiff) String() string { return fmt.Sprintf("%v ±%v", d.offset, d.uncertainty) }

// worst is the largest difference between the two clocks the measurement
// allows.
func (d clockDiff) worst() time.Duration { return max(d.offset, -d.offset) + d.uncertainty }

// checkClocks measures each edge node's realtime against the compute
// node's, over the nodes' own network, and the runner's against each
// node's, over kubectl exec.
//
// Probe events, lease renew-starts and API timestamps come from the nodes,
// so a pair of nodes fails when the measurement allows them to be further
// apart than clockTolerance. The runner's own instants only mark when it
// sent a command through kubectl exec, which delays it by about as much as
// the measurement's uncertainty, so the runner fails only when it is
// certainly further than clockTolerance from a node.
func (c *clusterCell) checkClocks() (map[string]string, error) {
	v := map[string]string{}
	var errs []error
	edges := map[string]clockDiff{}
	for _, n := range []string{edgeNode1, edgeNode2} {
		d, err := c.pingClock(n)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		edges[n] = d
		v["clock/"+role(n)+"-vs-compute"] = d.String()
		if d.worst() > clockTolerance {
			errs = append(errs, fmt.Errorf("%s's clock is %v from compute's, beyond %v", role(n), d, clockTolerance))
		}
	}
	if d1, ok := edges[edgeNode1]; ok {
		if d2, ok := edges[edgeNode2]; ok {
			d := clockDiff{d1.offset - d2.offset, d1.uncertainty + d2.uncertainty}
			v["clock/edge-1-vs-edge-2"] = d.String()
			if d.worst() > clockTolerance {
				errs = append(errs, fmt.Errorf("the edge nodes' clocks are %v apart, beyond %v", d, clockTolerance))
			}
		}
	}
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		var best clockSample
		for i := range 5 {
			s, err := c.readClock(n)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if i == 0 || s.rtt < best.rtt {
				best = s
			}
		}
		if best.at.IsZero() {
			continue
		}
		d := clockDiff{best.skew, best.rtt / 2}
		v["clock/"+role(n)+"-vs-runner"] = d.String()
		if max(d.offset, -d.offset)-d.uncertainty > clockTolerance {
			errs = append(errs, fmt.Errorf("%s's clock is %v from the runner's, beyond %v", role(n), d,
				clockTolerance))
		}
	}
	return v, errors.Join(errs...)
}

// pingClock measures node's realtime against the compute node's: node
// answers with edgeprobe clockserve on its host network, and the compute
// node asks it with edgeprobe clockping.
func (c *clusterCell) pingClock(node string) (clockDiff, error) {
	var n corev1.Node
	if err := c.l.c.Get(context.Background(), client.ObjectKey{Name: node}, &n); err != nil {
		return clockDiff{}, err
	}
	var addr netip.Addr
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			if ip, err := netip.ParseAddr(a.Address); err == nil {
				addr = ip
				break
			}
		}
	}
	if !addr.IsValid() {
		return clockDiff{}, fmt.Errorf("%s has no internal address", role(node))
	}
	srv := c.command(node, probePath, "clockserve", "-port", strconv.Itoa(clockPort), "-duration", "10s")
	if err := srv.Start(); err != nil {
		return clockDiff{}, err
	}
	defer func() { _ = srv.Wait() }()
	// kubectl exec takes a moment to start the server.
	time.Sleep(2 * time.Second)
	out, err := run(c, computeNode, probePath, "clockping", "-to",
		netip.AddrPortFrom(addr, clockPort).String(), "-count", "20")
	if err != nil {
		return clockDiff{}, fmt.Errorf("compare %s's clock with compute's over UDP port %d: %w", role(node),
			clockPort, err)
	}
	var r struct{ Offset, RTT int64 }
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return clockDiff{}, fmt.Errorf("%w: %s", err, out)
	}
	return clockDiff{time.Duration(r.Offset), time.Duration(r.RTT / 2)}, nil
}

func (c *clusterCell) versions() map[string]string {
	v := map[string]string{}
	ctx := context.Background()
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		var node corev1.Node
		if err := c.l.c.Get(ctx, client.ObjectKey{Name: n}, &node); err == nil {
			i := node.Status.NodeInfo
			v["node/"+role(n)] = fmt.Sprintf("os=%q kernel=%s runtime=%s kubelet=%s", i.OSImage, i.KernelVersion,
				i.ContainerRuntimeVersion, i.KubeletVersion)
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
			where := role(p.Spec.NodeName)
			if !underTest(p.Spec.NodeName) {
				where = "cell"
			}
			for _, cs := range p.Status.ContainerStatuses {
				v["image/"+where+"/"+ns+"/"+cs.Name] = cs.ImageID
			}
		}
	}
	return v
}

// underTest reports whether node is one of the nodes under test.
func underTest(node string) bool {
	return node == computeNode || node == edgeNode1 || node == edgeNode2
}

// versionedPod reports whether p runs a component whose version the
// summary records: the core on the nodes under test, Cilium, and the
// providers.
func versionedPod(p corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	if !underTest(p.Spec.NodeName) {
		return strings.HasPrefix(p.Name, "galactic-controller-")
	}
	for _, prefix := range []string{"galactic-", "cilium-", "edge-provider-", "fabric-router-"} {
		if strings.HasPrefix(p.Name, prefix) && !strings.HasPrefix(p.Name, "cilium-operator") {
			return true
		}
	}
	return false
}
