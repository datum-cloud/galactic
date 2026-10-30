// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeconformance_test is the Galactic Edge provider conformance
// suite. It runs the failure-test matrix of the provider contract
// (docs/enhancements/networking/galactic-edge/contract.md) against a cell
// running fixed core artifacts, with providers built outside the core: the
// reference provider in examples/edge-provider, deployed from its checked-in
// kustomizations, and pods acting under a provider's ServiceAccount through
// pod-bound tokens for the cases a well-behaved provider never produces.
//
// It drives the containerlab lab's dfw cluster (deploy/containerlab,
// task deploy:galactic-edge) and skips unless EDGE_CONFORMANCE_KUBECONFIG
// names that cluster's kubeconfig. Node-level steps (signals, packet probes)
// run through docker exec on the Kind node containers, which share the host's
// kernel and so its CLOCK_BOOTTIME: every timing is measured on that clock,
// the one leases are timed on. Run it with task verify:edge-conformance.
package edgeconformance_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// lab is the cell under test.
type lab struct {
	kubeconfig string
	rest       *rest.Config
	c          client.Client
	cs         kubernetes.Interface
	scheme     *runtime.Scheme
	root       string
	artifacts  string
	probeBin   string
}

var (
	theLab     *lab
	labOnce    sync.Once
	errLabInit error
	skipReason string
)

// getLab returns the lab, or skips the test when the suite is not pointed
// at one.
func getLab(t *testing.T) *lab {
	t.Helper()
	labOnce.Do(func() {
		kc := os.Getenv("EDGE_CONFORMANCE_KUBECONFIG")
		if kc == "" {
			skipReason = "EDGE_CONFORMANCE_KUBECONFIG is not set; run task verify:edge-conformance"
			return
		}
		theLab, errLabInit = newLab(kc)
	})
	if skipReason != "" {
		t.Skip(skipReason)
	}
	if errLabInit != nil {
		t.Fatal(errLabInit)
	}
	return theLab
}

func newLab(kubeconfig string) (*lab, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, authv1.AddToScheme,
		rbacv1.AddToScheme,
		coordinationv1.AddToScheme, galacticv1alpha1.AddToScheme, cloudv1alpha1.AddToScheme,
		networkv1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		return nil, err
	}
	artifacts := os.Getenv("EDGE_CONFORMANCE_ARTIFACTS")
	if artifacts == "" {
		artifacts = filepath.Join(root, "bin", "edge-conformance")
	}
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		return nil, err
	}
	l := &lab{kubeconfig: kubeconfig, rest: cfg, c: c, cs: cs, scheme: s, root: root, artifacts: artifacts}
	if err := l.installProbe(); err != nil {
		return nil, err
	}
	return l, nil
}

// installProbe builds edgeprobe and copies it onto every dfw node.
func (l *lab) installProbe() error {
	l.probeBin = filepath.Join(l.artifacts, "edgeprobe")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", l.probeBin, "./tests/edgeconformance/edgeprobe")
	cmd.Dir, cmd.Env = l.root, append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build edgeprobe: %w: %s", err, out)
	}
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		cp := exec.CommandContext(context.Background(), "docker", "cp", l.probeBin, n+":/usr/local/bin/edgeprobe")
		if out, err := cp.CombinedOutput(); err != nil {
			return fmt.Errorf("copy edgeprobe to %s: %w: %s", n, err, out)
		}
	}
	return nil
}

// The dfw nodes: one compute node and the two edge nodes running galactic-edge.
const (
	computeNode = "dfw-worker"
	edgeNode1   = "dfw-worker2"
	edgeNode2   = "dfw-worker3"
)

// boottime reads the host's CLOCK_BOOTTIME, which every Kind node shares.
func boottime() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		panic(err)
	}
	return time.Duration(ts.Nano())
}

// wallToBoot converts a wall-clock instant to CLOCK_BOOTTIME.
func wallToBoot(w time.Time) time.Duration {
	return boottime() - time.Since(w)
}

// nodeExec runs a command in a node container.
func nodeExec(node string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "docker", append([]string{execVerb, node}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v: %w: %s", node, args, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// sandboxPID returns the PID of the pod's sandbox, whose network namespace
// is the pod's.
func sandboxPID(node, namespace, pod string) (int, error) {
	id, err := nodeExec(node, "crictl", "pods", "--namespace", namespace, "--name", pod, "--state", "ready", "-q")
	if err != nil {
		return 0, err
	}
	ids := strings.Fields(id)
	if len(ids) != 1 {
		return 0, fmt.Errorf("pod %s/%s has %d ready sandboxes on %s", namespace, pod, len(ids), node)
	}
	pid, err := nodeExec(node, "crictl", "inspectp", "-o", "go-template", "--template", "{{.info.pid}}", ids[0])
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(pid)
}

// containerPID returns the PID of a pod's running container.
func containerPID(node, namespace, pod, container string) (int, error) {
	sb, err := nodeExec(node, "crictl", "pods", "--namespace", namespace, "--name", pod, "--state", "ready", "-q")
	if err != nil {
		return 0, err
	}
	id, err := nodeExec(node, "crictl", "ps", "--pod", strings.TrimSpace(sb), "--name", container,
		"--state", "running", "-q")
	if err != nil {
		return 0, err
	}
	if id == "" {
		return 0, fmt.Errorf("container %s of %s/%s is not running", container, namespace, pod)
	}
	pid, err := nodeExec(node, "crictl", "inspect", "-o", "go-template", "--template", "{{.info.pid}}",
		strings.Fields(id)[0])
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(pid)
}

// signal sends sig to a pod's container from its node.
func signal(node, namespace, pod, container, sig string) error {
	pid, err := containerPID(node, namespace, pod, container)
	if err != nil {
		return err
	}
	_, err = nodeExec(node, "kill", "-"+sig, strconv.Itoa(pid))
	return err
}

// event is one line edgeprobe prints.
type event struct {
	T     time.Duration `json:"t"`
	Seq   int           `json:"seq"`
	From  string        `json:"from"`
	Reply string        `json:"reply"`
	Src   string        `json:"src"`
	Dst   string        `json:"dst"`
	Sent  int           `json:"sent"`
	End   bool          `json:"end"`
	// ID is a captured ICMPv6 echo request's identifier.
	ID int `json:"id"`
	// Status, Proto and Assigned are a CONNECT-IP request's response
	// status, the ALPN protocol its connection negotiated (h3 or h2) and
	// its assigned prefix.
	Status   int    `json:"status"`
	Proto    string `json:"proto"`
	Assigned string `json:"assigned"`
	// Len is the size of a packet a CONNECT-IP tunnel delivered.
	Len int `json:"len"`
	// Error is why a CONNECT-IP tunnel or a capture ended.
	Error string `json:"error"`
	// Paths is how many routes for a prefix a router's RIB held.
	Paths *int `json:"paths"`
}

// last reports whether e marks the end of a probe's window: a send probe's
// count or a capture's end.
func (e event) last() bool { return e.End || e.Sent > 0 }

// probeRun is an edgeprobe running in a pod's network namespace.
type probeRun struct {
	cmd *exec.Cmd
	out bytes.Buffer
	// stderr holds what the probe wrote to its standard error, which is
	// also passed on to the test's.
	stderr bytes.Buffer
	name   string
	events []event
}

// nsenter enters a pod's namespaces from its node.
const nsenter = "nsenter"

// execVerb is the exec subcommand of docker and kubectl.
const execVerb = "exec"

// otherReply marks a packet a CONNECT-IP tunnel delivered that is not an
// echo reply to the probe.
const otherReply = "other"

// startProbe runs edgeprobe with args in the network namespace of the pod
// whose sandbox has pid on node.
func startProbe(node string, pid int, name string, args ...string) (*probeRun, error) {
	full := append([]string{execVerb, node, nsenter, "-t", strconv.Itoa(pid), "-n", "/usr/local/bin/edgeprobe"},
		args...)
	p := &probeRun{cmd: exec.CommandContext(context.Background(), "docker", full...), name: name}
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = io.MultiWriter(os.Stderr, &p.stderr)
	return p, p.cmd.Start()
}

// wait waits for the probe and parses its events, saving them as an
// artifact.
func (p *probeRun) wait(l *lab, t *testing.T) []event {
	t.Helper()
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("probe %s: %v", p.name, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(p.out.Bytes()))
	for sc.Scan() {
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("probe %s: %v: %s", p.name, err, sc.Text())
		}
		p.events = append(p.events, e)
	}
	l.save(t, p.name+".jsonl", p.out.Bytes())
	return p.events
}

// save writes an artifact for the running test.
func (l *lab) save(t *testing.T, name string, b []byte) {
	t.Helper()
	dir := filepath.Join(l.artifacts, strings.ReplaceAll(t.Name(), "/", "_"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// record logs a measurement and saves it with the run's results.
func (l *lab) record(t *testing.T, what string, v any) {
	t.Helper()
	t.Logf("%s: %v", what, v)
	results.Lock()
	defer results.Unlock()
	results.m[t.Name()+": "+what] = fmt.Sprint(v)
}

var results = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

// kubectl runs kubectl against the lab.
func (l *lab) kubectl(args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "kubectl", append([]string{"--kubeconfig", l.kubeconfig}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %v: %w: %s", args, err, out)
	}
	return string(out), nil
}

// eventually polls cond every interval until it holds or timeout passes.
func eventually(t *testing.T, timeout, interval time.Duration, what string, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		ok, err := cond()
		if ok {
			return
		}
		last = err
		time.Sleep(interval)
	}
	t.Fatalf("timed out after %v waiting for %s (last error: %v)", timeout, what, last)
}

// asPod is a client that acts as pod under its ServiceAccount, through a
// token bound to the pod: the identity the contract's admission policies
// check.
func (l *lab) asPod(t *testing.T, pod *corev1.Pod) client.Client {
	t.Helper()
	tr, err := l.cs.CoreV1().ServiceAccounts(pod.Namespace).CreateToken(context.Background(),
		pod.Spec.ServiceAccountName, &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: ptr.To[int64](3600),
			BoundObjectRef:    &authv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: pod.Name, UID: pod.UID},
		}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := rest.AnonymousClientConfig(l.rest)
	cfg.BearerToken = tr.Status.Token
	c, err := client.New(cfg, client.Options{Scheme: l.scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tokenPod starts a pause pod under a provider's ServiceAccount on node,
// for acting as a provider pod that does not run the provider.
func (l *lab) tokenPod(t *testing.T, namespace, name, node string) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			ServiceAccountName: "edge-provider",
			NodeSelector:       map[string]string{"kubernetes.io/hostname": node},
			Tolerations:        []corev1.Toleration{edgeTaint},
			Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10",
				ImagePullPolicy: corev1.PullIfNotPresent}},
		},
	}
	ctx := context.Background()
	if err := l.c.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	eventually(t, 2*time.Minute, time.Second, "token pod "+name+" running", func() (bool, error) {
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	return pod
}
