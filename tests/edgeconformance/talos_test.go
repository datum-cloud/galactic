// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
)

// The talos target's fixture. Everything it creates carries fixtureLabel,
// which task test:edge-conformance:talos:clean deletes by.
const (
	toolNamespace = "edge-conformance-system"
	fixtureLabel  = "app.kubernetes.io/part-of=galactic-edge-fixture"
	// clockTolerance is how far apart the cell's node clocks may be when
	// the suite compares a time taken on one node with one taken on
	// another; the summary records each node's observed offset.
	clockTolerance = 100 * time.Millisecond
)

// talosConfig is the talos target's configuration, read from the
// environment.
type talosConfig struct {
	// nodes are the compute node and the two edge nodes under test.
	nodes [3]string
	// providerImage is the reference provider's image, by digest.
	providerImage string
	// toolImage runs the fixture's node pods and tenant clients, by
	// digest; it needs sh, nsenter, nft, ip, kill and tar.
	toolImage string
}

func talosConfigFromEnv() (*talosConfig, error) {
	nodes := strings.Split(os.Getenv("EDGE_CONFORMANCE_NODES"), ",")
	if len(nodes) != 3 || nodes[0] == "" || nodes[1] == "" || nodes[2] == "" {
		return nil, errors.New("EDGE_CONFORMANCE_NODES must name the compute node and two edge nodes, " +
			"comma-separated")
	}
	c := &talosConfig{nodes: [3]string(nodes), providerImage: os.Getenv("EDGE_CONFORMANCE_PROVIDER_IMAGE"),
		toolImage: os.Getenv("EDGE_CONFORMANCE_TOOL_IMAGE")}
	for name, img := range map[string]string{"EDGE_CONFORMANCE_PROVIDER_IMAGE": c.providerImage,
		"EDGE_CONFORMANCE_TOOL_IMAGE": c.toolImage} {
		if !strings.Contains(img, "@sha256:") {
			return nil, fmt.Errorf("%s must name an image by digest, got %q", name, img)
		}
	}
	return c, nil
}

// apply points the suite at the configured nodes and the fixture's tenant
// namespaces.
func (c *talosConfig) apply() {
	computeNode, edgeNode1, edgeNode2 = c.nodes[0], c.nodes[1], c.nodes[2]
	tenantA.vpcNamespace = "edge-conformance-10"
	tenantB.vpcNamespace = "edge-conformance-20"
}

// toolsManifest is the fixture's privileged pod on every node under test:
// the suite runs node-level steps (probes, signals, nft, reboot) in it,
// through kubectl exec, in the node's network and PID namespaces.
var toolsManifest = template.Must(template.New("tools").Parse(`
apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/part-of: galactic-edge-fixture
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: edge-conformance-node
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/part-of: galactic-edge-fixture
spec:
  selector:
    matchLabels:
      app: edge-conformance-node
  template:
    metadata:
      labels:
        app: edge-conformance-node
        app.kubernetes.io/part-of: galactic-edge-fixture
    spec:
      hostNetwork: true
      hostPID: true
      terminationGracePeriodSeconds: 1
      tolerations:
        - operator: Exists
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: kubernetes.io/hostname
                    operator: In
                    values: [{{range .Nodes}}"{{.}}", {{end}}]
      containers:
        - name: tools
          image: {{.Image}}
          command: ["sleep", "infinity"]
          securityContext:
            privileged: true
`))

// deployTools applies the fixture's node pods and waits for one on each
// node under test.
func (l *lab) deployTools() error {
	var b bytes.Buffer
	if err := toolsManifest.Execute(&b, map[string]any{"Namespace": toolNamespace, "Image": l.talos.toolImage,
		"Nodes": l.talos.nodes}); err != nil {
		return err
	}
	if err := l.apply(b.String()); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Minute)
	for _, n := range l.talos.nodes {
		for {
			if _, err := l.toolPod(n); err == nil {
				break
			} else if time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

// toolPod returns the name of the fixture's running node pod on node.
func (l *lab) toolPod(node string) (string, error) {
	var pods corev1.PodList
	if err := l.c.List(context.Background(), &pods, client.InNamespace(toolNamespace),
		client.MatchingLabels{appLabel: "edge-conformance-node"}); err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == node && p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.Ready {
					return p.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no ready edge-conformance-node pod on %s", role(node))
}

// apply applies a manifest with kubectl.
func (l *lab) apply(manifest string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "--kubeconfig", l.kubeconfig, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl apply: %w: %s", err, out)
	}
	return nil
}

// tenantManifest is one of the fixture's tenants, which the lab's ns10 and
// ns20 provide there: a VPC holding the edge address space beside its own
// workload network, the lab's traffic policies, and one client workload on
// each node under test, each on its own VPCAttachment and policy binding.
// The VPC is each client's default network, so the client's default route
// is the VPC, as in the lab. The clients on the edge nodes also keep the
// VPC's host VRF there, which an edge attachment joins and never creates.
var tenantManifest = template.Must(template.New("tenant").Funcs(template.FuncMap{
	"inc": func(i int) int { return i + 1 },
}).Parse(`
apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/part-of: galactic-edge-fixture
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: VPC
metadata:
  name: "{{.VPC}}"
  namespace: {{.Namespace}}
spec:
  networks:
    - fd20:{{.VPC}}::/64
    - fd00:ed9e::/32
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: lab-egress
  namespace: {{.Namespace}}
spec:
  rules:
    - name: allow-private
      action: Allow
      match:
        path: Private
    - name: allow-nat
      action: Allow
      match:
        path: PublicNAT
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: lab-ingress
  namespace: {{.Namespace}}
spec:
  rules:
    - name: allow-private
      action: Allow
      match:
        path: Private
    - name: allow-nat-returns
      action: Allow
      match:
        path: PublicNAT
{{- range $i, $node := .Nodes}}
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: VPCAttachment
metadata:
  name: edge-client-{{inc $i}}
  namespace: {{$.Namespace}}
spec:
  vpc:
    name: "{{$.VPC}}"
  interface:
    name: eth0
    mode: Netns
    addresses:
      - fd20:{{$.VPC}}::{{inc $i}}:0:0/96
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicyBinding
metadata:
  name: edge-client-{{inc $i}}
  namespace: {{$.Namespace}}
spec:
  ingressPolicyRef:
    name: lab-ingress
  egressPolicyRef:
    name: lab-egress
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge-client-{{inc $i}}
  namespace: {{$.Namespace}}
  labels:
    app: edge-client-{{inc $i}}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: edge-client-{{inc $i}}
  template:
    metadata:
      labels:
        app: edge-client-{{inc $i}}
      annotations:
        v1.multus-cni.io/default-network: {{$.Namespace}}/edge-client-{{inc $i}}
    spec:
      nodeSelector:
        kubernetes.io/hostname: {{$node}}
      tolerations:
        - operator: Exists
      terminationGracePeriodSeconds: 1
      containers:
        - name: client
          image: {{$.Image}}
          command: ["sleep", "infinity"]
{{- end}}
`))

// deployTenants applies the fixture's two tenants and waits for their VPCs
// and clients.
func (l *lab) deployTenants(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, tn := range []tenant{tenantA, tenantB} {
		var b bytes.Buffer
		err := tenantManifest.Execute(&b, map[string]any{"Namespace": tn.vpcNamespace,
			"VPC": tn.vpc, "Nodes": l.talos.nodes, "Image": l.talos.toolImage})
		if err != nil {
			t.Fatal(err)
		}
		if err := l.apply(b.String()); err != nil {
			t.Fatal(err)
		}
		eventually(t, 5*time.Minute, 2*time.Second, "VPC "+tn.vpc+" identifier", func() (bool, error) {
			var v cloudv1alpha1.VPC
			if err := l.c.Get(ctx, client.ObjectKey{Namespace: tn.vpcNamespace, Name: tn.vpc}, &v); err != nil {
				return false, err
			}
			return v.Status.VPC != "", nil
		})
		for i, node := range l.talos.nodes {
			eventually(t, 5*time.Minute, 2*time.Second, "client "+strconv.Itoa(i+1)+" of "+tn.vpcNamespace,
				func() (bool, error) {
					var pods corev1.PodList
					if err := l.c.List(ctx, &pods, client.InNamespace(tn.vpcNamespace),
						client.MatchingLabels{appLabel: "edge-client-" + strconv.Itoa(i+1)}); err != nil {
						return false, err
					}
					for _, p := range pods.Items {
						if p.Spec.NodeName == node && p.Status.Phase == corev1.PodRunning {
							return true, nil
						}
					}
					return false, nil
				})
		}
	}
}

// teardownTalos deletes the fixture's tenants and node pods.
func (l *lab) teardownTalos(t *testing.T) {
	for _, ns := range []string{tenantA.vpcNamespace, tenantB.vpcNamespace, toolNamespace} {
		if _, err := l.kubectl("delete", "namespace", ns, "--ignore-not-found", "--wait=true",
			"--timeout=300s"); err != nil {
			t.Error(err)
		}
	}
}

// providerPatch is how the talos target runs the reference provider: from
// its published image, placed by the suite's node selector alone, since
// the fixture leaves the cell's node labels as they are.
func (l *lab) providerPatch() string {
	if l.talos == nil {
		return `      - op: add
        path: /spec/template/spec/containers/0/imagePullPolicy
        value: Never
` + tunPatch
	}
	return fmt.Sprintf(`      - op: replace
        path: /spec/template/spec/containers/0/image
        value: %s
      - op: remove
        path: /spec/template/spec/affinity
`, l.talos.providerImage)
}

// requireTalos skips a row the lab cannot host.
func requireTalos(t *testing.T, l *lab) {
	t.Helper()
	if l.talos == nil {
		t.Skip("needs the talos target: real nodes to isolate and reboot")
	}
}

// isolationTable is the nft table that cuts a network namespace off from
// the API server.
const isolationTable = "edgeconf_isolate"

// apiDestinations returns the nft rules that drop traffic to the API
// server: its endpoints, the kubernetes Service, and Talos's KubePrism.
func (l *lab) apiDestinations(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	var svc corev1.Service
	if err := l.c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "kubernetes"}, &svc); err != nil {
		t.Fatal(err)
	}
	var slices discoveryv1.EndpointSliceList
	if err := l.cs.DiscoveryV1().RESTClient().Get().Namespace("default").Resource("endpointslices").
		Param("labelSelector", "kubernetes.io/service-name=kubernetes").Do(ctx).Into(&slices); err != nil {
		t.Fatal(err)
	}
	type dst struct {
		addr netip.Addr
		port int32
	}
	var dsts []dst
	for _, ip := range svc.Spec.ClusterIPs {
		dsts = append(dsts, dst{netip.MustParseAddr(ip), 443})
	}
	for _, s := range slices.Items {
		for _, p := range s.Ports {
			for _, e := range s.Endpoints {
				for _, a := range e.Addresses {
					dsts = append(dsts, dst{netip.MustParseAddr(a), ptr.Deref(p.Port, 6443)})
				}
			}
		}
	}
	var rules strings.Builder
	for _, d := range dsts {
		fam := "ip"
		if d.addr.Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&rules, "add rule inet %s out %s daddr %s tcp dport %d drop; ", isolationTable, fam, d.addr,
			d.port)
	}
	// KubePrism, the node-local API load balancer host processes use.
	fmt.Fprintf(&rules, "add rule inet %s out tcp dport 7445 drop; ", isolationTable)
	return rules.String()
}

// isolate cuts node's host network namespace and the namespace of the
// process pid off from the API server, and returns the function that
// restores them. A watchdog on the node restores them after limit, should
// the suite die first.
func (l *lab) isolate(t *testing.T, node string, pid int, limit time.Duration) func() {
	t.Helper()
	script := fmt.Sprintf("add table inet %[1]s; add chain inet %[1]s out "+
		"{ type filter hook output priority -300; policy accept; }; %[2]s", isolationTable, l.apiDestinations(t))
	undo := fmt.Sprintf("nft delete table inet %[1]s; nsenter -t %[2]d -n nft delete table inet %[1]s",
		isolationTable, pid)
	if _, err := nodeExec(node, "sh", "-c", fmt.Sprintf(
		"setsid sh -c 'sleep %d; %s' >/dev/null 2>&1 </dev/null &", int(limit.Seconds()), undo)); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeExec(node, "nft", script); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeExec(node, "nsenter", "-t", strconv.Itoa(pid), "-n", "nft", script); err != nil {
		_, _ = nodeExec(node, "sh", "-c", undo)
		t.Fatal(err)
	}
	return func() {
		if out, err := nodeExec(node, "sh", "-c", undo); err != nil {
			t.Errorf("restore %s's API access: %v: %s", role(node), err, out)
		}
	}
}

// role names a node by its part in the run: compute, edge-1 or edge-2. The
// run's output and summary name nodes only this way, so that results can
// be shared without the cell's node names.
func role(node string) string {
	switch node {
	case computeNode:
		return "compute"
	case edgeNode1:
		return "edge-1"
	case edgeNode2:
		return "edge-2"
	}
	return "a node outside the run"
}

// otherEdge returns the edge node that is not node.
func otherEdge(node string) string {
	if node == edgeNode1 {
		return edgeNode2
	}
	return edgeNode1
}

func rowAPIIsolation(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	requireTalos(t, l)
	a.refresh(t, l)
	oldPod, oldAtt := a.pod, a.att
	sniffOld, err := startProbe(a.node, podPID(t, a.node, oldPod.Namespace, oldPod.Name), "sniff-old", "sniff",
		"-iface", oldAtt.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "150s")
	if err != nil {
		t.Fatal(err)
	}
	p := l.probe(t, a.tn, computeNode, "api-isolation", targetAddr(), 148*time.Second)
	time.Sleep(3 * time.Second)

	// The node and the provider lose the API server; the provider keeps
	// running and its packets keep flowing.
	providerPID, err := theLab.cell.containerPID(a.node, oldPod.Namespace, oldPod.Name, "edge-provider")
	if err != nil {
		t.Fatal(err)
	}
	isolated := now()
	restore := l.isolate(t, a.node, providerPID, 150*time.Second)
	restored := false
	defer func() {
		if !restored {
			restore()
		}
	}()
	last := a.lastRenewal(t, l)
	le := a.lease(t, l)
	renewed := wallToRef(le.Spec.RenewTime.Time)
	l.record(t, "last renewal start after the isolation began", last-isolated)

	// A replacement on the other edge node claims the prefix. The old
	// node can confirm nothing, so core may accept it only TakeoverWait
	// after reading the old holder's lease unchanged, which it can do no
	// earlier than the holder's last renewal.
	b := &side{tn: a.tn, svc: a.svc, vpcUID: a.vpcUID, deploy: "a12", node: otherEdge(a.node)}
	l.deployProvider(t, a.tn.namespace, b.deploy, b.node, b.config(prefix))
	b.refresh(t, l)
	sniffNew, err := startProbe(b.node, podPID(t, b.node, b.pod.Namespace, b.pod.Name), "sniff-new", "sniff",
		"-iface", b.att.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "100s")
	if err != nil {
		t.Fatal(err)
	}
	r := l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, b.att.Name, 2*time.Minute)
	l.record(t, "closedEpoch of the isolated holder", r.Status.ClosedEpoch)
	restore()
	restored = true
	l.record(t, "isolation lasted", now()-isolated)

	seenOld, seenNew := windowed(sniffOld.wait(l, t)), sniffNew.wait(l, t)
	evs := p.wait(l, t)
	stop, ok := stopAfter(seenOld, last)
	if !ok {
		t.Fatal("the isolated node's gate never closed")
	}
	l.record(t, "isolated gate closed after the last renewal start", stop-last)
	if stop-last > localExpiry {
		t.Errorf("the isolated node's gate closed %v after the last renewal start, bound %v", stop-last, localExpiry)
	}
	if len(seenNew) == 0 {
		t.Fatal("no packet reached the replacement")
	}
	firstNew := seenNew[0].T
	l.record(t, "replacement's first packet after the old holder's last renewal", firstNew-renewed)
	if firstNew-renewed < takeoverWait-clockTolerance {
		t.Errorf("the replacement forwarded %v after the old holder's last renewal, before TakeoverWait %v",
			firstNew-renewed, takeoverWait)
	}
	l.record(t, "last packet at the isolated node to first at the replacement", firstNew-stop)
	if firstNew <= stop {
		t.Errorf("both nodes forwarded the prefix: the replacement's first packet came %v before the isolated "+
			"node's last", stop-firstNew)
	}
	l.record(t, "outage seen by the client", largestGap(replies(evs)))

	// The rest of the suite runs on the replacement.
	l.stopProvider(t, a.tn.namespace, a.deploy)
	a.deploy, a.node = b.deploy, b.node
	a.refresh(t, l)
	l.waitReachable(t, a)
}

// nodeBootID returns node's boot ID.
func (l *lab) nodeBootID(t *testing.T, node string) string {
	t.Helper()
	var n corev1.Node
	if err := l.c.Get(context.Background(), client.ObjectKey{Name: node}, &n); err != nil {
		t.Fatal(err)
	}
	return n.Status.NodeInfo.BootID
}

// nodeReady reports whether node is Ready.
func (l *lab) nodeReady(node string) (bool, error) {
	var n corev1.Node
	if err := l.c.Get(context.Background(), client.ObjectKey{Name: node}, &n); err != nil {
		return false, err
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue, nil
		}
	}
	return false, nil
}

func rowReboot(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	requireTalos(t, l)
	ctx := context.Background()
	a.refresh(t, l)
	boot := l.nodeBootID(t, a.node)
	before := a.lease(t, l)
	epoch := ptr.Deref(before.Spec.LeaseTransitions, 0)
	// A bare-metal node takes minutes to come back, so the client probes
	// for long enough to see the provider reacquire its claims.
	p := l.probe(t, a.tn, computeNode, "reboot", targetAddr(), 15*time.Minute)
	time.Sleep(3 * time.Second)

	// An abrupt reboot, as on a power loss: the node's processes get no
	// chance to release anything, and its kernel state is gone.
	rebooted := now()
	cmd := theLab.cell.command(a.node, "sh", "-c",
		"echo 1 > /proc/sys/kernel/sysrq; echo s > /proc/sysrq-trigger; sleep 2; echo b > /proc/sysrq-trigger")
	go func() { _ = cmd.Run() }()
	eventually(t, 20*time.Minute, 5*time.Second, role(a.node)+" back on a new boot", func() (bool, error) {
		var n corev1.Node
		if err := l.c.Get(ctx, client.ObjectKey{Name: a.node}, &n); err != nil {
			return false, err
		}
		ready, err := l.nodeReady(a.node)
		return ready && n.Status.NodeInfo.BootID != boot, err
	})
	l.record(t, "node Ready on a new boot after the reboot", now()-rebooted)

	// The provider's lease moves to a new epoch once its restarted process
	// has waited out TakeoverWait. Watch for the first version of it.
	var acquired *coordinationv1.Lease
	eventually(t, 10*time.Minute, 250*time.Millisecond, "the provider's lease on the new boot", func() (bool, error) {
		le := &coordinationv1.Lease{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(before), le); err != nil {
			return false, nil
		}
		if ptr.Deref(le.Spec.LeaseTransitions, 0) > epoch {
			acquired = le
			return true, nil
		}
		return false, nil
	})
	evs := p.wait(l, t)
	if err := l.cell.install(l.probeBin); err != nil {
		t.Fatal(err)
	}
	start, err := strconv.ParseInt(acquired.Annotations["galactic.datumapis.com/edge-renew-start"], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	acquiredAt := l.bootRef(t, a.node, time.Duration(start))
	l.record(t, "lease epoch before and on the new boot",
		fmt.Sprintf("%d -> %d (sequence %s)", epoch, ptr.Deref(acquired.Spec.LeaseTransitions, 0),
			acquired.Annotations["galactic.datumapis.com/edge-sequence"]))

	rs := windowed(evs)
	stop, ok := stopAfter(rs, rebooted)
	if !ok {
		t.Fatal("forwarding never stopped after the reboot")
	}
	resume, ok := resumeAfter(rs, stop+time.Second)
	if !ok {
		t.Fatal("forwarding never resumed after the reboot")
	}
	l.record(t, "outage", resume-stop)
	// No gate opens from the previous boot: forwarding resumes only under
	// the lease of the new boot.
	l.record(t, "first reply after the new boot's lease renew-start", resume-acquiredAt)
	if resume < acquiredAt-clockTolerance {
		t.Errorf("forwarding resumed %v before the provider held its lease on the new boot", acquiredAt-resume)
	}
	started := l.containerStart(t, a)
	l.record(t, "resumed after the restarted process started", resume-started)
	if resume-started < takeoverWait-clockTolerance {
		t.Errorf("forwarding resumed %v after the restarted process started, before TakeoverWait %v",
			resume-started, takeoverWait)
	}
	if resume-started > takeoverWait+5*time.Second {
		t.Errorf("forwarding resumed %v after the restarted process started, want TakeoverWait %v plus the 1 s "+
			"accept-and-apply target (measured, with 4 s of slack for the process's first read)",
			resume-started, takeoverWait)
	}
	a.refresh(t, l)
	r := l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 3*time.Minute)
	if c := meta.FindStatusCondition(r.Status.Conditions, "Accepted"); c != nil {
		l.record(t, "route accepted again", c.Reason)
	}
	l.waitReachable(t, a)
}
