// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// The MASQUE service as the lab deploys it
// (deploy/containerlab/resources/masque-service): config/masque in
// masque-system, the grant authority for cell dfw, and one provider pod on
// dfw-worker2. Every connector's /96 comes from the authority's ledger of
// its VPC; both VPCs' ledgers reserve the same ranges, so their first
// connectors hold the same /96, as TestMASQUE's do.
const (
	svcNS         = "masque-system"
	svcProvider   = "masque"
	svcCell       = "dfw"
	svcAuthority  = "masque.dfw.lab.test:443"
	svcPort       = 8443
	svcHealthPort = 9188
	svcConnectors = "fd00:ed9e:500::/80"
	svcPools      = "fd00:ed9e:501::/80"
	// svcCA and svcOtherCA are where the suite copies, onto every dfw node,
	// the CA that signed the service's certificate and one that did not.
	svcCA      = "/usr/local/share/masque-service-ca.pem"
	svcOtherCA = "/usr/local/share/masque-service-other-ca.pem"
	// packetSize is the IPv6 minimum MTU every admitted request carries in
	// both directions.
	packetSize = 1280
	// pingPayload is the ICMPv6 echo payload of a packetSize packet: less
	// the 40-byte IPv6 and 8-byte ICMPv6 headers.
	pingPayload = packetSize - 48
	// refreshBound is how long a revoked connector can keep forwarding: the
	// adapter refreshes each request's grant every 5 s, and a refresh has 2 s
	// (docs/edge/masque-provider.md, Grant refresh and revocation).
	refreshBound = 7 * time.Second
	// nameLabel selects config/masque's pods.
	nameLabel = "app.kubernetes.io/name"
)

// svcConnector is one connector the authority granted: its tenant, the
// credential and /96 grant create printed, and the echo identifier its
// client uses.
type svcConnector struct {
	name   string
	tn     tenant
	vpcUID string
	issued issuedGrant
	echo   int
}

// issuedGrant is what masque-authority grant create prints.
type issuedGrant struct {
	Connector  string    `json:"connector"`
	Credential string    `json:"credential"`
	VPC        string    `json:"vpc"`
	Prefix     string    `json:"prefix"`
	Expires    time.Time `json:"expires"`
}

// vpc is the connector's Galactic-VPC selector.
func (c *svcConnector) vpc() string { return c.tn.vpcNamespace + "/" + c.tn.vpc }

// addr is the address the connector's client sends from: the first after
// its /96's.
func (c *svcConnector) addr() string {
	return netip.MustParsePrefix(c.issued.Prefix).Addr().Next().String()
}

// service is the MASQUE service under test.
type service struct {
	l           *lab
	ca, otherCA *testCA
	// pod is the running pod of the provider Deployment.
	pod *corev1.Pod
	// c10 and c20 are the main connectors of VPCs 10 and 20; c10b is VPC
	// 10's second connector.
	c10, c10b, c20 *svcConnector
	// links maps every attachment the run created to its host link, for
	// teardown's check that none remains.
	links map[string]string
	// unrelated holds the UIDs of the tenants' edge-client pods, which the
	// run must leave in place.
	unrelated map[string]types.UID
}

// The two VPCs the service serves, as tenant selectors.
var (
	svcTenant10 = tenant{vpcNamespace: tenantA.vpcNamespace, vpc: tenantA.vpc, provider: svcProvider}
	svcTenant20 = tenant{vpcNamespace: tenantB.vpcNamespace, vpc: tenantB.vpc, provider: svcProvider}
)

// TestMASQUEService runs the shipped MASQUE service, cmd/masque-provider
// and cmd/masque-authority from their published Dockerfiles, deployed from
// config/masque through the lab overlay, against the lab's gVPC workloads.
// Connectors are granted with the authority's own operator commands. It
// covers independent clients connecting, sending and receiving 1280-byte
// packets to local and remote workloads in both directions, disconnecting
// and reconnecting; invalid credentials and denied VPC selections; TLS
// certificate and hostname validation; return traffic to subdivisions of a
// connector's /96; a disabled and an expired grant stopping within their
// bounds while another connector keeps forwarding; readiness only while the
// pod holds its Lease; process restart; and drain on SIGTERM. Run it with
// task verify:masque-service.
func TestMASQUEService(t *testing.T) {
	l := getLab(t)
	t.Cleanup(func() { l.writeSummary(t) })
	s := &service{l: l, ca: newTestCA(t, "masque service CA"), otherCA: newTestCA(t, "masque other CA"),
		links: map[string]string{}, unrelated: map[string]types.UID{}}
	if os.Getenv("EDGE_CONFORMANCE_KEEP") == "" {
		t.Cleanup(func() { s.teardown(t) })
	}
	if !t.Run("setup", s.setup) {
		t.FailNow()
	}
	s.row(t, "readiness", s.rowReadiness)
	s.row(t, "lifecycle-h3", func(t *testing.T) { s.lifecycle(t, "h3") })
	s.row(t, "h2-lifecycle", s.rowH2Lifecycle)
	s.row(t, "authorization-h3", func(t *testing.T) { s.authorization(t, "h3") })
	s.row(t, "spoofing-isolation-h3", s.rowSpoofingIsolationH3)
	s.row(t, "h2-authz-isolation", s.rowH2AuthzIsolation)
	s.row(t, "tls-validation", s.rowTLS)
	s.row(t, "subdivisions", s.rowSubdivisions)
	s.row(t, "mtu-1280-both", s.rowMTU1280)
	s.row(t, "grant-disable", s.rowDisable)
	s.row(t, "grant-expiry", func(t *testing.T) { s.expiry(t, "h3") })
	s.row(t, "h3-to-h2-same-pod", s.rowSamePodH3ToH2)
	s.row(t, "h3-to-h2-cross-node", s.rowCrossNodeH3ToH2)
	s.row(t, "remote-convergence", s.rowRemoteConvergence)
	s.row(t, "mtu-live-drop", s.rowMTULiveDrop)
	s.row(t, "diagnostics-walk", s.rowDiagnosticsWalk)
	s.row(t, "lease-readiness", s.rowLeaseReadiness)
	s.row(t, "process-restart", s.rowProcessRestart)
	s.row(t, "drain", s.rowDrain)
	s.row(t, "node-restart", s.rowNodeRestart)
}

// row runs fn as subtest name once every connector is authorized and, when
// it fails, saves the provider pods' logs with its artifacts.
func (s *service) row(t *testing.T, name string, fn func(*testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		defer func() {
			if !t.Failed() {
				return
			}
			var pods corev1.PodList
			if err := s.l.c.List(context.Background(), &pods, client.InNamespace(svcNS)); err != nil {
				return
			}
			for _, p := range pods.Items {
				if logs, err := s.l.kubectl("-n", svcNS, "logs", p.Name, "--all-containers"); err == nil {
					s.l.save(t, p.Name+".log", []byte(logs))
				}
			}
		}()
		// A connector idle for longer than its authorization's validUntil,
		// at most 28 s, gets a new authorization on its next request, and
		// the authority answers 503 until the old one is released. Each row
		// starts with every connector authorized, so none measures that.
		for _, c := range []*svcConnector{s.c10, s.c10b, s.c20} {
			if c != nil && s.pod != nil {
				s.waitConnected(t, c)
			}
		}
		fn(t)
	})
}

// overlay is the lab overlay directory of the service.
func (s *service) overlay(sub ...string) string {
	return filepath.Join(append([]string{s.l.root, "deploy", "containerlab", "resources", "masque-service"}, sub...)...)
}

func (s *service) setup(t *testing.T) {
	l, ctx := s.l, context.Background()
	for _, tn := range []tenant{svcTenant10, svcTenant20} {
		for i := 1; i <= 3; i++ {
			p := l.clientPod(t, tn, i)
			s.unrelated[p.Namespace+"/"+p.Name] = p.UID
		}
	}
	l.copyToNodes(t, "masque-service-ca.pem", svcCA, s.ca.pem)
	l.copyToNodes(t, "masque-service-other-ca.pem", svcOtherCA, s.otherCA.pem)
	if _, err := l.kubectl("apply", "-k", s.overlay()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.kubectl("patch", "edgeprovider", svcProvider, "--subresource=status", "--type=merge",
		"-p", `{"status":{"approved":true}}`); err != nil {
		t.Fatal(err)
	}
	// The authority's certificate and the CA the provider trusts come from
	// cert-manager (config/masque/authority/components/cert-manager); the
	// service's own certificate is the deployment's choice, so the suite
	// issues it.
	svcCert, svcKey := s.ca.issue(t, strings.Split(svcAuthority, ":")[0])
	tlsSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: svcNS, Name: "masque-provider-tls"},
		Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: svcCert, corev1.TLSPrivateKeyKey: svcKey}}
	if err := l.c.Create(ctx, tlsSecret); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	} else if err != nil {
		if err := l.c.Update(ctx, tlsSecret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.kubectl("apply", "-k", s.overlay("authority")); err != nil {
		t.Fatal(err)
	}
	s.waitReady(t, "masque-authority", computeNode, "")
	var authTLS corev1.Secret
	if err := l.c.Get(ctx, client.ObjectKey{Namespace: svcNS, Name: "masque-authority-tls"}, &authTLS); err != nil {
		t.Fatal(err)
	}
	if got := authTLS.Annotations["cert-manager.io/issuer-name"]; got != "masque-authority-root" {
		t.Fatalf("masque-authority-tls issued by %q, want cert-manager Issuer masque-authority-root", got)
	}
	if len(authTLS.Data["ca.crt"]) == 0 {
		t.Fatal("masque-authority-tls has no ca.crt for the provider pods to trust")
	}
	for _, tn := range []tenant{svcTenant10, svcTenant20} {
		if _, err := s.authority(t, "ledger", "init", "--vpc", tn.vpcNamespace+"/"+tn.vpc, "--cell", svcCell,
			"--connectors", svcConnectors, "--pools", svcPools); err != nil {
			t.Fatal(err)
		}
	}
	s.c10 = s.grant(t, "c10", svcTenant10, 0x5a10, 0)
	s.c10b = s.grant(t, "c10b", svcTenant10, 0x5a11, 0)
	s.c20 = s.grant(t, "c20", svcTenant20, 0x5b20, 0)
	l.record(t, "VPC 10 connector /96", s.c10.issued.Prefix)
	l.record(t, "VPC 10 second connector /96", s.c10b.issued.Prefix)
	l.record(t, "VPC 20 connector /96", s.c20.issued.Prefix)

	if _, err := l.kubectl("apply", "-k", s.overlay("provider")); err != nil {
		t.Fatal(err)
	}
	s.pod = s.waitReady(t, "masque-provider", edgeNode1, "")
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
}

// authority runs masque-authority with args in the authority's pod, under
// its own ServiceAccount: the binary of the image under test, with the
// permissions config/masque grants the authority. It returns the command's
// standard output.
func (s *service) authority(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "kubectl", append([]string{"--kubeconfig", s.l.kubeconfig,
		"-n", svcNS, execVerb, "deployment/masque-authority", "-c", "masque-authority", "--", "/masque-authority"},
		args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("masque-authority %v: %w: %s", args, err, stderr.String())
	}
	return stdout.String(), nil
}

// grant creates a connector in tn's VPC with lifetime, or the authority's
// maximum when it is zero. It may reach the VPC's workloads and the lab's
// off-fabric host, under the lab's traffic policies.
func (s *service) grant(t *testing.T, name string, tn tenant, echo int, lifetime time.Duration) *svcConnector {
	t.Helper()
	args := []string{"grant", "create", "--vpc", tn.vpcNamespace + "/" + tn.vpc, "--cell", svcCell,
		"--route", "fd20:" + tn.vpc + "::/32", "--route", remoteHost + "/128",
		"--ingress-policy", labIngress, "--egress-policy", "lab-egress"}
	if lifetime > 0 {
		args = append(args, "--lifetime", lifetime.String())
	}
	out, err := s.authority(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	c := &svcConnector{name: name, tn: tn, vpcUID: s.l.vpcUID(t, tn), echo: echo}
	if err := json.Unmarshal([]byte(out), &c.issued); err != nil {
		t.Fatalf("grant create printed %q: %v", out, err)
	}
	if c.issued.Credential == "" || c.issued.Prefix == "" {
		t.Fatalf("grant create printed no credential or prefix: connector %s", c.issued.Connector)
	}
	return c
}

// waitReady waits until a running pod of deployment, other than the pod
// whose UID is not, is Ready on node, and returns it.
func (s *service) waitReady(t *testing.T, deployment, node string, not types.UID) *corev1.Pod {
	t.Helper()
	var pod *corev1.Pod
	eventually(t, 3*time.Minute, time.Second, deployment+" ready on "+node, func() (bool, error) {
		var pods corev1.PodList
		if err := s.l.c.List(context.Background(), &pods, client.InNamespace(svcNS),
			client.MatchingLabels{nameLabel: deployment}); err != nil {
			return false, err
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.UID != not && p.DeletionTimestamp == nil && p.Spec.NodeName == node &&
				p.Status.Phase == corev1.PodRunning && podReady(p) {
				pod = p
				return true, nil
			}
		}
		return false, nil
	})
	return pod
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// server is the provider pod as the probe dials it, from the pod's node.
func (s *service) server(pod *corev1.Pod) cipServer {
	return cipServer{pod: pod, port: svcPort, authority: svcAuthority, ca: svcCA}
}

// connectArgs are the probe's arguments for one request of c to pod over
// transport, sending packetSize-byte echo requests to dsts for d.
func (s *service) connectArgs(pod *corev1.Pod, c *svcConnector, transport string, d time.Duration,
	dsts ...string) []string {
	return append(s.server(pod).args(c.issued.Credential, c.vpc(), c.echo, d, dsts),
		"-transport", transport, "-size", strconv.Itoa(packetSize))
}

// connect starts one request of c to the provider pod from its node.
func (s *service) connect(t *testing.T, name string, c *svcConnector, transport string, d time.Duration,
	dsts ...string) *probeRun {
	t.Helper()
	return s.connectTo(t, s.pod, name, c, transport, d, dsts...)
}

// connectTo starts one request of c to pod from pod's node.
func (s *service) connectTo(t *testing.T, pod *corev1.Pod, name string, c *svcConnector, transport string,
	d time.Duration, dsts ...string) *probeRun {
	t.Helper()
	p, err := startProbe(pod.Spec.NodeName, 1, name, s.connectArgs(pod, c, transport, d, dsts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// once runs one request of c to pod for a second and returns its events.
func (s *service) once(pod *corev1.Pod, c *svcConnector, transport string, dsts ...string) ([]event, error) {
	return runProbe(pod.Spec.NodeName, s.connectArgs(pod, c, transport, time.Second, dsts...))
}

// waitConnected waits until c is admitted on the provider pod and its
// tenant's workload on the pod's node answers through it.
func (s *service) waitConnected(t *testing.T, c *svcConnector) {
	t.Helper()
	s.waitConnectedTo(t, s.pod, c, "h3")
}

// waitConnectedTo waits until c is admitted on pod over transport and its
// tenant's workload on pod's node answers through it.
func (s *service) waitConnectedTo(t *testing.T, pod *corev1.Pod, c *svcConnector, transport string) {
	t.Helper()
	dst := s.l.workloadOn(t, c.tn, pod.Spec.NodeName).addr
	eventually(t, 2*time.Minute, 2*time.Second, "connector "+c.name+" answered on "+pod.Name, func() (bool, error) {
		evs, err := s.once(pod, c, transport, dst)
		if err != nil {
			return false, err
		}
		return len(echoes(evs, dst)) > 0, fmt.Errorf("status %d", status(evs))
	})
}

// proto returns the ALPN protocol a request's connection negotiated.
func proto(evs []event) string {
	for _, e := range evs {
		if e.Proto != "" {
			return e.Proto
		}
	}
	return ""
}

// requireDelivered fails unless evs is a whole session of c over transport,
// sending to len(ws) destinations for d, in which each workload of ws
// answered at least 90% of its packetSize-byte echo requests with
// packetSize-byte replies, and nothing arrived from any other source. It
// returns the packets from each workload that were not echo replies, which
// the caller accounts for.
func (s *service) requireDelivered(t *testing.T, what string, c *svcConnector, transport string, evs []event,
	ws ...workloadRef) map[string][]event {
	t.Helper()
	d := lifecycleWindow
	requireSessionFor(t, what, evs, d, len(ws), c.issued.Prefix)
	if p := proto(evs); p != transport {
		t.Errorf("%s: negotiated %q, want %s", what, p, transport)
	}
	per := sentCount(evs) / len(ws)
	inbound := map[string][]event{}
	for _, w := range ws {
		rs := echoes(evs, w.addr)
		short := 0
		for _, r := range rs {
			if r.Len != packetSize {
				short++
			}
		}
		s.l.record(t, fmt.Sprintf("%s to %s", what, w.node), fmt.Sprintf("%d/%d %d-byte replies, %d of another size",
			len(rs)-short, per, packetSize, short))
		if per == 0 || len(rs) < per*9/10 || short > 0 {
			t.Errorf("%s to %s: %d of %d answered, %d not %d bytes", what, w.node, len(rs), per, short, packetSize)
		}
		inbound[w.addr] = nil
	}
	stray := 0
	for _, e := range evs {
		if e.Reply != otherReply {
			continue
		}
		if _, ok := inbound[e.From]; ok && e.Dst == c.addr() {
			inbound[e.From] = append(inbound[e.From], e)
			continue
		}
		stray++
	}
	if stray > 0 {
		t.Errorf("%s: the client received %d packets from no workload it talks to", what, stray)
	}
	return inbound
}

// pinger is a workload pinging a connector's address with packetSize-byte
// echo requests: traffic the gVPC starts toward the connector.
type pinger struct {
	w     workloadRef
	count int
	done  chan struct{}
}

// pingFrom starts count packetSize-byte pings, 100 ms apart, from tenant
// tn's edge client i to dst. Nothing answers them: the client reports each
// one it receives.
func (s *service) pingFrom(t *testing.T, tn tenant, i int, dst string) *pinger {
	count := lifecyclePings
	t.Helper()
	pod := s.l.clientPod(t, tn, i)
	node := map[int]string{1: computeNode, 2: edgeNode1, 3: edgeNode2}[i]
	p := &pinger{w: s.l.workloadOn(t, tn, node), count: count, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		// Every ping goes unanswered, so ping exits nonzero.
		_, _ = s.l.kubectl("-n", pod.Namespace, execVerb, pod.Name, "--", "ping", "-6", "-n", "-q", "-i", "0.1",
			"-c", strconv.Itoa(count), "-s", strconv.Itoa(pingPayload), "-W", "1", dst)
	}()
	return p
}

// requireInbound fails unless at least 90% of p's pings reached the
// connector's client as packetSize-byte packets.
func (s *service) requireInbound(t *testing.T, what string, p *pinger, got []event) {
	t.Helper()
	<-p.done
	n := 0
	for _, e := range got {
		if e.Len == packetSize {
			n++
		}
	}
	s.l.record(t, fmt.Sprintf("%s from %s", what, p.w.node), fmt.Sprintf("%d/%d %d-byte packets, %d of another size",
		n, p.count, packetSize, len(got)-n))
	if n < p.count*9/10 || len(got) != n {
		t.Errorf("%s from %s: %d of %d pings arrived at %d bytes, %d of another size", what, p.w.node, n, p.count,
			packetSize, len(got)-n)
	}
}

// lifecycleWindow is how long each of the lifecycle's requests runs. The
// workloads' pings start pingDelay into it, once the connector's route is
// advertised, and end well before it closes.
const (
	lifecycleWindow = 10 * time.Second
	pingDelay       = 3 * time.Second
	lifecyclePings  = 40
)

// lifecycle runs VPC 10's and VPC 20's connectors as independent clients
// over transport, at once: each connects, exchanges packetSize-byte packets
// in both directions with its tenant's workload on the provider's node and
// on the compute node, disconnects, and reconnects to do it again. Each
// connector's route claim is released after it disconnects, and nothing
// reaches either client but its own tenant's packets.
func (s *service) lifecycle(t *testing.T, transport string) {
	l := s.l
	conns := []*svcConnector{s.c10, s.c20}
	for _, round := range []string{"connect", "reconnect"} {
		runs := map[*svcConnector]*probeRun{}
		ws := map[*svcConnector][]workloadRef{}
		for _, c := range conns {
			ws[c] = []workloadRef{l.workloadOn(t, c.tn, edgeNode1), l.workloadOn(t, c.tn, computeNode)}
			runs[c] = s.connect(t, round+"-"+transport+"-"+c.name, c, transport, lifecycleWindow, ws[c][0].addr,
				ws[c][1].addr)
		}
		time.Sleep(pingDelay)
		pings := map[*svcConnector][]*pinger{}
		for _, c := range conns {
			pings[c] = []*pinger{s.pingFrom(t, c.tn, 2, c.addr()),
				s.pingFrom(t, c.tn, 1, c.addr())}
		}
		ended := map[*svcConnector]time.Time{}
		for _, c := range conns {
			evs := runs[c].wait(l, t)
			ended[c] = time.Now()
			what := fmt.Sprintf("%s %s of %s", transport, round, c.name)
			inbound := s.requireDelivered(t, what, c, transport, evs, ws[c]...)
			for _, p := range pings[c] {
				s.requireInbound(t, what+": gVPC pings", p, inbound[p.w.addr])
			}
		}
		// Disconnecting releases only the connector's route claim; core
		// removes the route once no attachment uses it.
		for _, c := range conns {
			eventually(t, 15*time.Second, 250*time.Millisecond, c.name+"'s claim released", func() (bool, error) {
				r := l.route(t, svcNS, c.vpcUID, netip.MustParsePrefix(c.issued.Prefix))
				return r == nil || (r.Spec.Claim != nil && r.Spec.Claim.Released), nil
			})
			l.record(t, fmt.Sprintf("%s %s: %s's claim released after its request ended", transport, round, c.name),
				time.Since(ended[c]).Round(100*time.Millisecond))
		}
	}
}

// authorization checks over transport that an unknown credential is
// refused with 401 and a connector's credential presented for the other
// VPC with 403, neither with any packet delivered.
func (s *service) authorization(t *testing.T, transport string) {
	unknown := &svcConnector{name: "unknown", tn: svcTenant10, echo: 1,
		issued: issuedGrant{Credential: rand.Text(), Prefix: s.c10.issued.Prefix}}
	foreign := &svcConnector{name: "c10 for VPC 20", tn: svcTenant20, echo: 1, issued: s.c10.issued}
	dst := s.l.workloadOn(t, svcTenant10, edgeNode1).addr
	for _, c := range []struct {
		c    *svcConnector
		want int
	}{{unknown, 401}, {foreign, 403}} {
		evs, err := s.once(s.pod, c.c, transport, dst)
		if err != nil {
			t.Fatal(err)
		}
		s.l.record(t, transport+" "+c.c.name, status(evs))
		if got := status(evs); got != c.want || len(echoes(evs, dst)) > 0 || proto(evs) != transport {
			t.Errorf("%s over %s: status %d with %d replies on %q, want %d and none", c.c.name, transport, got,
				len(echoes(evs, dst)), proto(evs), c.want)
		}
	}
}

// rowTLS checks on both transports that a client which trusts another CA,
// or which expects another name, refuses the server's certificate before
// it sends a request.
func (s *service) rowTLS(t *testing.T) {
	dst := s.l.workloadOn(t, svcTenant10, edgeNode1).addr
	for _, transport := range []string{"h3", "h2"} {
		for _, c := range []struct {
			what, authority, ca, want string
		}{
			{"another CA", svcAuthority, svcOtherCA, "certificate signed by unknown authority"},
			{"another name", "masque.sjc.lab.test:443", svcCA, "certificate is valid for masque.dfw.lab.test"},
		} {
			srv := cipServer{pod: s.pod, port: svcPort, authority: c.authority, ca: c.ca}
			args := append(srv.args(s.c10.issued.Credential, s.c10.vpc(), s.c10.echo, time.Second, []string{dst}),
				"-transport", transport)
			evs, err := runProbe(s.pod.Spec.NodeName, args)
			s.l.record(t, transport+" with "+c.what, err)
			switch {
			case err == nil:
				t.Errorf("%s with %s: the client accepted the server, status %d", transport, c.what, status(evs))
			case !strings.Contains(err.Error(), c.want):
				t.Errorf("%s with %s: %v, want an error naming %q", transport, c.what, err, c.want)
			}
		}
	}
}

// rowSubdivisions sends from addresses in two /112 subdivisions of VPC 10's
// connector /96, none of them the address the probe uses by default, to
// VPC 10's workloads on the provider's node and the compute node and to the
// off-fabric host through NAT. Each pair is answered: the /96 carries
// return traffic to any address inside it.
func (s *service) rowSubdivisions(t *testing.T) {
	c := s.c10
	base := netip.MustParsePrefix(c.issued.Prefix).Addr().As16()
	srcs := make([]string, 0, 4)
	for _, sub := range []byte{1, 2} {
		for _, host := range []byte{1, 2} {
			a := base
			a[13], a[15] = sub, host
			srcs = append(srcs, netip.AddrFrom16(a).String())
		}
	}
	dsts := []string{s.l.workloadOn(t, c.tn, edgeNode1).addr, s.l.workloadOn(t, c.tn, computeNode).addr, remoteHost}
	d := 5 * time.Second
	p, err := startProbe(s.pod.Spec.NodeName, 1, "subdivisions",
		append(s.connectArgs(s.pod, c, "h3", d, dsts...), "-src", strings.Join(srcs, ","))...)
	if err != nil {
		t.Fatal(err)
	}
	evs := p.wait(s.l, t)
	pairs := len(srcs) * len(dsts)
	requireSessionFor(t, "VPC 10's request", evs, d, pairs, c.issued.Prefix)
	perPair := sentCount(evs) / pairs
	for _, src := range srcs {
		for _, dst := range dsts {
			n := 0
			for _, e := range echoes(evs, dst) {
				if e.Dst == src {
					n++
				}
			}
			s.l.record(t, fmt.Sprintf("%s to %s", src, dst), fmt.Sprintf("%d/%d", n, perPair))
			if perPair == 0 || n < perPair*9/10 {
				t.Errorf("%s to %s: %d of %d answered", src, dst, n, perPair)
			}
		}
	}
	if n := others(evs); n > 0 {
		t.Errorf("the client received %d packets that were not its replies", n)
	}
}

// stopsWhileOtherForwards runs c and VPC 10's second connector at once to
// their workloads on the provider's node over transport, calls act once c
// forwards, and returns c's echo replies and the instant act returned. The
// second connector must answer throughout without a gap, and the shared
// instance must keep renewing its Lease at the same epoch.
func (s *service) stopsWhileOtherForwards(t *testing.T, label string, c *svcConnector, transport string,
	d time.Duration, act func() time.Time) ([]event, time.Time) {
	t.Helper()
	l := s.l
	// The other connector's authorization may have lapsed while it was
	// idle; the authority answers 503 until it has replaced it.
	s.waitConnected(t, s.c10b)
	dst := l.workloadOn(t, c.tn, edgeNode1).addr
	other := l.workloadOn(t, s.c10b.tn, edgeNode1).addr
	before, epoch := s.lease(t, s.pod)
	pc := s.connect(t, label+"-"+c.name, c, transport, d, dst)
	po := s.connect(t, label+"-"+s.c10b.name, s.c10b, transport, d, other)
	eventually(t, time.Minute, time.Second, c.name+"'s route accepted", func() (bool, error) {
		r := l.route(t, svcNS, c.vpcUID, netip.MustParsePrefix(c.issued.Prefix))
		return r != nil && meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted), nil
	})
	time.Sleep(3 * time.Second)
	at := act()
	evs := pc.wait(l, t)
	s.requireOther(t, label, po.wait(l, t), transport, d, other)
	after, epochAfter := s.lease(t, s.pod)
	if after <= before || epochAfter != epoch {
		t.Errorf("the shared instance did not keep renewing at the same epoch: renew-start %v to %v, epoch %d to %d",
			before, after, epoch, epochAfter)
	}
	return echoes(evs, dst), at
}

// requireOther fails unless VPC 10's second connector answered at least
// 90% of its probes with no gap over a second.
func (s *service) requireOther(t *testing.T, label string, evs []event, transport string, d time.Duration,
	dst string) {
	t.Helper()
	requireSessionFor(t, "the other connector's request", evs, d, 1, s.c10b.issued.Prefix)
	rs := echoes(evs, dst)
	s.l.record(t, label+": the other connector", fmt.Sprintf("%d/%d over %s, largest gap %v", len(rs), sentCount(evs),
		transport, largestGap(rs)))
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second {
		t.Errorf("%s: the other connector answered %d of %d with a %v gap", label, len(rs), sentCount(evs),
			largestGap(rs))
	}
}

// lease returns the latest renew-start and the epoch of pod's instance
// Lease.
func (s *service) lease(t *testing.T, pod *corev1.Pod) (time.Duration, int32) {
	t.Helper()
	var le coordinationv1.Lease
	if err := s.l.c.Get(context.Background(), client.ObjectKey{Namespace: svcNS, Name: "ei-" + string(pod.UID)},
		&le); err != nil {
		t.Fatal(err)
	}
	v, err := strconv.ParseInt(le.Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(v), deref(le.Spec.LeaseTransitions)
}

// rowDisable disables a connector with grant disable while it forwards and
// VPC 10's second connector forwards through the same instance: the
// disabled one stops within refreshBound, its next request is refused with
// 403, and the other is untouched.
func (s *service) rowDisable(t *testing.T) {
	c := s.grant(t, "c10-disabled", svcTenant10, 0x5a12, 0)
	s.disable(t, c, "h3")
}

// disable runs rowDisable's checks for connector c over transport.
func (s *service) disable(t *testing.T, c *svcConnector, transport string) {
	t.Helper()
	l := s.l
	rs, disabled := s.stopsWhileOtherForwards(t, "disable-"+transport, c, transport, 30*time.Second, func() time.Time {
		if _, err := s.authority(t, "grant", "disable", c.issued.Connector); err != nil {
			t.Fatal(err)
		}
		return time.Now()
	})
	if len(rs) == 0 {
		t.Fatal("the connector never forwarded")
	}
	last := rs[len(rs)-1].T - wallToBoot(disabled)
	l.record(t, "last reply after grant disable", last)
	if last > refreshBound {
		t.Errorf("the disabled connector forwarded %v after grant disable, bound %v", last, refreshBound)
	}
	dst := l.workloadOn(t, c.tn, edgeNode1).addr
	evs, err := s.once(s.pod, c, transport, dst)
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "disabled connector's next request", status(evs))
	if status(evs) != 403 || len(echoes(evs, dst)) > 0 {
		t.Errorf("the disabled connector's next request got %d with %d replies, want 403 and none", status(evs),
			len(echoes(evs, dst)))
	}
}

// expiryLifetime is the credential lifetime of an expiring connector: long
// enough to set up its attachment and forward, short enough to expire
// within its row.
const expiryLifetime = 50 * time.Second

// expiry grants a connector whose credential expires within the row and
// runs it over transport, with VPC 10's second connector forwarding
// through the same instance: the expiring one stops by its credential's
// expiry plus 1 s, its next request is refused with 401, and the other is
// untouched.
func (s *service) expiry(t *testing.T, transport string) {
	l := s.l
	c := s.grant(t, "c10-expiring-"+transport, svcTenant10, 0x5a13, expiryLifetime)
	d := time.Until(c.issued.Expires) + 5*time.Second
	if d < 20*time.Second {
		t.Fatalf("the credential expires in %v, too soon to forward first", time.Until(c.issued.Expires))
	}
	rs, _ := s.stopsWhileOtherForwards(t, "expiry-"+transport, c, transport, d, func() time.Time { return time.Now() })
	if len(rs) == 0 {
		t.Fatal("the connector never forwarded")
	}
	expires := wallToBoot(c.issued.Expires)
	last := rs[len(rs)-1].T - expires
	l.record(t, "last reply relative to the credential's expiry", last)
	// validUntil is the expiry rounded down to the second, and core stops
	// forwarding MaxSkew before it.
	if last > time.Second {
		t.Errorf("the connector forwarded %v past its credential's expiry, bound 1 s", last)
	}
	if last < -(time.Second + maxSkew + stopGap + margin) {
		t.Errorf("the connector stopped %v before its credential expired", -last)
	}
	dst := l.workloadOn(t, c.tn, edgeNode1).addr
	evs, err := s.once(s.pod, c, transport, dst)
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "expired connector's next request", status(evs))
	if status(evs) != 401 || len(echoes(evs, dst)) > 0 {
		t.Errorf("the expired connector's next request got %d with %d replies, want 401 and none", status(evs),
			len(echoes(evs, dst)))
	}
}

// metric is one sample of a provider's /metrics.
type metric struct {
	name   string
	labels map[string]string
	value  float64
}

// scrape reads pod's /metrics from its node.
func (s *service) scrape(t *testing.T, pod *corev1.Pod) []metric {
	t.Helper()
	out, err := nodeExec(pod.Spec.NodeName, "curl", "-sf", "--max-time", "5",
		"http://["+pod.Status.PodIP+"]:"+strconv.Itoa(svcHealthPort)+"/metrics")
	if err != nil {
		t.Fatal(err)
	}
	var ms []metric
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		m := metric{name: line[:i], labels: map[string]string{}, value: v}
		if j := strings.IndexByte(m.name, '{'); j >= 0 {
			for _, kv := range splitLabels(m.name[j+1 : len(m.name)-1]) {
				k, val, _ := strings.Cut(kv, "=")
				m.labels[k], _ = strconv.Unquote(val)
			}
			m.name = m.name[:j]
		}
		ms = append(ms, m)
	}
	return ms
}

// splitLabels splits a label set at the commas between its pairs.
func splitLabels(s string) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case s[i] == ',' && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// sum adds the samples of name whose labels include every pair of kv.
func sum(ms []metric, name string, kv ...string) float64 {
	total := 0.0
	for _, m := range ms {
		if m.name != name {
			continue
		}
		match := true
		for i := 0; i+1 < len(kv); i += 2 {
			if m.labels[kv[i]] != kv[i+1] {
				match = false
			}
		}
		if match {
			total += m.value
		}
	}
	return total
}

// probeStatus returns the HTTP status pod's health listener answers path
// with, from pod's node.
func (s *service) probeStatus(pod *corev1.Pod, path string) string {
	out, err := nodeExec(pod.Spec.NodeName, "curl", "-s", "-o", "/dev/null", "--max-time", "2", "-w", "%{http_code}",
		"http://["+pod.Status.PodIP+"]:"+strconv.Itoa(svcHealthPort)+path)
	if err != nil {
		return "error: " + out
	}
	return out
}

// rowReadiness checks the provider pod is Ready, answers its probes and
// holds its Lease, and runs unprivileged.
func (s *service) rowReadiness(t *testing.T) {
	l, pod := s.l, s.pod
	for path, want := range map[string]string{"/healthz": "200", "/readyz": "200"} {
		got := s.probeStatus(pod, path)
		l.record(t, path, got)
		if got != want {
			t.Errorf("%s answered %s, want %s", path, got, want)
		}
	}
	if v := sum(s.scrape(t, pod), "galactic_masque_lease_held"); v != 1 {
		t.Errorf("galactic_masque_lease_held is %v, want 1", v)
	}
	if !podReady(pod) {
		t.Error("the provider pod is not Ready")
	}
	spec := pod.Spec
	if spec.HostNetwork || spec.HostPID || spec.HostIPC {
		t.Errorf("provider pod shares a host namespace: network=%t pid=%t ipc=%t", spec.HostNetwork, spec.HostPID,
			spec.HostIPC)
	}
	pid, err := containerPID(pod.Spec.NodeName, pod.Namespace, pod.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	st, err := nodeExec(pod.Spec.NodeName, "grep", "-E", "^(Cap(Eff|Prm)|Uid):", "/proc/"+strconv.Itoa(pid)+"/status")
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "provider process", strings.ReplaceAll(st, "\n", "; "))
	for _, line := range strings.Split(st, "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.HasPrefix(f[0], "Cap") && f[1] != "0000000000000000" {
			t.Errorf("the provider process holds capabilities: %s", line)
		}
	}
	var auth corev1.PodList
	if err := l.c.List(context.Background(), &auth, client.InNamespace(svcNS),
		client.MatchingLabels{nameLabel: "masque-authority"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range append(auth.Items, *pod) {
		for _, cs := range p.Status.ContainerStatuses {
			l.record(t, "image "+cs.Image, cs.ImageID)
		}
	}
}

// rowLeaseReadiness partitions the provider pod from the API server: once
// its Lease's deadline passes, /readyz fails, galactic_masque_lease_held
// drops to 0, a new request is refused and the kubelet takes the pod out of
// service, while /healthz keeps answering. Healed, the pod is ready again
// and serves the connectors.
func (s *service) rowLeaseReadiness(t *testing.T) {
	l, pod := s.l, s.pod
	_, heal := l.partitionAPI(t, edgeNode1, podPID(t, edgeNode1, svcNS, pod.Name))
	time.Sleep(time.Second)
	last, _ := s.lease(t, pod)
	var unready time.Duration
	eventually(t, localExpiry+10*time.Second, 200*time.Millisecond, "/readyz failing", func() (bool, error) {
		now := boottime()
		if st := s.probeStatus(pod, "/readyz"); st != "503" {
			return false, fmt.Errorf("/readyz %s", st)
		}
		unready = now
		return true, nil
	})
	l.record(t, "/readyz failed after the last renewal start", unready-last)
	if unready-last > localExpiry+advertisementPoll {
		t.Errorf("/readyz kept answering 200 %v after the last renewal start, past the lease's %v", unready-last,
			localExpiry)
	}
	ms := s.scrape(t, pod)
	if v := sum(ms, "galactic_masque_lease_held"); v != 0 {
		t.Errorf("galactic_masque_lease_held is %v without the lease", v)
	}
	if st := s.probeStatus(pod, "/healthz"); st != "200" {
		t.Errorf("/healthz answered %s while the process runs", st)
	}
	dst := l.workloadOn(t, s.c10.tn, edgeNode1).addr
	evs, err := s.once(pod, s.c10, "h3", dst)
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "request without the lease", status(evs))
	if status(evs) != 503 || len(echoes(evs, dst)) > 0 {
		t.Errorf("a request without the lease got %d with %d replies, want 503 and none", status(evs),
			len(echoes(evs, dst)))
	}
	unreadyAt := time.Now()
	eventually(t, 30*time.Second, 500*time.Millisecond, "the kubelet marking the pod not ready", func() (bool, error) {
		p := &corev1.Pod{}
		err := l.c.Get(context.Background(), client.ObjectKeyFromObject(pod), p)
		return err == nil && !podReady(p), err
	})
	l.record(t, "pod not Ready after /readyz failed", time.Since(unreadyAt).Round(100*time.Millisecond))
	heal()
	healed := time.Now()
	s.pod = s.waitReady(t, "masque-provider", edgeNode1, "")
	l.record(t, "pod Ready again after the partition healed", time.Since(healed).Round(100*time.Millisecond))
	if s.pod.UID != pod.UID {
		t.Error("the partition replaced the pod")
	}
	if v := sum(s.scrape(t, s.pod), "galactic_masque_lease_held"); v != 1 {
		t.Errorf("galactic_masque_lease_held is %v after the partition healed", v)
	}
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
}

// rowProcessRestart kills the provider's process without shutdown while
// both connectors forward. The kubelet restarts the container in the same
// pod, and the new process adopts the pod's attachments, takes a later
// lease epoch and serves both connectors again on their adopted attachments
// under the same authorizations.
//
// A connector's authorization is valid for at most 28 s after its last
// refresh, and core stops it 2 s before that, while the new process can
// take its lease only once the old one's has expired, 15 s after the kill.
// The row therefore kills the process just after both connectors' grants
// were refreshed and reconnects both the moment the new process holds its
// lease, so each reconnects with its authorization still valid. An
// authorization that core has already stopped but the authority renews
// leaves the adopted attachment refused (#1236); the row does not test
// that case.
func (s *service) rowProcessRestart(t *testing.T) {
	l, ctx := s.l, context.Background()
	conns := []*svcConnector{s.c10, s.c20}
	runs := map[*svcConnector]*probeRun{}
	for _, c := range conns {
		runs[c] = s.connect(t, "before-kill-"+c.name, c, "h3", 40*time.Second, l.workloadOn(t, c.tn, edgeNode1).addr)
	}
	atts, svcs := s.freshGrants(t, conns)
	_, before := s.lease(t, s.pod)
	restartsBefore := restarts(s.pod)
	pid, err := containerPID(edgeNode1, svcNS, s.pod.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeExec(edgeNode1, "kill", "-KILL", strconv.Itoa(pid)); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	// The requests the kill cut off end at their QUIC idle timeout; they
	// are collected at the end of the row.
	defer func() {
		for _, c := range conns {
			runs[c].wait(l, t)
		}
	}()
	eventually(t, time.Minute, 200*time.Millisecond, "the restarted process holding its lease", func() (bool, error) {
		var le coordinationv1.Lease
		err := l.c.Get(ctx, client.ObjectKey{Namespace: svcNS, Name: "ei-" + string(s.pod.UID)}, &le)
		return err == nil && deref(le.Spec.LeaseTransitions) > before, client.IgnoreNotFound(err)
	})
	l.record(t, "lease taken again after the process was killed", time.Since(killed).Round(100*time.Millisecond))
	served := make(chan *svcConnector, len(conns))
	for _, c := range conns {
		dst := l.workloadOn(t, c.tn, edgeNode1).addr
		go func() {
			for time.Since(killed) < 2*time.Minute {
				if evs, err := s.once(s.pod, c, "h3", dst); err == nil && len(echoes(evs, dst)) > 0 {
					l.record(t, c.name+" serving again after the process was killed",
						time.Since(killed).Round(100*time.Millisecond))
					served <- c
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
			served <- nil
		}()
	}
	for range conns {
		c := <-served
		if c == nil {
			t.Fatal("a connector was not served again within 2 minutes of the kill")
		}
		cur := s.attachment(t, s.pod, c)
		if svc := s.issuedService(t, c); svc == nil || svc.UID != svcs[c] {
			t.Errorf("%s was served again under a new authorization", c.name)
		}
		if cur == nil || cur.UID != atts[c].UID {
			t.Errorf("%s was served again on a new attachment, not its adopted one", c.name)
		}
	}
	pod := &corev1.Pod{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(s.pod), pod); err != nil {
		t.Fatal(err)
	}
	l.record(t, "provider container restarts", restarts(pod)-restartsBefore)
	if restarts(pod) <= restartsBefore {
		t.Error("the provider's container was not restarted in the same pod")
	}
	s.pod = pod
	logs, err := l.kubectl("-n", svcNS, "logs", pod.Name, "-c", "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	l.save(t, "provider.log", []byte(logs))
	for _, c := range conns {
		att := atts[c]
		if !slices.ContainsFunc(strings.Split(logs, "\n"), func(line string) bool {
			return strings.Contains(line, `"msg":"adopted attachment"`) && strings.Contains(line, att.Name)
		}) {
			t.Errorf("the restarted process did not adopt %s's attachment %s", c.name, att.Name)
		}
	}
	s.pod = s.waitReady(t, "masque-provider", edgeNode1, "")
}

// freshGrants waits until the open requests of conns are admitted, each
// holding its accepted route claim, and then until both forward on grants
// refreshed within the last 3 s, so each validUntil is at least 25 s away.
// It returns each connector's attachment and EdgeService UID.
func (s *service) freshGrants(t *testing.T, conns []*svcConnector) (
	map[*svcConnector]*galacticv1alpha1.EdgeAttachment, map[*svcConnector]types.UID) {
	t.Helper()
	l := s.l
	eventually(t, time.Minute, 200*time.Millisecond, "the requests admitted", func() (bool, error) {
		for _, c := range conns {
			r := l.route(t, svcNS, c.vpcUID, netip.MustParsePrefix(c.issued.Prefix))
			if r == nil || r.Spec.Claim == nil || r.Spec.Claim.Released ||
				!meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
				return false, nil
			}
		}
		return true, nil
	})
	// Each open request's grant is refreshed every 5 s from here on.
	time.Sleep(6 * time.Second)
	atts := map[*svcConnector]*galacticv1alpha1.EdgeAttachment{}
	svcs := map[*svcConnector]types.UID{}
	eventually(t, time.Minute, 200*time.Millisecond, "the connectors forwarding on fresh grants", func() (bool, error) {
		for _, c := range conns {
			atts[c] = s.attachment(t, s.pod, c)
			svc := s.issuedService(t, c)
			if atts[c] == nil || svc == nil || svc.Spec.ValidUntil == nil ||
				!meta.IsStatusConditionTrue(atts[c].Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) ||
				time.Until(svc.Spec.ValidUntil.Time) < 25*time.Second {
				return false, nil
			}
			svcs[c] = svc.UID
		}
		return true, nil
	})
	return atts, svcs
}

// restarts is how many times pod's containers restarted.
func restarts(p *corev1.Pod) int32 {
	n := int32(0)
	for _, cs := range p.Status.ContainerStatuses {
		n += cs.RestartCount
	}
	return n
}

// issuedService returns the EdgeService the authority issued for c, or nil.
func (s *service) issuedService(t *testing.T, c *svcConnector) *galacticv1alpha1.EdgeService {
	t.Helper()
	var svc galacticv1alpha1.EdgeService
	err := s.l.c.Get(context.Background(), client.ObjectKey{Namespace: c.tn.vpcNamespace,
		Name: "masque-" + c.issued.Connector}, &svc)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return &svc
}

// attachment returns pod's attachment to c's current EdgeService, and
// records its host link for teardown.
func (s *service) attachment(t *testing.T, pod *corev1.Pod, c *svcConnector) *galacticv1alpha1.EdgeAttachment {
	t.Helper()
	svc := s.issuedService(t, c)
	if svc == nil {
		return nil
	}
	att := s.l.attachmentOf(t, pod, svc)
	if att != nil && att.Status.HostLink != "" {
		s.links[att.Name] = att.Status.HostLink
	}
	return att
}

// rowDrain deletes the provider pod while VPC 10's connector forwards
// through it. SIGTERM ends the request at once, and before the pod is gone
// the provider releases the connector's route claim, deletes its
// attachments and releases its Lease, all within the 20 s the service
// gives that, and the pod exits within its 30 s grace period. The
// Deployment's replacement then serves the connector.
func (s *service) rowDrain(t *testing.T) {
	l, ctx := s.l, context.Background()
	old := s.pod
	c := s.c10
	dst := l.workloadOn(t, c.tn, edgeNode1).addr
	att := s.attachment(t, old, s.c10)
	p := s.connect(t, "drain", c, "h3", 40*time.Second, dst)
	eventually(t, time.Minute, 500*time.Millisecond, c.name+"'s attachment on the old pod", func() (bool, error) {
		att = s.attachment(t, old, c)
		return att != nil, nil
	})
	time.Sleep(3 * time.Second)
	route := netip.MustParsePrefix(c.issued.Prefix)
	if _, err := l.kubectl("-n", svcNS, "delete", "pod", old.Name, "--wait=false"); err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	type seen struct{ released, detached, leaseReleased, gone time.Duration }
	var at seen
	since := func() time.Duration { return time.Since(deleted).Round(100 * time.Millisecond) }
	leaseKey := client.ObjectKey{Namespace: svcNS, Name: "ei-" + string(old.UID)}
	for at.gone == 0 && time.Since(deleted) < 45*time.Second {
		if at.released == 0 {
			if r := l.route(t, svcNS, c.vpcUID, route); r == nil || r.Spec.Claim == nil || r.Spec.Claim.Released ||
				r.Spec.Claim.Attachment != att.Name {
				at.released = since()
			}
		}
		if at.detached == 0 && l.attachmentOf(t, old, s.issuedService(t, c)) == nil {
			at.detached = since()
		}
		if at.leaseReleased == 0 {
			var le coordinationv1.Lease
			err := l.c.Get(ctx, leaseKey, &le)
			if apierrors.IsNotFound(err) ||
				(err == nil && le.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] == "true") {
				at.leaseReleased = since()
			}
		}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); apierrors.IsNotFound(err) {
			at.gone = since()
		}
		time.Sleep(200 * time.Millisecond)
	}
	evs := p.wait(l, t)
	rs := echoes(evs, dst)
	if len(rs) == 0 {
		t.Fatal("the connector never forwarded through the old pod")
	}
	lastReply := rs[len(rs)-1].T - wallToBoot(deleted)
	l.record(t, "last reply after the pod's deletion", lastReply)
	l.record(t, "route claim released after the deletion", at.released)
	l.record(t, "attachment deleted after the deletion", at.detached)
	l.record(t, "lease released after the deletion", at.leaseReleased)
	l.record(t, "pod gone after the deletion", at.gone)
	if lastReply > stopGap {
		t.Errorf("the request forwarded %v after SIGTERM", lastReply)
	}
	if !slices.ContainsFunc(evs, func(e event) bool { return e.End && e.T < wallToBoot(deleted)+5*time.Second }) {
		t.Error("the server did not end the request on SIGTERM")
	}
	for what, d := range map[string]time.Duration{"route claim release": at.released, "attachment deletion": at.detached,
		"lease release": at.leaseReleased} {
		if d == 0 || d > 20*time.Second || (at.gone != 0 && d > at.gone) {
			t.Errorf("%s took %v, want it within 20 s and before the pod was gone (%v)", what, d, at.gone)
		}
	}
	if at.gone == 0 || at.gone >= 30*time.Second {
		t.Errorf("the pod took %v to go, want it to exit within its 30 s grace period", at.gone)
	}
	s.pod = s.waitReady(t, "masque-provider", edgeNode1, old.UID)
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
	l.record(t, "replacement serving after the deletion", time.Since(deleted).Round(time.Second))
}

// teardown removes the service in the order docs/edge/masque-service.md
// gives, and fails the run unless everything it created is gone and
// everything it did not create is untouched.
func (s *service) teardown(t *testing.T) {
	l, ctx := s.l, context.Background()
	for _, c := range []*svcConnector{s.c10, s.c10b, s.c20} {
		if c != nil && s.pod != nil {
			s.attachment(t, s.pod, c)
		}
	}
	// The provider's pods release their routes and attachments as they
	// stop, before the authority and the registration go.
	if _, err := l.kubectl("delete", "-k", s.overlay("provider"), "--ignore-not-found", "--wait=true",
		"--timeout=120s"); err != nil {
		t.Error(err)
	}
	eventually(t, 2*time.Minute, time.Second, "provider pods gone", func() (bool, error) {
		var pods corev1.PodList
		err := l.c.List(ctx, &pods, client.InNamespace(svcNS),
			client.MatchingLabels{nameLabel: "masque-provider"})
		return err == nil && len(pods.Items) == 0, err
	})
	l.waitEdgeObjectsGone(t, svcNS)
	if _, err := l.kubectl("delete", "-k", s.overlay("authority"), "--ignore-not-found", "--wait=true",
		"--timeout=120s"); err != nil {
		t.Error(err)
	}
	// The authority issued every connector's EdgeService; with it gone,
	// nothing else removes them.
	for _, tn := range []tenant{svcTenant10, svcTenant20} {
		var svcs galacticv1alpha1.EdgeServiceList
		if err := l.c.List(ctx, &svcs, client.InNamespace(tn.vpcNamespace)); err != nil {
			t.Error(err)
		}
		for i := range svcs.Items {
			if svcs.Items[i].Spec.ProviderRef.Name == svcProvider {
				l.deleteAndWait(t, &svcs.Items[i])
			}
		}
	}
	if _, err := l.kubectl("delete", "-k", s.overlay(), "--ignore-not-found", "--wait=true",
		"--timeout=180s"); err != nil {
		t.Error(err)
	}
	l.requireNoEdgeAdvertisements(t, svcNS)
	requireLinksGone(t, s.links)
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		if _, err := nodeExec(n, "rm", "-f", svcCA, svcOtherCA); err != nil {
			t.Error(err)
		}
	}
	for _, tn := range []tenant{svcTenant10, svcTenant20} {
		for i := 1; i <= 3; i++ {
			p := l.clientPod(t, tn, i)
			if want := s.unrelated[p.Namespace+"/"+p.Name]; want != p.UID {
				t.Errorf("unrelated pod %s/%s was replaced", p.Namespace, p.Name)
			}
		}
		c1, w2 := l.clientPod(t, tn, 1), l.workloadOn(t, tn, edgeNode1)
		if out, err := l.kubectl("-n", c1.Namespace, execVerb, c1.Name, "--", "ping", "-6", "-c", "3", "-W", "2",
			w2.addr); err != nil {
			t.Errorf("VPC %s's workloads no longer reach each other after teardown: %v: %s", tn.vpc, err, out)
		}
	}
}
