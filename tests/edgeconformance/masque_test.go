// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// The MASQUE fixture's provider, grants and connectors. Both tenants'
// connectors hold the same /96, so their packets are told apart only by the
// VPC they enter; each tenant's client uses its own ICMPv6 echo identifier
// so a packet seen anywhere names the client that sent it.
const (
	masqueNS       = "edge-masque"
	masqueProvider = "masque-fixture"
	masqueService  = "svc-masque"
	masqueGrant    = "fd00:ed9e:300::/48"
	masquePool     = "fd00:ed9e:0:30::/64"
	masquePrefix   = "fd00:ed9e:300:1::/96"
	// masqueSecond is VPC 10's second connector, in the same service as
	// its first, so the two share one attachment.
	masqueSecond  = "fd00:ed9e:300:2::/96"
	masqueOutside = "fd00:ed9e:400:1::/96"
	// masquePartial is the partly set-up instance's /96, also outside the
	// grant and claimed by no other instance.
	masquePartial   = "fd00:ed9e:400:2::/96"
	masqueAuthority = "masque.test:8443"
	masquePort      = 8443
	// remoteHost is the lab's off-fabric host, reached through the NAT
	// shards.
	remoteHost = "2001:db8:1:40::2"
	// masqueCA is where the suite copies the fixture's CA onto each node.
	masqueCA = "/usr/local/share/masque-ca.pem"
	systemNS = "galactic-system"
)

// masqueTenant is one VPC's connector.
type masqueTenant struct {
	tn     tenant
	svc    *galacticv1alpha1.EdgeService
	vpcUID string
	vpcID  string
	token  string
	id     int
}

// masque is the MASQUE fixture: one provider pod serving both tenants.
type masque struct {
	l    *lab
	a, b *masqueTenant
	// refused is the credential of a connector whose route core refuses.
	refused string
	// second is the credential of VPC 10's second connector.
	second  string
	certPEM []byte
	keyPEM  []byte
	// pod is the running pod of the fixture's main Deployment.
	pod *corev1.Pod
	// links maps every attachment the run created to its host link, for
	// teardown's check that none remains.
	links map[string]string
	// unrelated holds the UIDs of the tenants' edge-client pods, which the
	// run must leave in place.
	unrelated map[string]types.UID
}

// TestMASQUE proves CONNECT-IP packet access on the Galactic Edge foundation
// with the MASQUE fixture provider (tests/edgeconformance/masqueprovider),
// which runs the MASQUE provider adapter (internal/edge/masque): the
// deployed agent creates the fixture's PacketAccess devices and the
// unprivileged fixture opens them, two VPCs with identical connector /96s
// stay isolated in both directions, NAT egress works from the attachment
// node, two connectors share one attachment and ending one leaves the
// other forwarding, a restarted provider process adopts its attachments,
// router maintenance keeps an attachment in use, a connector's second
// request replaces its first without both forwarding, a stalled provider,
// a stalled agent and an API partition each stop forwarding within the
// local expiry bound, recreation, partial setup and teardown clean up
// through core while leaving unrelated and replacement resources alone, and
// one connector's expired grant stops it while another keeps the shared
// instance renewing. Run it with task verify:masque-conformance.
func TestMASQUE(t *testing.T) {
	l := getLab(t)
	t.Cleanup(func() { l.writeSummary(t) })
	m := newMasque(t, l)
	if os.Getenv("EDGE_CONFORMANCE_KEEP") == "" {
		t.Cleanup(func() { m.teardown(t) })
	}
	if !t.Run("setup", m.setup) {
		t.FailNow()
	}
	t.Run("M16-unprivileged-provider", m.rowUnprivileged)
	t.Run("M16-refused-requests", m.rowRefusedRequests)
	t.Run("M16-missing-device", m.rowMissingDevice)
	t.Run("A06-packet-access-registration", m.rowRegistration)
	t.Run("M07-isolation", func(t *testing.T) { m.isolation(t, "cold") })
	t.Run("nat-egress", m.rowNATEgress)
	t.Run("A16-pod-link-route-drift", m.rowRouteDrift)
	t.Run("shared-attachment-cancel", m.rowSharedCancel)
	t.Run("maintenance-during-use", m.rowMaintenance)
	t.Run("process-restart", m.rowProcessRestart)
	t.Run("same-pod-replacement", m.rowReplace)
	t.Run("provider-stall", m.rowProviderStall)
	t.Run("agent-stall", m.rowAgentStall)
	t.Run("api-partition", m.rowAPIPartition)
	t.Run("partial-setup", m.rowPartial)
	t.Run("recreation", m.rowRecreation)
	t.Run("connector-revocation", m.rowConnectorRevocation)
}

func newMasque(t *testing.T, l *lab) *masque {
	t.Helper()
	certPEM, keyPEM, caPEM := masqueCerts(t)
	ca := filepath.Join(l.artifacts, "masque-ca.pem")
	if err := os.WriteFile(ca, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		cp := exec.CommandContext(context.Background(), "docker", "cp", ca, n+":"+masqueCA)
		if out, err := cp.CombinedOutput(); err != nil {
			t.Fatalf("copy CA to %s: %v: %s", n, err, out)
		}
	}
	return &masque{
		l: l,
		a: &masqueTenant{tn: tenant{vpcNamespace: "ns10", vpc: "10", provider: masqueProvider},
			token: rand.Text(), id: 0x0a10},
		b: &masqueTenant{tn: tenant{vpcNamespace: "ns20", vpc: "20", provider: masqueProvider},
			token: rand.Text(), id: 0x0b20},
		refused: rand.Text(), second: rand.Text(), certPEM: certPEM, keyPEM: keyPEM,
		links: map[string]string{}, unrelated: map[string]types.UID{},
	}
}

// masqueCerts returns a server certificate for the authority's host, its
// key, and the CA that signed it.
func masqueCerts(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "masque conformance CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.Split(masqueAuthority, ":")[0]
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func (m *masque) setup(t *testing.T) {
	l := m.l
	for _, mt := range []*masqueTenant{m.a, m.b} {
		for i := 1; i <= 2; i++ {
			p := m.client(t, mt.tn, i)
			m.unrelated[p.Namespace+"/"+p.Name] = p.UID
		}
	}
	l.ensureNamespace(t, masqueNS)
	l.applyOverlayOf(t, filepath.Join(l.root, "tests", "edgeconformance", "masqueprovider", "deploy", "registration"),
		"masque-registration", "", nil)
	if _, err := l.kubectl("patch", "edgeprovider", masqueProvider, "--subresource=status", "--type=merge",
		"-p", `{"status":{"approved":true}}`); err != nil {
		t.Fatal(err)
	}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		mt.vpcUID, mt.vpcID = l.vpcUID(t, mt.tn), l.vpcID(t, mt.tn)
		mt.svc = l.grantService(t, mt.tn, masqueService, func(s *galacticv1alpha1.EdgeService) {
			s.Spec.Capabilities = []string{capPacket, "PrefixReachability"}
			s.Spec.Prefixes = []string{masqueGrant}
			s.Spec.ClientPool = masquePool
		})
		l.waitServiceAdmitted(t, mt.svc, true)
	}
	m.pod = m.deploy(t, "m1", edgeNode1, m.config(true))
	// The adapter requests a connector's attachment and claims its route
	// when a request first needs them.
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
	m.waitServing(t, m.pod)
}

// fixtureConfig, fixtureService and fixtureConnector are the fixture's
// config.yaml (tests/edgeconformance/masqueprovider/config.go).
type fixtureConfig struct {
	Provider   string             `json:"provider"`
	Authority  string             `json:"authority"`
	Listen     string             `json:"listen"`
	Services   []fixtureService   `json:"services"`
	Connectors []fixtureConnector `json:"connectors"`
}

type fixtureService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	VPCUID    string `json:"vpcUID"`
	VPCID     string `json:"vpcID"`
	VPC       string `json:"vpc"`
}

type fixtureConnector struct {
	ID         string   `json:"id"`
	Credential string   `json:"credential"`
	Service    string   `json:"service"`
	Prefix     string   `json:"prefix"`
	Routes     []string `json:"routes,omitempty"`
}

// config is the fixture's config.yaml: both tenants' services and
// connectors, VPC 10's second connector, plus, when withRefused is set, a
// VPC 10 connector whose /96 lies outside the grant, so core refuses its
// route.
func (m *masque) config(withRefused bool) string {
	svcs := make([]fixtureService, 0, 2)
	conns := make([]fixtureConnector, 0, 4)
	for _, mt := range []*masqueTenant{m.a, m.b} {
		svcs = append(svcs, mt.serviceConfig())
		conns = append(conns, fixtureConnector{ID: "connector-" + mt.tn.vpc, Credential: mt.token,
			Service: mt.serviceKey(), Prefix: masquePrefix,
			Routes: []string{"fd20:" + mt.tn.vpc + "::/32", remoteHost + "/128"}})
	}
	conns = append(conns, fixtureConnector{ID: "connector-10-second", Credential: m.second,
		Service: m.a.serviceKey(), Prefix: masqueSecond, Routes: []string{"fd20:10::/32"}})
	if withRefused {
		conns = append(conns, fixtureConnector{ID: "connector-outside", Credential: m.refused,
			Service: m.a.serviceKey(), Prefix: masqueOutside})
	}
	return marshalConfig(svcs, conns)
}

// serviceConfig is mt's grant as the fixture's config.yaml lists it.
func (mt *masqueTenant) serviceConfig() fixtureService {
	return fixtureService{Namespace: mt.svc.Namespace, Name: mt.svc.Name, UID: string(mt.svc.UID),
		VPCUID: mt.vpcUID, VPCID: mt.vpcID, VPC: mt.tn.vpc}
}

// serviceKey is how a fixture connector names mt's service.
func (mt *masqueTenant) serviceKey() string { return mt.svc.Namespace + "/" + mt.svc.Name }

func marshalConfig(svcs []fixtureService, conns []fixtureConnector) string {
	b, _ := json.Marshal(fixtureConfig{Provider: masqueProvider, Authority: masqueAuthority,
		Listen: ":" + strconv.Itoa(masquePort), Services: svcs, Connectors: conns})
	return string(b)
}

// deploy runs the fixture's Deployment name on node with cfg and returns its
// running pod.
func (m *masque) deploy(t *testing.T, name, node, cfg string, patches ...string) *corev1.Pod {
	t.Helper()
	l := m.l
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: masqueNS, Name: "masque-config-" + name},
		Data:       map[string][]byte{"config.yaml": []byte(cfg), "tls.crt": m.certPEM, "tls.key": m.keyPEM},
	}
	l.deleteAndWait(t, &corev1.Secret{ObjectMeta: secret.ObjectMeta})
	if err := l.c.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	l.applyOverlayOf(t, filepath.Join(l.root, "tests", "edgeconformance", "masqueprovider", "deploy", "provider"),
		"masque-"+name, fmt.Sprintf(`
namespace: %s
patches:
  - target:
      kind: Deployment
    options:
      allowNameChange: true
    patch: |-
      - op: replace
        path: /metadata/name
        value: masque-provider-%s
      - op: replace
        path: /spec/template/spec/volumes/0/secret/secretName
        value: masque-config-%s
      - op: add
        path: /spec/template/spec/nodeSelector
        value: {kubernetes.io/hostname: %s}
      - op: add
        path: /spec/template/spec/tolerations
        value: [{key: galactic.datumapis.com/nat, operator: Exists, effect: NoSchedule}]
      - op: add
        path: /metadata/labels/edge-conformance~1instance
        value: %s
      - op: add
        path: /spec/template/metadata/labels/edge-conformance~1instance
        value: %s
      - op: add
        path: /spec/selector/matchLabels/edge-conformance~1instance
        value: %s
`, masqueNS, name, name, node, name, name, name)+strings.Join(patches, ""), nil)
	return l.waitProviderPod(t, masqueNS, name, node)
}

// waitServing waits until pod's attachments to both services are ready,
// and records their host links.
func (m *masque) waitServing(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	for _, mt := range []*masqueTenant{m.a, m.b} {
		att := m.l.waitServing(t, pod, mt.svc)
		m.links[att.Name] = att.Status.HostLink
	}
}

// waitConnected waits until mt's connector is admitted and its tenant's
// workload on the provider's node answers through it.
func (m *masque) waitConnected(t *testing.T, mt *masqueTenant) {
	t.Helper()
	dst := m.workload(t, mt.tn, 2).addr
	eventually(t, 2*time.Minute, 2*time.Second, "connector of VPC "+mt.tn.vpc+" answered", func() (bool, error) {
		evs, err := m.connectOnce(mt.token, mt.tn.vpc, mt.id, time.Second, dst)
		if err != nil {
			return false, err
		}
		return len(echoes(evs, dst)) > 0, nil
	})
}

// connect runs one CONNECT-IP session to the fixture's pod from its node's
// host network, pinging dsts. The client runs on the pod's node because the
// lab's pod network does not carry UDP from a node to a pod on another node;
// where the client runs does not change the gVPC path behind the fixture.
func (m *masque) connect(t *testing.T, name, token, vpc string, id int, d time.Duration, dsts ...string) *probeRun {
	t.Helper()
	p, err := startProbe(m.pod.Spec.NodeName, 1, name, connectArgs(m.pod, token, vpc, id, d, dsts)...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func connectArgs(pod *corev1.Pod, token, vpc string, id int, d time.Duration, dsts []string) []string {
	return []string{"connectip", "-server", "[" + pod.Status.PodIP + "]:" + strconv.Itoa(masquePort),
		"-authority", masqueAuthority, "-ca", masqueCA, "-token", token, "-vpc", vpc, "-id", strconv.Itoa(id),
		"-to", strings.Join(dsts, ","), "-interval", probeInterval.String(), "-duration", d.String()}
}

// connectOnce runs one short session to the fixture's pod and returns its
// events.
func (m *masque) connectOnce(token, vpc string, id int, d time.Duration, dsts ...string) ([]event, error) {
	return connectOnceTo(m.pod, token, vpc, id, d, dsts...)
}

// connectOnceTo runs one short session to pod and returns its events.
func connectOnceTo(pod *corev1.Pod, token, vpc string, id int, d time.Duration, dsts ...string) ([]event, error) {
	p, err := startProbe(pod.Spec.NodeName, 1, "once", connectArgs(pod, token, vpc, id, d, dsts)...)
	if err != nil {
		return nil, err
	}
	if err := p.cmd.Wait(); err != nil {
		return nil, fmt.Errorf("connectip: %w: %s", err, p.out.String())
	}
	var evs []event
	for _, line := range strings.Split(strings.TrimSpace(p.out.String()), "\n") {
		var e event
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	return evs, nil
}

// echoes returns the echo replies from dst.
func echoes(evs []event, dst string) []event {
	var out []event
	for _, e := range evs {
		if e.Reply == "echo" && e.From == dst {
			out = append(out, e)
		}
	}
	return out
}

// others counts the packets the tunnel delivered that were not echo replies
// to this client.
func others(evs []event) int {
	n := 0
	for _, e := range evs {
		if e.Reply == "other" {
			n++
		}
	}
	return n
}

// requireSession fails unless evs is a request that was accepted with the
// connector /96 and sent through its whole window of d to n destinations. A
// refused request, or a tunnel the server closed early, sends fewer than 90%
// of the probes the window holds, so its reply ratio alone proves nothing.
func requireSession(t *testing.T, what string, evs []event, d time.Duration, n int) {
	t.Helper()
	requireSessionFor(t, what, evs, d, n, masquePrefix)
}

// requireSessionFor is requireSession for a connector assigned prefix.
func requireSessionFor(t *testing.T, what string, evs []event, d time.Duration, n int, prefix string) {
	t.Helper()
	if s := status(evs); s != 200 {
		t.Errorf("%s: status %d, want 200", what, s)
	}
	assigned := ""
	for _, e := range evs {
		if e.Assigned != "" {
			assigned = e.Assigned
		}
	}
	if assigned != prefix {
		t.Errorf("%s: assigned %q, want %s", what, assigned, prefix)
	}
	if want, got := int(d/probeInterval)*n, sentCount(evs); got < want*9/10 {
		t.Errorf("%s: sent %d of the window's %d probes", what, got, want)
	}
}

// requireAnswered fails unless evs is a whole session of d to dst in which
// at least 90% of the probes were answered, no two answers were more than a
// second apart, and nothing else arrived.
func (m *masque) requireAnswered(t *testing.T, what string, evs []event, d time.Duration, dst string) {
	t.Helper()
	requireSession(t, what, evs, d, 1)
	rs := echoes(evs, dst)
	m.l.record(t, what, fmt.Sprintf("%d/%d, largest gap %v, %d other", len(rs), sentCount(evs), largestGap(rs),
		others(evs)))
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second || others(evs) > 0 {
		t.Errorf("%s: %d of %d answered, largest gap %v, %d other packets", what, len(rs), sentCount(evs),
			largestGap(rs), others(evs))
	}
}

func status(evs []event) int {
	for _, e := range evs {
		if e.Status != 0 {
			return e.Status
		}
	}
	return 0
}

// workloadRef is a tenant workload: its node, sandbox, link and address.
type workloadRef struct {
	node  string
	pid   int
	iface string
	addr  string
}

// workload returns tenant tn's edge client i: 1 on the compute node, 2 on
// the fixture's node.
func (m *masque) workload(t *testing.T, tn tenant, i int) workloadRef {
	t.Helper()
	node := map[int]string{1: computeNode, 2: edgeNode1}[i]
	pid := m.l.clientPID(t, tn, node)
	out, err := nodeExec(node, "nsenter", "-t", strconv.Itoa(pid), "-n", "ip", "-6", "-o", "addr", "show",
		"scope", "global")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.HasPrefix(f[3], "fd20:"+tn.vpc+":") {
			return workloadRef{node: node, pid: pid, iface: f[1], addr: strings.Split(f[3], "/")[0]}
		}
	}
	t.Fatalf("no VPC %s address on edge-client-%d: %s", tn.vpc, i, out)
	return workloadRef{}
}

// client returns tenant tn's running edge-client-i pod.
func (m *masque) client(t *testing.T, tn tenant, i int) *corev1.Pod {
	t.Helper()
	var pods corev1.PodList
	if err := m.l.c.List(context.Background(), &pods, client.InNamespace(tn.vpcNamespace),
		client.MatchingLabels{appLabel: "edge-client-" + strconv.Itoa(i)}); err != nil {
		t.Fatal(err)
	}
	for i := range pods.Items {
		if p := &pods.Items[i]; p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			return p
		}
	}
	t.Fatalf("no running edge-client-%d in %s", i, tn.vpcNamespace)
	return nil
}

func (m *masque) rowUnprivileged(t *testing.T) {
	l, pod := m.l, m.pod
	spec := pod.Spec
	if spec.HostNetwork || spec.HostPID || spec.HostIPC {
		t.Errorf("fixture pod shares a host namespace: network=%t pid=%t ipc=%t", spec.HostNetwork, spec.HostPID,
			spec.HostIPC)
	}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			t.Errorf("fixture pod mounts hostPath %s", v.HostPath.Path)
		}
	}
	for _, c := range spec.Containers {
		sc := c.SecurityContext
		if sc == nil || sc.Capabilities == nil || !slices.Contains(sc.Capabilities.Drop, "ALL") ||
			len(sc.Capabilities.Add) > 0 || (sc.Privileged != nil && *sc.Privileged) {
			t.Errorf("container %s is not unprivileged: %+v", c.Name, sc)
		}
	}
	pid, err := containerPID(edgeNode1, pod.Namespace, pod.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	st, err := nodeExec(edgeNode1, "grep", "-E", "^(Cap(Eff|Prm|Bnd)|Uid|Gid):", "/proc/"+strconv.Itoa(pid)+"/status")
	if err != nil {
		t.Fatal(err)
	}
	l.save(t, "process-status.txt", []byte(st))
	for _, line := range strings.Split(st, "\n") {
		if f := strings.Fields(line); len(f) == 2 && (f[0] == "CapEff:" || f[0] == "CapPrm:") &&
			f[1] != "0000000000000000" {
			t.Errorf("fixture process holds capabilities: %s", line)
		}
	}
	l.record(t, "fixture process", strings.ReplaceAll(st, "\n", "; "))

	m.checkPacketDevices(t)
	m.checkAdmission(t)
	m.recordVersions(t)
}

// checkPacketDevices checks that galactic-edge created each packet device
// in the fixture's pod, owned by the fixture's UID, and that the fixture
// opened it and reported Ready.
func (m *masque) checkPacketDevices(t *testing.T) {
	t.Helper()
	l, pod := m.l, m.pod
	sandbox := podPID(t, edgeNode1, pod.Namespace, pod.Name)
	for _, mt := range []*masqueTenant{m.a, m.b} {
		att := l.attachmentOf(t, pod, mt.svc)
		dev, err := nodeExec(edgeNode1, "nsenter", "-t", strconv.Itoa(sandbox), "-n", "ip", "-d", "link", "show",
			"dev", att.Status.PacketDevice)
		if err != nil {
			t.Fatal(err)
		}
		l.record(t, "VPC "+mt.tn.vpc+" packet device", strings.Join(strings.Fields(dev), " "))
		if !strings.Contains(dev, "tun type tun") || !strings.Contains(dev, "user 65532 group 65532") {
			t.Errorf("VPC %s packet device %s is not a TUN device owned by 65532: %s", mt.tn.vpc,
				att.Status.PacketDevice, dev)
		}
		c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady)
		if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "Serving" {
			t.Errorf("VPC %s attachment not served by the fixture: %+v", mt.tn.vpc, c)
		}
	}

}

// checkAdmission checks that admission refuses an unknown credential, a
// credential presented for the other VPC, and a connector whose route core
// refused.
func (m *masque) checkAdmission(t *testing.T) {
	t.Helper()
	l := m.l
	dst := m.workload(t, m.a.tn, 2).addr
	for _, c := range []struct {
		what, token, vpc string
		want             int
	}{
		{"unknown credential", rand.Text(), "10", 401},
		{"VPC 10 credential for VPC 20", m.a.token, "20", 403},
		{"connector with a refused route", m.refused, "10", 503},
	} {
		evs, err := m.connectOnce(c.token, c.vpc, 1, time.Second, dst)
		if err != nil {
			t.Fatal(err)
		}
		l.record(t, c.what, status(evs))
		if got := status(evs); got != c.want || len(echoes(evs, dst)) > 0 {
			t.Errorf("%s: status %d with %d replies, want %d and none", c.what, got, len(echoes(evs, dst)), c.want)
		}
	}
	// The refused connector's request claimed its route, which core refused.
	att := l.attachmentOf(t, m.pod, m.a.svc)
	l.record(t, "outside-grant route", m.waitRefused(t, m.a.vpcUID, netip.MustParsePrefix(masqueOutside), att.Name))
}

// recordVersions saves what the run executed against: Kubernetes, the
// nodes' kernels and runtimes, and the image of every component the rows
// exercise.
func (m *masque) recordVersions(t *testing.T) {
	t.Helper()
	l := m.l
	v := map[string]string{}
	if out, err := l.kubectl("version", "-o", "json"); err == nil {
		v["kubernetes"] = strings.Join(strings.Fields(out), " ")
	}
	var nodes corev1.NodeList
	if err := l.c.List(context.Background(), &nodes); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes.Items {
		v["node "+n.Name] = n.Status.NodeInfo.KernelVersion + ", " + n.Status.NodeInfo.ContainerRuntimeVersion +
			", " + n.Status.NodeInfo.KubeletVersion
	}
	var pods corev1.PodList
	for _, ns := range []string{systemNS, "kube-system", masqueNS} {
		if err := l.c.List(context.Background(), &pods, client.InNamespace(ns)); err != nil {
			t.Fatal(err)
		}
		for _, p := range pods.Items {
			if p.Spec.NodeName != edgeNode1 && p.Spec.NodeName != computeNode {
				continue
			}
			for _, cs := range p.Status.ContainerStatuses {
				v["image "+cs.Image] = cs.ImageID
			}
		}
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	l.save(t, "versions.json", b)
	for k, s := range v {
		l.record(t, k, s)
	}
}

// isolation sends from each tenant's connector, at once, to its own
// workloads on the compute node and on the fixture's node and to the other
// tenant's, with neighbor caches flushed first. Each tenant's own workloads
// answer; nothing reaches the other tenant's workloads, whose links are
// captured, and no client receives a packet that is not its own reply.
func (m *masque) isolation(t *testing.T, label string) {
	l := m.l
	wl := map[*masqueTenant][]workloadRef{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		wl[mt] = []workloadRef{m.workload(t, mt.tn, 1), m.workload(t, mt.tn, 2)}
		for _, w := range wl[mt] {
			if _, err := nodeExec(w.node, "nsenter", "-t", strconv.Itoa(w.pid), "-n", "ip", "-6", "neigh", "flush",
				"all"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, link := range m.currentLinks(t) {
		if _, err := nodeExec(edgeNode1, "ip", "-6", "neigh", "flush", "dev", link); err != nil {
			t.Fatal(err)
		}
	}
	type sniffer struct {
		w  workloadRef
		mt *masqueTenant
		p  *probeRun
	}
	var sniffs []sniffer
	for _, mt := range []*masqueTenant{m.a, m.b} {
		for _, w := range wl[mt] {
			p, err := startProbe(w.node, w.pid, label+"-sniff-"+mt.tn.vpc+"-"+w.node, "sniff", "-iface", w.iface,
				"-icmp", "-duration", "9s")
			if err != nil {
				t.Fatal(err)
			}
			sniffs = append(sniffs, sniffer{w, mt, p})
		}
	}
	time.Sleep(time.Second)
	runs := map[*masqueTenant]*probeRun{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		other := m.b
		if mt == m.b {
			other = m.a
		}
		dsts := []string{wl[mt][0].addr, wl[mt][1].addr, wl[other][0].addr, wl[other][1].addr}
		runs[mt] = m.connect(t, label+"-vpc-"+mt.tn.vpc, mt.token, mt.tn.vpc, mt.id, 5*time.Second, dsts...)
	}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		other := m.b
		if mt == m.b {
			other = m.a
		}
		evs := runs[mt].wait(l, t)
		requireSession(t, "VPC "+mt.tn.vpc+"'s request", evs, 5*time.Second, 4)
		perDst := sentCount(evs) / 4
		for _, w := range wl[mt] {
			n := len(echoes(evs, w.addr))
			l.record(t, fmt.Sprintf("VPC %s to its workload on %s", mt.tn.vpc, w.node), fmt.Sprintf("%d/%d", n, perDst))
			if perDst == 0 || n < perDst*9/10 {
				t.Errorf("VPC %s to its workload on %s: %d of %d answered", mt.tn.vpc, w.node, n, perDst)
			}
		}
		for _, w := range wl[other] {
			n := len(echoes(evs, w.addr))
			l.record(t, fmt.Sprintf("VPC %s to VPC %s's workload on %s", mt.tn.vpc, other.tn.vpc, w.node), n)
			if n > 0 {
				t.Errorf("VPC %s reached VPC %s's workload on %s: %d replies", mt.tn.vpc, other.tn.vpc, w.node, n)
			}
		}
		if n := others(evs); n > 0 {
			t.Errorf("VPC %s's client received %d packets that were not its replies", mt.tn.vpc, n)
		}
	}
	for _, s := range sniffs {
		evs := s.p.wait(l, t)
		own, foreign := 0, 0
		for _, e := range evs {
			switch e.ID {
			case s.mt.id:
				own++
			case m.a.id, m.b.id:
				foreign++
			}
		}
		l.record(t, fmt.Sprintf("echo requests on VPC %s's workload on %s", s.mt.tn.vpc, s.w.node),
			fmt.Sprintf("%d own, %d from the other VPC's client", own, foreign))
		if foreign > 0 {
			t.Errorf("VPC %s's workload on %s received %d of the other VPC's echo requests", s.mt.tn.vpc, s.w.node,
				foreign)
		}
		if own < int(5*time.Second/probeInterval)/2 {
			t.Errorf("capture on VPC %s's workload on %s saw only %d of its own tenant's requests", s.mt.tn.vpc,
				s.w.node, own)
		}
	}
}

func (m *masque) rowNATEgress(t *testing.T) {
	runs := map[*masqueTenant]*probeRun{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		runs[mt] = m.connect(t, "nat-vpc-"+mt.tn.vpc, mt.token, mt.tn.vpc, mt.id, 5*time.Second, remoteHost)
	}
	for mt, p := range runs {
		evs := p.wait(m.l, t)
		requireSession(t, "VPC "+mt.tn.vpc+"'s request", evs, 5*time.Second, 1)
		n := len(echoes(evs, remoteHost))
		m.l.record(t, "VPC "+mt.tn.vpc+" to the off-fabric host", fmt.Sprintf("%d/%d", n, sentCount(evs)))
		if n < sentCount(evs)*9/10 || others(evs) > 0 {
			t.Errorf("VPC %s to the off-fabric host: %d of %d answered, %d other packets", mt.tn.vpc, n,
				sentCount(evs), others(evs))
		}
	}
}

// rowPartial starts a second instance whose setup cannot complete, its only
// connector's route refused, kills it without shutdown, and checks that
// core reaps everything it left while the first instance keeps forwarding.
func (m *masque) rowPartial(t *testing.T) {
	l := m.l
	dst := m.workload(t, m.a.tn, 2).addr
	token := rand.Text()
	b := marshalConfig([]fixtureService{m.a.serviceConfig()}, []fixtureConnector{{ID: "connector-partial",
		Credential: token, Service: m.a.serviceKey(), Prefix: masquePartial}})
	pod := m.deploy(t, "partial", edgeNode1, b)
	// Its only connector's request gets the attachment set up, and is
	// refused once core refuses the route.
	var evs []event
	eventually(t, 2*time.Minute, 2*time.Second, "partial instance's request refused", func() (bool, error) {
		var err error
		evs, err = connectOnceTo(pod, token, "10", 1, time.Second, dst)
		return err == nil && status(evs) == 503, err
	})
	att := l.waitServing(t, pod, m.a.svc)
	m.links[att.Name] = att.Status.HostLink
	route := m.waitRefused(t, m.a.vpcUID, netip.MustParsePrefix(masquePartial), att.Name)
	l.record(t, "partial instance's route", route)

	p := m.connect(t, "partial-continuity", m.a.token, "10", m.a.id, 40*time.Second, dst)
	time.Sleep(3 * time.Second)
	// Orphaning the Deployment and its ReplicaSet leaves nothing to replace
	// the pod, which is then killed without running its shutdown.
	for _, kind := range []string{"deployment", "replicaset"} {
		if _, err := l.kubectl("-n", masqueNS, "delete", kind, "-l", "edge-conformance/instance=partial",
			"--cascade=orphan"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.kubectl("-n", masqueNS, "delete", "pod", pod.Name, "--grace-period=0", "--force"); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	m.waitAcceptedFor(t, 20*time.Second, m.a)
	evs = p.wait(l, t)
	requireSession(t, "first instance's request", evs, 40*time.Second, 1)
	rs := echoes(evs, dst)
	l.record(t, "first instance across the kill", fmt.Sprintf("%d/%d, largest gap %v", len(rs), sentCount(evs),
		largestGap(rs)))
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second {
		t.Errorf("first instance answered %d of %d with a %v gap across the kill", len(rs), sentCount(evs),
			largestGap(rs))
	}
	m.waitReaped(t, pod.UID, []*galacticv1alpha1.EdgeAttachment{att}, killed)
	m.waitNoRoute(t, m.a.vpcUID, netip.MustParsePrefix(masquePartial))
}

// rowSharedCancel runs VPC 10's two connectors at once. Both are in one
// service, so they share its attachment and packet device. The second's
// request ends while the first's runs: the first keeps forwarding without a
// gap and its route stays accepted, the second's claim is released, and the
// attachment is neither replaced nor taken out of service.
func (m *masque) rowSharedCancel(t *testing.T) {
	l := m.l
	dst := m.workload(t, m.a.tn, 2).addr
	att := l.attachmentOf(t, m.pod, m.a.svc)
	first := m.connect(t, "shared-first", m.a.token, "10", m.a.id, 45*time.Second, dst)
	time.Sleep(3 * time.Second)
	second := m.connect(t, "shared-second", m.second, "10", m.a.id+1, 5*time.Second, dst)
	evs := second.wait(l, t)
	requireSessionFor(t, "second connector's request", evs, 5*time.Second, 1, masqueSecond)
	if n := len(echoes(evs, dst)); n < sentCount(evs)*9/10 || others(evs) > 0 {
		t.Errorf("second connector: %d of %d answered, %d other packets", n, sentCount(evs), others(evs))
	}
	ended := time.Now()
	r := l.route(t, masqueNS, m.a.vpcUID, netip.MustParsePrefix(masqueSecond))
	if r == nil || r.Spec.Claim == nil || r.Spec.Claim.Attachment != att.Name {
		t.Fatalf("the second connector's route was not claimed on the shared attachment %s", att.Name)
	}
	eventually(t, 10*time.Second, 500*time.Millisecond, "second connector's claim released", func() (bool, error) {
		r := l.route(t, masqueNS, m.a.vpcUID, netip.MustParsePrefix(masqueSecond))
		return r != nil && r.Spec.Claim != nil && r.Spec.Claim.Released, nil
	})
	l.record(t, "second connector's claim released after its request ended", time.Since(ended).Round(time.Second))
	m.waitAcceptedFor(t, 15*time.Second, m.a)
	m.requireAnswered(t, "first connector across the second's end", first.wait(l, t), 45*time.Second, dst)
	cur := l.attachmentOf(t, m.pod, m.a.svc)
	if cur == nil || cur.UID != att.UID ||
		!meta.IsStatusConditionTrue(cur.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) {
		t.Error("ending one connector's request replaced the shared attachment or took it out of service")
	}
}

// rowMaintenance leaves the fixture's attachments their VPCs' only users on
// the fixture's node, by scaling each tenant's edge client there to zero,
// and lets galactic-router's garbage collection run while a request of each
// tenant reaches its workload on the compute node. The VRFs, the
// attachments and the requests survive it, and a connector's first request
// after collection is set up and answered.
func (m *masque) rowMaintenance(t *testing.T) {
	l, ctx := m.l, context.Background()
	atts := map[*masqueTenant]*galacticv1alpha1.EdgeAttachment{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		atts[mt] = l.attachmentOf(t, m.pod, mt.svc)
		old := m.client(t, mt.tn, 2)
		key := client.ObjectKey{Namespace: mt.tn.vpcNamespace, Name: "edge-client-2"}
		scale := func(n int32) error {
			d := &appsv1.Deployment{}
			if err := l.c.Get(ctx, key, d); err != nil {
				return err
			}
			d.Spec.Replicas = &n
			return l.c.Update(ctx, d)
		}
		if err := scale(0); err != nil {
			t.Fatal(err)
		}
		// The row replaces this client on purpose; teardown expects its
		// replacement.
		defer func() {
			if err := scale(1); err != nil {
				t.Error(err)
				return
			}
			var p *corev1.Pod
			eventually(t, 3*time.Minute, 2*time.Second, "edge-client-2 restored in "+mt.tn.vpcNamespace,
				func() (bool, error) {
					var pods corev1.PodList
					err := l.c.List(ctx, &pods, client.InNamespace(mt.tn.vpcNamespace),
						client.MatchingLabels{appLabel: "edge-client-2"})
					for i := range pods.Items {
						if c := &pods.Items[i]; c.Status.Phase == corev1.PodRunning && c.DeletionTimestamp == nil {
							p = c
						}
					}
					return p != nil, err
				})
			delete(m.unrelated, old.Namespace+"/"+old.Name)
			m.unrelated[p.Namespace+"/"+p.Name] = p.UID
		}()
	}
	// Precondition: no pod of either VPC is left on the fixture's node, so
	// the attachment is all that keeps each VPC's VRF there.
	for _, mt := range []*masqueTenant{m.a, m.b} {
		eventually(t, 3*time.Minute, 2*time.Second, "no VPC "+mt.tn.vpc+" pod on "+edgeNode1, func() (bool, error) {
			var pods corev1.PodList
			if err := l.c.List(ctx, &pods, client.InNamespace(mt.tn.vpcNamespace)); err != nil {
				return false, err
			}
			for _, p := range pods.Items {
				if p.Spec.NodeName == edgeNode1 {
					return false, nil
				}
			}
			return true, nil
		})
	}
	router := l.podOn(t, systemNS, "galactic-router", edgeNode1)
	since := time.Now().UTC().Format(time.RFC3339)
	interval := l.gcInterval(t)
	l.record(t, "galactic-router GC interval", interval)
	d := interval + 45*time.Second
	runs := map[*masqueTenant]*probeRun{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		runs[mt] = m.connect(t, "maintenance-vpc-"+mt.tn.vpc, mt.token, mt.tn.vpc, mt.id, d,
			m.workload(t, mt.tn, 1).addr)
	}
	time.Sleep(interval + 30*time.Second)
	logs, err := l.kubectl("-n", systemNS, "logs", router, "--since-time="+since)
	if err != nil {
		t.Fatal(err)
	}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		vrf := fmt.Sprintf("G%09sV", atts[mt].Status.VPC)
		if _, err := nodeExec(edgeNode1, "ip", "link", "show", vrf); err != nil {
			t.Errorf("VPC %s's VRF %s is gone with the fixture's attachment still on it: %v", mt.tn.vpc, vrf, err)
		}
		// A collection pass ran and kept the VRF for the attachment.
		if !slices.ContainsFunc(strings.Split(logs, "\n"), func(line string) bool {
			return strings.Contains(line, "GC: kept VRF an edge attachment uses") && strings.Contains(line, vrf)
		}) {
			t.Errorf("no garbage collection pass kept VPC %s's VRF %s during the row", mt.tn.vpc, vrf)
		}
	}
	dst := m.workload(t, m.a.tn, 1).addr
	evs, err := m.connectOnce(m.second, "10", m.a.id+1, 3*time.Second, dst)
	if err != nil {
		t.Fatal(err)
	}
	requireSessionFor(t, "second connector's first request after collection", evs, 3*time.Second, 1, masqueSecond)
	if n := len(echoes(evs, dst)); n < sentCount(evs)*9/10 {
		t.Errorf("second connector after collection: %d of %d answered", n, sentCount(evs))
	}
	for mt, p := range runs {
		m.requireAnswered(t, "VPC "+mt.tn.vpc+" across garbage collection", p.wait(l, t), d,
			m.workload(t, mt.tn, 1).addr)
		if cur := l.attachmentOf(t, m.pod, mt.svc); cur == nil || cur.UID != atts[mt].UID {
			t.Errorf("VPC %s's attachment did not survive garbage collection", mt.tn.vpc)
		}
	}
}

// rowProcessRestart kills the fixture's process without shutdown. The
// kubelet restarts its container in the same pod, and the new process
// adopts the pod's attachments: both tenants are served again on the same
// attachment objects, under a later lease epoch.
func (m *masque) rowProcessRestart(t *testing.T) {
	l, ctx := m.l, context.Background()
	atts := map[*masqueTenant]types.UID{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		atts[mt] = l.attachmentOf(t, m.pod, mt.svc).UID
	}
	leaseKey := client.ObjectKey{Namespace: masqueNS, Name: "ei-" + string(m.pod.UID)}
	epoch := func() int32 {
		var lease coordinationv1.Lease
		if err := l.c.Get(ctx, leaseKey, &lease); err != nil {
			t.Fatal(err)
		}
		if lease.Spec.LeaseTransitions == nil {
			return 0
		}
		return *lease.Spec.LeaseTransitions
	}
	before := epoch()
	pid, err := containerPID(edgeNode1, m.pod.Namespace, m.pod.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeExec(edgeNode1, "kill", "-KILL", strconv.Itoa(pid)); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
	l.record(t, "serving again after the process was killed", time.Since(killed).Round(time.Second))
	p := l.providerPod(t, masqueNS, "m1")
	if p == nil || p.UID != m.pod.UID {
		t.Fatal("killing the process replaced the pod")
	}
	restarts := int32(0)
	for _, cs := range p.Status.ContainerStatuses {
		restarts += cs.RestartCount
	}
	l.record(t, "fixture container restarts", restarts)
	if restarts == 0 {
		t.Error("the fixture's container was not restarted")
	}
	logs, err := l.kubectl("-n", masqueNS, "logs", m.pod.Name, "-c", "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		cur := l.attachmentOf(t, m.pod, mt.svc)
		if cur == nil || cur.UID != atts[mt] {
			t.Errorf("VPC %s's attachment was replaced instead of adopted", mt.tn.vpc)
			continue
		}
		// The new process found the attachment at start, before any
		// request asked for it.
		if !slices.ContainsFunc(strings.Split(logs, "\n"), func(line string) bool {
			return strings.Contains(line, `"msg":"adopted attachment"`) && strings.Contains(line, cur.Name)
		}) {
			t.Errorf("the restarted process did not adopt VPC %s's attachment %s", mt.tn.vpc, cur.Name)
		}
	}
	if after := epoch(); after <= before {
		t.Errorf("the restarted process forwards under lease epoch %d, not after %d", after, before)
	}
}

// waitRefused waits for core to refuse the claim on p and returns the
// refusal's reason.
func (m *masque) waitRefused(t *testing.T, vpcUID string, p netip.Prefix, attachment string) string {
	t.Helper()
	var reason string
	eventually(t, time.Minute, time.Second, "refusal of "+p.String(), func() (bool, error) {
		r := m.l.route(t, masqueNS, vpcUID, p)
		if r == nil || r.Spec.Claim == nil || r.Spec.Claim.Attachment != attachment {
			return false, nil
		}
		c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason == "WaitingForFencing" {
			return false, nil
		}
		reason = c.Reason
		return true, nil
	})
	return reason
}

// waitReaped waits until core has deleted atts and the instance and lease of
// podUID, a pod that no longer exists, and the node has removed each
// attachment's host link. It records each time from since.
func (m *masque) waitReaped(t *testing.T, podUID types.UID, atts []*galacticv1alpha1.EdgeAttachment,
	since time.Time) {
	t.Helper()
	l, ctx := m.l, context.Background()
	gone := func(obj client.Object) {
		eventually(t, 3*time.Minute, time.Second, fmt.Sprintf("%T %s reaped", obj, obj.GetName()), func() (bool, error) {
			err := l.c.Get(ctx, client.ObjectKeyFromObject(obj), obj)
			return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
		})
		l.record(t, fmt.Sprintf("%T %s reaped after", obj, obj.GetName()), time.Since(since).Round(time.Second))
	}
	for _, att := range atts {
		gone(&galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: masqueNS, Name: att.Name}})
		deleted := time.Now()
		eventually(t, time.Minute, time.Second, "host link "+att.Status.HostLink+" removed", func() (bool, error) {
			present, err := linkPresent(edgeNode1, att.Status.HostLink)
			return err == nil && !present, err
		})
		l.record(t, "host link "+att.Status.HostLink+" removed after its attachment",
			time.Since(deleted).Round(time.Second))
	}
	inst := "ei-" + string(podUID)
	gone(&galacticv1alpha1.EdgeInstance{ObjectMeta: metav1.ObjectMeta{Namespace: masqueNS, Name: inst}})
	gone(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: masqueNS, Name: inst}})
}

// waitNoRoute waits until core has reaped the route of p.
func (m *masque) waitNoRoute(t *testing.T, vpcUID string, p netip.Prefix) {
	t.Helper()
	eventually(t, 3*time.Minute, time.Second, "route "+p.String()+" reaped", func() (bool, error) {
		return m.l.route(t, masqueNS, vpcUID, p) == nil, nil
	})
}

// waitAcceptedFor checks that each of tenants' routes stays accepted for
// the current pod's attachment for d. The adapter holds a connector's route
// only while a request of the connector is open, so the caller keeps one
// open throughout.
func (m *masque) waitAcceptedFor(t *testing.T, d time.Duration, tenants ...*masqueTenant) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, mt := range tenants {
			att := m.l.attachmentOf(t, m.pod, mt.svc)
			r := m.l.route(t, masqueNS, mt.vpcUID, netip.MustParsePrefix(masquePrefix))
			if att == nil || r == nil || r.Status.Accepted == nil || r.Status.Accepted.Attachment != att.Name ||
				!meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
				t.Fatalf("VPC %s's route is no longer accepted for the current attachment", mt.tn.vpc)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// rowRecreation deletes the fixture's pod, lets its Deployment replace it,
// and checks the replacement serves both tenants in isolation, the old
// pod's attachments, instance, lease and host links are reaped, and the
// old pod's shutdown leaves the replacement's routes alone.
func (m *masque) rowRecreation(t *testing.T) {
	l := m.l
	old := m.pod
	oldAtts := make([]*galacticv1alpha1.EdgeAttachment, 0, 2)
	for _, mt := range []*masqueTenant{m.a, m.b} {
		oldAtts = append(oldAtts, l.attachmentOf(t, old, mt.svc))
	}
	if _, err := l.kubectl("-n", masqueNS, "delete", "pod", old.Name, "--wait=false"); err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	eventually(t, 3*time.Minute, time.Second, "replacement pod", func() (bool, error) {
		p := l.providerPod(t, masqueNS, "m1")
		if p == nil || p.UID == old.UID {
			return false, nil
		}
		m.pod = p
		return true, nil
	})
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
	m.waitServing(t, m.pod)
	l.record(t, "replacement serving after", time.Since(deleted).Round(time.Second))
	m.waitReaped(t, old.UID, oldAtts, deleted)
	runs := map[*masqueTenant]*probeRun{}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		runs[mt] = m.connect(t, "recreated-vpc-"+mt.tn.vpc, mt.token, mt.tn.vpc, mt.id, 30*time.Second,
			m.workload(t, mt.tn, 2).addr)
	}
	time.Sleep(3 * time.Second)
	m.waitAcceptedFor(t, 20*time.Second, m.a, m.b)
	for mt, p := range runs {
		m.requireAnswered(t, "VPC "+mt.tn.vpc+" after the old pod was reaped", p.wait(l, t), 30*time.Second,
			m.workload(t, mt.tn, 2).addr)
	}
	m.isolation(t, "after-recreation")
}

// currentLinks returns the host links of the current pod's attachments.
func (m *masque) currentLinks(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, mt := range []*masqueTenant{m.a, m.b} {
		if att := m.l.attachmentOf(t, m.pod, mt.svc); att != nil && att.Status.HostLink != "" {
			m.links[att.Name] = att.Status.HostLink
			out = append(out, att.Status.HostLink)
		}
	}
	return out
}

// linkPresent reports whether node has a link named name.
func linkPresent(node, name string) (bool, error) {
	out, err := nodeExec(node, "ip", "-o", "link", "show")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 1 && strings.Split(strings.TrimSuffix(f[1], ":"), "@")[0] == name {
			return true, nil
		}
	}
	return false, nil
}

// waitNamespaceEmpty waits until no EdgeAttachment, EdgeInstance, Lease or
// EdgeRoute remains in the fixture's namespace.
func (m *masque) waitNamespaceEmpty(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	eventually(t, 3*time.Minute, 2*time.Second, "fixture objects removed", func() (bool, error) {
		left := 0
		for _, list := range []client.ObjectList{&galacticv1alpha1.EdgeAttachmentList{},
			&galacticv1alpha1.EdgeInstanceList{}, &coordinationv1.LeaseList{}, &galacticv1alpha1.EdgeRouteList{}} {
			if err := m.l.c.List(ctx, list, client.InNamespace(masqueNS)); err != nil {
				return false, err
			}
			left += meta.LenList(list)
		}
		return left == 0, fmt.Errorf("%d objects remain", left)
	})
}

// teardown removes the fixture and fails the run unless everything it
// created is gone and everything it did not create is untouched.
func (m *masque) teardown(t *testing.T) {
	l, ctx := m.l, context.Background()
	if m.pod != nil {
		m.currentLinks(t)
	}
	if _, err := l.kubectl("-n", masqueNS, "delete", "deployment,replicaset,pod", "--all", "--wait=true",
		"--timeout=120s"); err != nil {
		t.Error(err)
	}
	eventually(t, 2*time.Minute, time.Second, "fixture pods gone", func() (bool, error) {
		var pods corev1.PodList
		err := l.c.List(ctx, &pods, client.InNamespace(masqueNS))
		return err == nil && len(pods.Items) == 0, err
	})
	for _, mt := range []*masqueTenant{m.a, m.b} {
		l.deleteAndWait(t, &galacticv1alpha1.EdgeService{ObjectMeta: metav1.ObjectMeta{Namespace: mt.tn.vpcNamespace,
			Name: masqueService}})
	}
	// The provider and core must remove what the run created before the
	// namespace's deletion would remove it for them.
	m.waitNamespaceEmpty(t)
	if _, err := l.kubectl("delete", "namespace", masqueNS, "--wait=true", "--timeout=180s"); err != nil {
		t.Error(err)
	}
	l.deleteAndWait(t, &galacticv1alpha1.EdgeProvider{ObjectMeta: metav1.ObjectMeta{Name: masqueProvider}})

	var advs networkv1alpha1.BGPAdvertisementList
	if err := l.c.List(ctx, &advs, client.InNamespace(systemNS)); err != nil {
		t.Error(err)
	}
	for _, a := range advs.Items {
		if strings.HasPrefix(a.Annotations["galactic.datumapis.com/edge-route"], masqueNS+"/") {
			t.Errorf("BGPAdvertisement %s of the fixture's route %s remains", a.Name,
				a.Annotations["galactic.datumapis.com/edge-route"])
		}
	}
	for att, link := range m.links {
		for _, n := range []string{edgeNode1, edgeNode2} {
			if present, err := linkPresent(n, link); err != nil || present {
				t.Errorf("host link %s of attachment %s on %s: present=%t, %v", link, att, n, present, err)
			}
		}
	}
	for _, n := range []string{computeNode, edgeNode1, edgeNode2} {
		if _, err := nodeExec(n, "rm", "-f", masqueCA); err != nil {
			t.Error(err)
		}
	}
	for _, mt := range []*masqueTenant{m.a, m.b} {
		for i := 1; i <= 2; i++ {
			p := m.client(t, mt.tn, i)
			if want := m.unrelated[p.Namespace+"/"+p.Name]; want != p.UID {
				t.Errorf("unrelated pod %s/%s was replaced", p.Namespace, p.Name)
			}
		}
		c1, w2 := m.client(t, mt.tn, 1), m.workload(t, mt.tn, 2)
		if out, err := l.kubectl("-n", c1.Namespace, "exec", c1.Name, "--", "ping", "-6", "-c", "3", "-W", "2",
			w2.addr); err != nil {
			t.Errorf("VPC %s's workloads no longer reach each other after teardown: %v: %s", mt.tn.vpc, err, out)
		}
	}
}
