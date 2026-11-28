// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// TestListenerBackend is Phase 0 of the Edge public listener design
// (docs/designs/edge-public-listener.md, #1507). It wires one SocketAccess
// attachment by hand as the backend of a gateway VIP, with no controller
// change, and sends UDP and TCP to it from the off-fabric host over both
// VIP families:
//
//   - a dedicated ingress VPC, granted to a reference provider with
//     SocketAccess only, under the lab's public-service traffic policy;
//   - a stand-in VPCAttachment for the edge attachment's address, which is
//     how the gateway and galactic-router find backends today;
//   - the attachment's /128 BGPAdvertisement with its VRF ID and End.DT46,
//     the shape edge route publication writes;
//   - one gateway-namespace NetworkService per protocol.
//
// The provider runs on edgeNode2. Remote delivery pins the VIP on the
// transit router to edgeNode1, so the gateway that receives each packet is
// not the backend's node; it must pass. Local delivery pins the VIP to
// edgeNode2, the backend's own node; it records what happens, including the
// gateway's drop counters, and does not fail the test.
func TestListenerBackend(t *testing.T) {
	l := getLab(t)
	t.Cleanup(func() { l.writeSummary(t) })

	p := &listenerProof{l: l, node: edgeNode2, used: map[int]bool{}}
	// EDGE_CONFORMANCE_KEEP keeps the fixtures and the VIP's pins on tr1,
	// for probing by hand. Delete the pins when done.
	if os.Getenv("EDGE_CONFORMANCE_KEEP") == "" {
		t.Cleanup(func() { p.teardown(t) })
		t.Cleanup(p.unpin)
	}

	if !t.Run("setup", p.setup) {
		t.FailNow()
	}

	t.Run("remote-delivery", func(t *testing.T) {
		for _, f := range listenerFamilies {
			t.Run(f.name, func(t *testing.T) {
				p.pin(t, f, edgeNode1)
				before := p.l.rulePackets(t, edgeNode1, f.vip)
				for _, proto := range listenerProtocols {
					// The first flow waits for the gateway to program the
					// rule; every later one must answer at once.
					eventually(t, 2*time.Minute, 2*time.Second, proto+" through "+edgeNode1, func() (bool, error) {
						err := p.request(f, proto)
						return err == nil, err
					})
					answered := 0
					for range listenerFlows {
						if err := p.request(f, proto); err != nil {
							t.Errorf("%s %s: %v", f.name, proto, err)
							continue
						}
						answered++
					}
					p.l.record(t, proto+" flows answered", fmt.Sprintf("%d/%d", answered, listenerFlows))
				}
				peer := p.tcpPeer(t, f)
				p.l.record(t, "backend saw client as", peer)
				if want := f.clientAsSeen(); peer != want {
					t.Errorf("backend saw the client as %q, want %q", peer, want)
				}
				after := p.l.rulePackets(t, edgeNode1, f.vip)
				p.l.record(t, edgeNode1+" rule packets", after-before)
				if after <= before {
					t.Errorf("%s counted no packets for %s: another node served the VIP", edgeNode1, f.vip)
				}
			})
		}
	})

	t.Run("local-delivery", func(t *testing.T) {
		for _, f := range listenerFamilies {
			t.Run(f.name, func(t *testing.T) {
				p.pin(t, f, p.node)
				drops := p.l.gatewayDrops(t, p.node)
				rule := p.l.rulePackets(t, p.node, f.vip)
				for _, proto := range listenerProtocols {
					answered := 0
					var last error
					for range listenerFlows {
						if err := p.request(f, proto); err != nil {
							last = err
							continue
						}
						answered++
					}
					p.l.record(t, proto+" flows answered", fmt.Sprintf("%d/%d", answered, listenerFlows))
					if last != nil {
						p.l.record(t, proto+" last failure", last)
					}
				}
				p.l.record(t, p.node+" rule packets",
					p.l.rulePackets(t, p.node, f.vip)-rule)
				p.l.record(t, p.node+" drops by reason", diffDrops(drops, p.l.gatewayDrops(t, p.node)))
			})
		}
	})
}

// The proof's fixed values. The VIPs fall in dfw's gateway VIP prefixes,
// which dfw's edge nodes originate to the transit; the ingress VPC's
// identifier and prefix are used by no other lab tenant.
const (
	listenerVPCNamespace = "edge-ingress"
	listenerVPC          = "95"
	listenerVPCNetwork   = "fd00:ed95::/32"
	listenerPool         = "fd00:ed95:0:1::/64"
	listenerProvider     = "listener-proof"
	listenerNamespace    = "edge-listener"
	listenerService      = "listener"
	listenerDeploy       = "lp1"
	listenerAdvert       = "edge-listener-proof"
	listenerLabel        = "edge-listener-proof"
	listenerPort         = 443
	listenerFlows        = 8
	protoUDP             = "udp"
	protoTCP             = "tcp"
	gatewayNamespace     = "galactic-system"
	gatewayMetricsPort   = 8081
	remoteHostNode       = "remote-host"
)

// listenerFamily is one VIP family: its address, how the transit router
// pins it to a gateway, and the client's address on the off-fabric host.
type listenerFamily struct {
	name   string
	vip    string
	client string
	// uplinks maps each dfw gateway to its address on its tr1 link and
	// tr1's bond to it; keep in step with scripts/verify-gateway-ingress*.sh.
	uplinks map[string][2]string
}

var listenerFamilies = []listenerFamily{
	{name: "ipv6", vip: "2001:db8:6060:1::95", client: "2001:db8:1:40::2", uplinks: map[string][2]string{
		edgeNode1: {"2001:db8:1:11::2", "bond1"}, edgeNode2: {"2001:db8:1:12::2", "bond2"}}},
	{name: "ipv4", vip: "198.51.100.30", client: "11.1.40.2", uplinks: map[string][2]string{
		edgeNode1: {"10.1.11.2", "bond1"}, edgeNode2: {"10.1.12.2", "bond2"}}},
}

// listenerProtocols are the protocols the proof serves, one NetworkService
// each.
var listenerProtocols = []string{protoUDP, protoTCP}

func (f listenerFamily) v4() bool { return strings.Contains(f.vip, ".") }

// clientAsSeen is the client's address as the IPv6-only backend sees it:
// itself for IPv6, and embedded under 64:ff9b::/96 for IPv4 (RFC 6052).
func (f listenerFamily) clientAsSeen() string {
	if !f.v4() {
		return f.client
	}
	a := netip.MustParseAddr(f.client).As4()
	b := [16]byte{0, 0x64, 0xff, 0x9b}
	copy(b[12:], a[:])
	return netip.AddrFrom16(b).String()
}

type listenerProof struct {
	l    *lab
	node string
	addr string
	pod  string
	// used holds every client source port drawn so far: a TCP port still in
	// TIME_WAIT towards the same VIP and port would refuse a new connect.
	used map[int]bool
}

// sourcePort draws a client source port in 20000-59999 that no earlier
// flow of this run used.
func (p *listenerProof) sourcePort() int {
	for {
		port := 20000 + rand.IntN(40000)
		if !p.used[port] {
			p.used[port] = true
			return port
		}
	}
}

func (p *listenerProof) setup(t *testing.T) {
	l := p.l
	ctx := context.Background()

	// The ingress VPC and its traffic policy. The lab writes a VPC's
	// identifier by hand, as deploy:galactic-edge does for ns10 and ns20.
	l.ensureNamespace(t, listenerVPCNamespace)
	p.applyYAML(t, "listener-vpc.yaml", fmt.Sprintf(`apiVersion: galactic.datumapis.com/v1alpha1
kind: VPC
metadata:
  name: %q
  namespace: %s
spec:
  networks: [%s]
`, listenerVPC, listenerVPCNamespace, listenerVPCNetwork))
	if _, err := l.kubectl("-n", listenerVPCNamespace, "patch", "vpc", listenerVPC, "--subresource=status",
		"--type=merge", "-p", fmt.Sprintf(`{"status":{"vpc":%q}}`, listenerVPC)); err != nil {
		t.Fatal(err)
	}
	l.applyOverlayOf(t, filepath.Join(l.root, "deploy", "containerlab", "resources", "tenants", "policies",
		"public-service"), "listener-policies", "namespace: "+listenerVPCNamespace+"\n", nil)

	// The provider and its SocketAccess grant.
	tn := tenant{vpcNamespace: listenerVPCNamespace, vpc: listenerVPC, provider: listenerProvider,
		namespace: listenerNamespace, service: listenerService}
	l.ensureNamespace(t, tn.namespace)
	l.register(t, tn.provider, tn.namespace, true)
	vpcUID := l.vpcUID(t, tn)
	svc := l.grantService(t, tn, tn.service, func(s *galacticv1alpha1.EdgeService) {
		s.Spec.Capabilities = []string{capSocket}
		s.Spec.Prefixes = nil
		s.Spec.ClientPool = listenerPool
	})
	l.waitServiceAdmitted(t, svc, true)
	l.deployProvider(t, tn.namespace, listenerDeploy, p.node, fmt.Sprintf(`provider: %s
port: %d
services:
  - namespace: %s
    name: %s
    uid: %s
    vpcUID: %s
    capabilities: [SocketAccess]
`, tn.provider, echoPort, svc.Namespace, svc.Name, svc.UID, vpcUID))
	pod := l.waitProviderPod(t, tn.namespace, listenerDeploy, p.node)
	p.pod = pod.Name
	att := l.waitServing(t, pod, svc)
	p.addr = netip.MustParseAddr(att.Status.Address).String()
	l.record(t, "attachment", fmt.Sprintf("%s address %s host link %s", att.Name, p.addr, att.Status.HostLink))

	// The attachment's /128 in the ingress VRF, which is how the gateway
	// resolves a backend's uSID and galactic-router binds a VIP to it. It
	// carries no edge-route label, so no forwarding gate withholds it.
	var vrf networkv1alpha1.BGPVRFInstance
	key := client.ObjectKey{Namespace: gatewayNamespace, Name: crdnames.BGPVRFInstanceName(listenerVPC, p.node)}
	eventually(t, time.Minute, time.Second, "BGPVRFInstance "+key.Name, func() (bool, error) {
		err := l.c.Get(ctx, key, &vrf)
		return err == nil && vrf.Spec.RouterRef != nil && len(vrf.Spec.ExportRouteTargets) > 0, err
	})
	vrfID := vrf.Spec.VRFID
	fn := networkv1alpha1.SRv6FunctionEndDT46
	adv := &networkv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: listenerAdvert, Namespace: gatewayNamespace},
		Spec: networkv1alpha1.BGPAdvertisementSpec{
			RouterRef:     networkv1alpha1.RouterRef{Name: vrf.Spec.RouterRef.Name},
			AddressFamily: networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN},
			Prefixes:      []networkv1alpha1.Prefix{networkv1alpha1.Prefix(p.addr + "/128")},
			Communities:   []networkv1alpha1.Community{networkv1alpha1.Community(vrf.Spec.ExportRouteTargets[0].Value)},
			VRFID:         &vrfID,
			Function:      &fn,
		},
	}
	l.deleteAndWait(t, &networkv1alpha1.BGPAdvertisement{ObjectMeta: adv.ObjectMeta})
	if err := l.c.Create(ctx, adv); err != nil {
		t.Fatal(err)
	}
	l.record(t, "advertisement", fmt.Sprintf("%s/128 vrfID %d router %s", p.addr, vrfID, vrf.Spec.RouterRef.Name))

	// The stand-in backend: the gateway and galactic-router select
	// VPCAttachments, so one names the edge attachment's address and node.
	// It has no hostInterface, so neither traffic policy nor the health
	// prober binds to it, and the services carry no health check.
	p.applyYAML(t, "listener-backend.yaml", fmt.Sprintf(`apiVersion: galactic.datumapis.com/v1alpha1
kind: VPCAttachment
metadata:
  name: listener-backend
  namespace: %s
  labels: {app: %s}
spec:
  vpc: {name: %q}
  interface:
    name: %s
    mode: Netns
    addresses: [%s/128]
`, listenerVPCNamespace, listenerLabel, listenerVPC, att.Status.HostLink, p.addr))
	if _, err := l.kubectl("-n", listenerVPCNamespace, "patch", "vpcattachment", "listener-backend",
		"--subresource=status", "--type=merge", "-p",
		fmt.Sprintf(`{"status":{"vpc":%q,"node":%q}}`, listenerVPC, p.node)); err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	for _, proto := range listenerProtocols {
		fmt.Fprintf(&b, `---
apiVersion: galactic.datumapis.com/v1alpha1
kind: NetworkService
metadata:
  name: listener-proof-%s
  namespace: %s
spec:
  vpcRef: %q
  vipAddresses: [%s, %s]
  protocol: %s
  port: %d
  backendSelector:
    matchLabels: {app: %s}
  backendPort: %d
`, proto, gatewayNamespace, listenerVPC, listenerFamilies[0].vip, listenerFamilies[1].vip, proto,
			listenerPort, listenerLabel, echoPort)
	}
	p.applyYAML(t, "listener-services.yaml", b.String())

	// One binding per protocol per VIP on the backend's node, each Bound.
	eventually(t, 3*time.Minute, 2*time.Second, "four Bound bindings for "+p.addr, func() (bool, error) {
		var list networkv1alpha1.ServiceVIPBindingList
		if err := l.c.List(ctx, &list, client.InNamespace(gatewayNamespace)); err != nil {
			return false, err
		}
		bound := 0
		for _, sb := range list.Items {
			a, err := netip.ParsePrefix(sb.Spec.BackendAddress)
			if err != nil {
				addr, aerr := netip.ParseAddr(sb.Spec.BackendAddress)
				if aerr != nil {
					continue
				}
				a = netip.PrefixFrom(addr, 128)
			}
			if a.Addr().String() == p.addr &&
				meta.IsStatusConditionTrue(sb.Status.Conditions, networkv1alpha1.ConditionTypeBound) {
				bound++
			}
		}
		return bound == 4, fmt.Errorf("%d of 4 bound", bound)
	})
}

// applyYAML writes body to the run's artifacts and applies it.
func (p *listenerProof) applyYAML(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join(p.l.artifacts, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.l.kubectl("apply", "-f", path); err != nil {
		t.Fatal(err)
	}
}

// clab is the container name of a containerlab node of the lab.
func clab(node string) string {
	lab := os.Getenv("LAB")
	if lab == "" {
		lab = "gvpc"
	}
	return "clab-" + lab + "-" + node
}

func transitRouter() string { return clab("tr1") }

// pin routes f's VIP from tr1 to gateway only, more specific than the
// prefix both dfw edge nodes originate.
func (p *listenerProof) pin(t *testing.T, f listenerFamily, gateway string) {
	t.Helper()
	up := f.uplinks[gateway]
	fam, plen := "-6", "/128"
	if f.v4() {
		fam, plen = "-4", "/32"
	}
	if _, err := nodeExec(transitRouter(), "ip", fam, "route", "replace", f.vip+plen, "via", up[0], "dev",
		up[1]); err != nil {
		t.Fatal(err)
	}
}

// unpin removes both families' pins, whatever is pinned.
func (p *listenerProof) unpin() {
	for _, f := range listenerFamilies {
		fam, plen := "-6", "/128"
		if f.v4() {
			fam, plen = "-4", "/32"
		}
		_, _ = nodeExec(transitRouter(), "ip", fam, "route", "del", f.vip+plen)
	}
}

// request sends one flow from a fresh source port on the off-fabric host
// and checks the reply. The echo answers with its identity and the
// payload; a connected socat accepts a reply only from the VIP, so any
// answer also proves the reply's source. Only the first line counts: over
// UDP, socat ends its input with an empty datagram, which draws a second,
// identity-only echo.
func (p *listenerProof) request(f listenerFamily, proto string) error {
	addr := p.socatAddress(f, proto, 0)
	out, err := nodeExec(transitHost(), "sh", "-c",
		"echo probe | timeout 5 socat -t2 -T3 - "+addr)
	if err != nil {
		return fmt.Errorf("%s: %w", addr, err)
	}
	reply, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if !strings.HasPrefix(reply, listenerProvider+"/") || !strings.HasSuffix(reply, " probe") {
		return fmt.Errorf("%s: reply %q is not the provider's echo", addr, reply)
	}
	return nil
}

func transitHost() string { return clab(remoteHostNode) }

// socatAddress is a socat address for f and proto from sport, or from a
// random unprivileged port when sport is 0.
func (p *listenerProof) socatAddress(f listenerFamily, proto string, sport int) string {
	if sport == 0 {
		sport = p.sourcePort()
	}
	kind := strings.ToUpper(proto) + "6"
	host := "[" + f.vip + "]"
	if f.v4() {
		kind, host = strings.ToUpper(proto)+"4", f.vip
	}
	return fmt.Sprintf("%s:%s:%d,sourceport=%d,reuseaddr", kind, host, listenerPort, sport)
}

var ssPeer = regexp.MustCompile(`\[?([0-9a-fA-F:.]+)\]?:(\d+)\s*$`)

// tcpPeer holds one TCP connection open through f's VIP and reads, from
// the provider pod's own network namespace, the address the backend sees
// as its peer.
func (p *listenerProof) tcpPeer(t *testing.T, f listenerFamily) string {
	t.Helper()
	sport := p.sourcePort()
	done := make(chan error, 1)
	go func() {
		_, err := nodeExec(transitHost(), "sh", "-c",
			"(echo probe; sleep 5) | timeout 8 socat -t6 - "+p.socatAddress(f, protoTCP, sport))
		done <- err
	}()
	defer func() { <-done }()
	pid, err := sandboxPID(p.node, listenerNamespace, p.pod)
	if err != nil {
		t.Fatal(err)
	}
	var peer string
	eventually(t, 5*time.Second, 200*time.Millisecond, "the backend's TCP connection", func() (bool, error) {
		out, err := nodeExec(p.node, "nsenter", "-t", strconv.Itoa(pid), "-n", "ss", "-Htn", "state",
			"established", "( sport = :"+strconv.Itoa(echoPort)+" )")
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(out, "\n") {
			m := ssPeer.FindStringSubmatch(strings.TrimSpace(line))
			if m != nil && m[2] == strconv.Itoa(sport) {
				a, err := netip.ParseAddr(m[1])
				if err != nil {
					return false, err
				}
				peer = a.Unmap().String()
				return true, nil
			}
		}
		return false, fmt.Errorf("no connection from port %d in %q", sport, out)
	})
	return peer
}

// gatewayMetrics scrapes a gateway's metrics endpoint.
func (l *lab) gatewayMetrics(t *testing.T, node string) string {
	t.Helper()
	out, err := nodeExec(node, "curl", "-s", "--max-time", "4",
		"http://localhost:"+strconv.Itoa(gatewayMetricsPort)+"/metrics")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rulePackets sums node's galactic_edge_rule_packets_total samples for vip.
func (l *lab) rulePackets(t *testing.T, node, vip string) float64 {
	t.Helper()
	var sum float64
	for _, line := range strings.Split(l.gatewayMetrics(t, node), "\n") {
		if strings.HasPrefix(line, "galactic_edge_rule_packets_total{") && strings.Contains(line, `vip="`+vip+`"`) {
			sum += sampleValue(line)
		}
	}
	return sum
}

// gatewayDrops returns node's galactic_edge_drops_total samples by labels.
func (l *lab) gatewayDrops(t *testing.T, node string) map[string]float64 {
	t.Helper()
	m := map[string]float64{}
	for _, line := range strings.Split(l.gatewayMetrics(t, node), "\n") {
		if strings.HasPrefix(line, "galactic_edge_drops_total") {
			i := strings.LastIndexByte(line, ' ')
			m[line[:i]] += sampleValue(line)
		}
	}
	return m
}

func sampleValue(line string) float64 {
	f := strings.Fields(line)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[len(f)-1], 64)
	return v
}

// diffDrops lists the drop series that rose between two scrapes.
func diffDrops(before, after map[string]float64) string {
	var rose []string
	for k, v := range after {
		if d := v - before[k]; d > 0 {
			rose = append(rose, fmt.Sprintf("%s +%g", k, d))
		}
	}
	if len(rose) == 0 {
		return "none"
	}
	return strings.Join(rose, "; ")
}

// teardown removes everything setup created, services first so the VIP's
// bindings go before their backend.
func (p *listenerProof) teardown(t *testing.T) {
	l := p.l
	for _, proto := range listenerProtocols {
		_, _ = l.kubectl("-n", gatewayNamespace, "delete", "networkservice", "listener-proof-"+proto,
			"--ignore-not-found", "--wait=true", "--timeout=120s")
	}
	_, _ = l.kubectl("-n", gatewayNamespace, "delete", "bgpadvertisement", listenerAdvert, "--ignore-not-found")
	if _, err := l.kubectl("delete", "namespace", listenerNamespace, "--ignore-not-found", "--wait=true",
		"--timeout=180s"); err != nil {
		t.Error(err)
	}
	l.unapprove(listenerProvider)
	_ = l.c.Delete(context.Background(), &galacticv1alpha1.EdgeProvider{ObjectMeta: metav1.ObjectMeta{
		Name: listenerProvider}})
	if _, err := l.kubectl("delete", "namespace", listenerVPCNamespace, "--ignore-not-found", "--wait=true",
		"--timeout=180s"); err != nil {
		t.Error(err)
	}

	// galactic-router GC removes the ingress VPC's BGPVRFInstance, and with
	// it the VPC's routes, on its next pass once nothing on the node uses the
	// VPC. Wait for that, so the lab is handed back as it was found.
	start := time.Now()
	key := client.ObjectKey{Namespace: gatewayNamespace, Name: crdnames.BGPVRFInstanceName(listenerVPC, p.node)}
	eventually(t, l.gcInterval(t)+2*time.Minute, 5*time.Second, "release of "+key.Name, func() (bool, error) {
		var inst networkv1alpha1.BGPVRFInstance
		err := l.c.Get(context.Background(), key, &inst)
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
	l.record(t, "ingress VPC state released after", time.Since(start).Round(time.Second))
}
