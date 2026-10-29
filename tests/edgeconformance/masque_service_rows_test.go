// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// remoteConvergenceTarget is the 5 s within which a remote node must stop
// routing a connector's /96 once the edge node withdrew it.
const remoteConvergenceTarget = 5 * time.Second

// udpBlockTable is the nftables table that keeps a client's UDP from the
// provider's CONNECT-IP port.
const udpBlockTable = "masque-udp-block"

// blockUDP drops UDP from pod's node, where the probe runs on the host
// network, to pod's CONNECT-IP port, and returns a function that reads how
// many datagrams the rule dropped. Cleanup removes the table.
func (s *service) blockUDP(t *testing.T, pod *corev1.Pod) func() int {
	t.Helper()
	node := pod.Spec.NodeName
	nft := func(args ...string) (string, error) { return nodeExec(node, append([]string{"nft"}, args...)...) }
	if _, err := nft("add", "table", "inet", udpBlockTable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = nft("delete", "table", "inet", udpBlockTable) })
	if _, err := nft("add", "chain", "inet", udpBlockTable, "out", "{", "type", "filter", "hook", "output",
		"priority", "0", ";", "}"); err != nil {
		t.Fatal(err)
	}
	if _, err := nft("add", "rule", "inet", udpBlockTable, "out", "ip6", "daddr", pod.Status.PodIP, "udp", "dport",
		strconv.Itoa(svcPort), "counter", "drop"); err != nil {
		t.Fatal(err)
	}
	counter := regexp.MustCompile(`counter packets (\d+)`)
	return func() int {
		out, err := nft("list", "chain", "inet", udpBlockTable, "out")
		if err != nil {
			t.Fatal(err)
		}
		m := counter.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no counter in %s", out)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
}

// rowH2Lifecycle runs the lifecycle over HTTP/2 with the client's UDP to
// the provider blocked: an HTTP/3 attempt first proves the block drops it,
// then neither the block's counter nor a capture in the provider's pod
// sees a UDP datagram to its port while the HTTP/2 clients run.
func (s *service) rowH2Lifecycle(t *testing.T) {
	l, pod := s.l, s.pod
	dropped := s.blockUDP(t, pod)
	args := s.connectArgs(pod, s.c10, "h3", time.Second, l.workloadOn(t, s.c10.tn, edgeNode1).addr)
	_, err := nodeExec(pod.Spec.NodeName, append([]string{"timeout", "5", "/usr/local/bin/edgeprobe"}, args...)...)
	control := dropped()
	l.record(t, "UDP datagrams the block dropped from an HTTP/3 attempt", control)
	if err == nil || control == 0 {
		t.Fatalf("UDP to the provider is not blocked: the HTTP/3 attempt returned %v with %d datagrams dropped", err,
			control)
	}
	capture, err := startProbe(pod.Spec.NodeName, podPID(t, pod.Spec.NodeName, svcNS, pod.Name), "h2-udp-capture",
		"sniff", "-iface", "eth0", "-port", strconv.Itoa(svcPort), "-duration", "50s")
	if err != nil {
		t.Fatal(err)
	}
	s.lifecycle(t, "h2")
	udp := 0
	for _, e := range capture.wait(l, t) {
		if !e.last() && e.Dst != "" {
			udp++
		}
	}
	during := dropped() - control
	l.record(t, "UDP datagrams to the provider's port captured in its pod during the HTTP/2 lifecycle", udp)
	l.record(t, "UDP datagrams the block dropped during the HTTP/2 lifecycle", during)
	if udp > 0 || during > 0 {
		t.Errorf("the HTTP/2 lifecycle sent UDP to the provider: %d captured, %d dropped", udp, during)
	}
}

// spoofEcho is the echo identifier of a client sending from spoofed
// sources.
const spoofEcho = 0x5a99

// spoofing sends over transport from VPC 10's connector with sources
// outside its /96: one in VPC 10's second connector's /96 and one in a /96
// no connector holds. VPC 10's workload on the provider's node, which is
// captured, receives none of them, and the second connector's client,
// running at the same time, receives nothing but its own replies. Over
// HTTP/2 the server's packet policy counts each refused packet. The HTTP/3
// client library refuses to send a packet from outside its assignment, so
// over HTTP/3 the row shows no spoofed packet reaches anything; the
// server's own HTTP/3 refusal is covered by internal/edge/connectip's
// tests.
func (s *service) spoofing(t *testing.T, transport string) {
	l, pod := s.l, s.pod
	// An authorization left idle past its validUntil is replaced first,
	// and the authority answers 503 until it is.
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c10b)
	w := l.workloadOn(t, s.c10.tn, edgeNode1)
	unheld := netip.MustParsePrefix(svcConnectors).Addr().As16()
	unheld[11], unheld[15] = 0xff, 1
	spoofed := []string{s.c10b.addr(), netip.AddrFrom16(unheld).String()}
	sniff, err := startProbe(w.node, w.pid, "spoof-sniff-"+transport, "sniff", "-iface", w.iface, "-icmp",
		"-duration", "9s")
	if err != nil {
		t.Fatal(err)
	}
	before := s.scrape(t, pod)
	other := s.connect(t, "spoof-other-"+transport, s.c10b, transport, 7*time.Second, w.addr)
	time.Sleep(time.Second)
	spoofer := *s.c10
	spoofer.echo = spoofEcho
	p, err := startProbe(pod.Spec.NodeName, 1, "spoof-"+transport,
		append(s.connectArgs(pod, &spoofer, transport, 5*time.Second, w.addr), "-src", strings.Join(spoofed, ","))...)
	if err != nil {
		t.Fatal(err)
	}
	evs := p.wait(l, t)
	requireSessionFor(t, "the spoofing request", evs, 5*time.Second, len(spoofed), s.c10.issued.Prefix)
	if n := len(echoes(evs, w.addr)) + others(evs); n > 0 {
		t.Errorf("the spoofing client received %d packets", n)
	}
	oevs := other.wait(l, t)
	requireSessionFor(t, "the other connector's request", oevs, 7*time.Second, 1, s.c10b.issued.Prefix)
	l.record(t, transport+": the other connector", fmt.Sprintf("%d/%d replies, %d other packets",
		len(echoes(oevs, w.addr)), sentCount(oevs), others(oevs)))
	if n := others(oevs); n > 0 {
		t.Errorf("the other connector's client received %d packets that were not its replies", n)
	}
	spoof, own := 0, 0
	for _, e := range sniff.wait(l, t) {
		switch e.ID {
		case spoofEcho:
			spoof++
		case s.c10b.echo:
			own++
		}
	}
	l.record(t, transport+": spoofed echo requests captured on the workload", spoof)
	if spoof > 0 {
		t.Errorf("%d spoofed echo requests reached VPC 10's workload", spoof)
	}
	if own == 0 {
		t.Error("the capture on VPC 10's workload saw none of the other connector's requests")
	}
	denied := sum(s.scrape(t, pod), "galactic_connectip_packets_denied_total", "direction", "to_vpc",
		"reason", "source") - sum(before, "galactic_connectip_packets_denied_total", "direction", "to_vpc",
		"reason", "source")
	l.record(t, transport+": packets the server refused for their source", fmt.Sprintf("%v of %d sent", denied,
		sentCount(evs)))
	if transport == "h2" && denied < float64(sentCount(evs))*9/10 {
		t.Errorf("the server counted %v of the %d spoofed packets as refused for their source", denied,
			sentCount(evs))
	}
}

// isolationOver runs the lab's isolation check between VPC 10's and VPC
// 20's connectors, which hold the same /96, over transport.
func (s *service) isolationOver(t *testing.T, transport string) {
	t.Helper()
	l := s.l
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
	clients := make([]isoClient, 0, 2)
	for _, c := range []*svcConnector{s.c10, s.c20} {
		clients = append(clients, isoClient{vpc: c.tn.vpc, id: c.echo,
			own: []workloadRef{l.workloadOn(t, c.tn, computeNode), l.workloadOn(t, c.tn, edgeNode1)},
			start: func(name string, d time.Duration, dsts []string) *probeRun {
				return s.connect(t, name+"-"+transport, c, transport, d, dsts...)
			},
			session: func(t *testing.T, what string, evs []event, d time.Duration, n int) {
				t.Helper()
				requireSessionFor(t, what, evs, d, n, c.issued.Prefix)
				if p := proto(evs); p != transport {
					t.Errorf("%s: negotiated %q, want %s", what, p, transport)
				}
			}})
	}
	var links []string
	for _, c := range []*svcConnector{s.c10, s.c20} {
		if att := s.attachment(t, s.pod, c); att != nil && att.Status.HostLink != "" {
			links = append(links, att.Status.HostLink)
		}
	}
	l.isolation(t, transport, links, clients[0], clients[1])
}

// rowSpoofingIsolationH3 runs the spoofing and cross-tenant isolation cases
// over HTTP/3, the baseline the HTTP/2 row repeats.
func (s *service) rowSpoofingIsolationH3(t *testing.T) {
	s.spoofing(t, "h3")
	s.isolationOver(t, "h3")
}

// rowH2AuthzIsolation repeats over HTTP/2 the HTTP/3 rows' denials,
// spoofing, denied VPC selection, cross-tenant isolation and credential
// expiry.
func (s *service) rowH2AuthzIsolation(t *testing.T) {
	s.authorization(t, "h2")
	s.spoofing(t, "h2")
	s.isolationOver(t, "h2")
	s.expiry(t, "h2")
}

// rowMTU1280 exchanges 1280-byte packets in both directions over each
// transport between VPC 10's connector and its workloads on the provider's
// node and the compute node, and the off-fabric host through NAT egress.
func (s *service) rowMTU1280(t *testing.T) {
	l, c := s.l, s.c10
	ws := []workloadRef{l.workloadOn(t, c.tn, edgeNode1), l.workloadOn(t, c.tn, computeNode),
		{node: "the off-fabric host through NAT", addr: remoteHost}}
	dsts := make([]string, 0, len(ws))
	for _, w := range ws {
		dsts = append(dsts, w.addr)
	}
	for _, transport := range []string{"h3", "h2"} {
		run := s.connect(t, "mtu-1280-"+transport, c, transport, lifecycleWindow, dsts...)
		time.Sleep(pingDelay)
		pings := []*pinger{s.pingFrom(t, c.tn, 2, c.addr()), s.pingFrom(t, c.tn, 1, c.addr())}
		what := transport + " at 1280 bytes"
		inbound := s.requireDelivered(t, what, c, transport, run.wait(l, t), ws...)
		for _, p := range pings {
			s.requireInbound(t, what+": gVPC pings", p, inbound[p.w.addr])
		}
	}
}

// rowSamePodH3ToH2 opens VPC 10's connector over HTTP/3 and, while it
// forwards, a second request of it over HTTP/2 on the same pod. The second
// replaces the first: the first's last reply comes before the second's
// first, within replaceHandoff; the route keeps its claim and epoch; and
// the replacement receives nothing the first request's packets drew, so no
// packet buffered for the replaced request arrives after the replacement
// takes over.
func (s *service) rowSamePodH3ToH2(t *testing.T) {
	l, c := s.l, s.c10
	w := l.workloadOn(t, c.tn, edgeNode1)
	pa := netip.MustParsePrefix(c.issued.Prefix)
	first := s.connect(t, "same-pod-h3", c, "h3", 30*time.Second, w.addr)
	eventually(t, time.Minute, 500*time.Millisecond, c.name+"'s route accepted", func() (bool, error) {
		r := l.route(t, svcNS, c.vpcUID, pa)
		return r != nil && meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted), nil
	})
	time.Sleep(5 * time.Second)
	before := l.route(t, svcNS, c.vpcUID, pa)
	replacement := *c
	replacement.echo = c.echo + 2
	second := s.connect(t, "same-pod-h2", &replacement, "h2", lifecycleWindow, w.addr)
	evs2 := second.wait(l, t)
	evs1 := first.wait(l, t)
	if p := proto(evs1); p != "h3" {
		t.Errorf("the replaced request negotiated %q, want h3", p)
	}
	inbound := s.requireDelivered(t, "the HTTP/2 replacement", &replacement, "h2", evs2, w)
	l.record(t, "packets of the replaced request delivered to the replacement", len(inbound[w.addr]))
	if n := len(inbound[w.addr]); n > 0 {
		t.Errorf("the replacement received %d packets the replaced request's echo requests drew", n)
	}
	r1, r2 := echoes(evs1, w.addr), echoes(evs2, w.addr)
	if len(r1) == 0 || len(r2) == 0 {
		t.Fatalf("the HTTP/3 request had %d replies and the HTTP/2 replacement %d", len(r1), len(r2))
	}
	lastOld, firstNew := r1[len(r1)-1].T, r2[0].T
	l.record(t, "HTTP/3 request's last reply to the HTTP/2 replacement's first", firstNew-lastOld)
	if firstNew <= lastOld {
		t.Errorf("both requests received replies: the replacement's first came %v before the replaced request's "+
			"last", lastOld-firstNew)
	}
	if firstNew-lastOld > replaceHandoff {
		t.Errorf("the handoff took %v, threshold %v", firstNew-lastOld, replaceHandoff)
	}
	if !slices.ContainsFunc(evs1, func(e event) bool { return e.End && e.T < firstNew+replaceHandoff }) {
		t.Error("the server did not close the replaced request at the handoff")
	}
	after := l.route(t, svcNS, c.vpcUID, pa)
	if after == nil || before == nil || after.Spec.Claim == nil || before.Spec.Claim == nil ||
		after.Spec.Claim.Epoch != before.Spec.Claim.Epoch || after.UID != before.UID ||
		after.Spec.Claim.Attachment != before.Spec.Claim.Attachment {
		t.Errorf("the route's claim changed across the replacement: before %+v, after %+v", before, after)
	} else {
		l.record(t, "route claim epoch across the replacement", after.Spec.Claim.Epoch)
	}
	logs, err := l.kubectl("-n", svcNS, "logs", s.pod.Name, "-c", "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, `"msg":"replacing request"`) {
		t.Error("the provider did not log the replacement")
	}
}

// secondInstance is the provider Deployment the cross-node row runs on
// dfw-worker3.
const secondInstance = "masque-provider-b"

// deploySecond runs a second provider Deployment, the lab's provider
// overlay renamed with its own pod labels and no Service, on node, and
// returns its ready pod. Cleanup deletes it.
func (s *service) deploySecond(t *testing.T, node string) *corev1.Pod {
	t.Helper()
	l := s.l
	l.applyOverlayOf(t, s.overlay("provider"), secondInstance, fmt.Sprintf(`
patches:
  - target:
      kind: Deployment
      name: masque-provider
    options:
      allowNameChange: true
    patch: |-
      - op: replace
        path: /metadata/name
        value: %[1]s
      - op: replace
        path: /metadata/labels/app.kubernetes.io~1name
        value: %[1]s
      - op: replace
        path: /spec/selector/matchLabels/app.kubernetes.io~1name
        value: %[1]s
      - op: replace
        path: /spec/template/metadata/labels/app.kubernetes.io~1name
        value: %[1]s
      - op: replace
        path: /spec/template/spec/nodeSelector
        value: {kubernetes.io/hostname: %[2]s}
  - target:
      kind: Service
      name: masque-provider
    patch: |-
      $patch: delete
      apiVersion: v1
      kind: Service
      metadata:
        name: masque-provider
`, secondInstance, node), nil)
	t.Cleanup(func() { s.deleteSecond(t) })
	return s.waitReady(t, secondInstance, node, "")
}

// deleteSecond deletes the second provider Deployment and waits until its
// pods are gone.
func (s *service) deleteSecond(t *testing.T) {
	t.Helper()
	if _, err := s.l.kubectl("-n", svcNS, "delete", "deployment", secondInstance, "--ignore-not-found",
		"--wait=true", "--timeout=120s"); err != nil {
		t.Error(err)
	}
	eventually(t, 2*time.Minute, time.Second, secondInstance+" pods gone", func() (bool, error) {
		var pods corev1.PodList
		err := s.l.c.List(context.Background(), &pods, client.InNamespace(svcNS),
			client.MatchingLabels{nameLabel: secondInstance})
		return err == nil && len(pods.Items) == 0, err
	})
}

// rowCrossNodeH3ToH2 moves VPC 10's connector from its HTTP/3 request on
// the provider on dfw-worker2, which keeps running with its path usable,
// to an HTTP/2 request on a provider on dfw-worker3. The authority retires
// the old pod's authorization before it issues the new pod's, and core
// moves the route only once the old holder's gate is closed, so the old
// request's last reply comes before the new one's first. The row records
// whether the old request was confirmed closed before the new one
// forwarded or the move waited on core's takeover, and how long the move
// took.
func (s *service) rowCrossNodeH3ToH2(t *testing.T) {
	l, c := s.l, s.c10
	b := s.deploySecond(t, edgeNode2)
	// The second pod's start can outlast the connector's idle
	// authorization; renew it on the first pod.
	s.waitConnected(t, c)
	wa, wb := l.workloadOn(t, c.tn, edgeNode1), l.workloadOn(t, c.tn, edgeNode2)
	pa := netip.MustParsePrefix(c.issued.Prefix)
	old := s.connect(t, "cross-node-h3", c, "h3", 90*time.Second, wa.addr)
	var before *galacticv1alpha1.EdgeRoute
	eventually(t, time.Minute, 500*time.Millisecond, c.name+"'s route accepted on "+s.pod.Name, func() (bool, error) {
		att := s.attachment(t, s.pod, c)
		before = l.route(t, svcNS, c.vpcUID, pa)
		return att != nil && before != nil && before.Spec.Claim != nil && !before.Spec.Claim.Released &&
			before.Status.Accepted != nil && before.Status.Accepted.Attachment == att.Name, nil
	})
	time.Sleep(5 * time.Second)
	moved := *c
	moved.echo = c.echo + 3
	start := boottime()
	var attempts []int
	var firstNew time.Duration
	eventually(t, 3*time.Minute, time.Second, c.name+" admitted on "+b.Name, func() (bool, error) {
		evs, err := s.once(b, &moved, "h2", wb.addr)
		if err != nil {
			return false, err
		}
		attempts = append(attempts, status(evs))
		if rs := echoes(evs, wb.addr); len(rs) > 0 {
			firstNew = rs[0].T
			return true, nil
		}
		return false, nil
	})
	l.record(t, "statuses of the requests to the new pod until one forwarded", attempts)
	l.record(t, "first reply on the new pod after the first request to it", firstNew-start)
	run := s.connectTo(t, b, "cross-node-h2", &moved, "h2", lifecycleWindow, wb.addr)
	s.requireDelivered(t, "the connector on "+b.Spec.NodeName, &moved, "h2", run.wait(l, t), wb)
	evs := old.wait(l, t)
	if p := proto(evs); p != "h3" {
		t.Errorf("the old request negotiated %q, want h3", p)
	}
	rs := echoes(evs, wa.addr)
	if len(rs) == 0 {
		t.Fatal("the old request never forwarded")
	}
	lastOld := rs[len(rs)-1].T
	l.record(t, "old request's last reply after the first request to the new pod", lastOld-start)
	l.record(t, "old request's last reply to the new pod's first", firstNew-lastOld)
	if firstNew <= lastOld {
		t.Errorf("both pods forwarded the connector: the new pod's first reply came %v before the old pod's last",
			lastOld-firstNew)
	}
	closed := slices.IndexFunc(evs, func(e event) bool { return e.End })
	switch {
	case closed >= 0 && evs[closed].T < firstNew:
		l.record(t, "old request", fmt.Sprintf("confirmed closed %v before the new pod's first reply (%s)",
			firstNew-evs[closed].T, evs[closed].Error))
	case closed >= 0:
		l.record(t, "old request", fmt.Sprintf("closed %v after the new pod's first reply, which waited out "+
			"core's takeover (%s)", evs[closed].T-firstNew, evs[closed].Error))
	default:
		t.Error("the old pod never closed the old request")
	}
	attB := s.attachment(t, b, &moved)
	after := l.route(t, svcNS, c.vpcUID, pa)
	if attB == nil || after == nil || after.Status.Accepted == nil || after.Status.Accepted.Attachment != attB.Name {
		t.Errorf("the route is not accepted for the new pod's attachment: %+v", after)
	} else if before.Spec.Claim != nil && after.Spec.Claim != nil {
		l.record(t, "route claim epoch before and after the move", fmt.Sprintf("%d to %d", before.Spec.Claim.Epoch,
			after.Spec.Claim.Epoch))
	}
	s.deleteSecond(t)
	s.waitConnected(t, c)
}

// ribSocket returns the GoBGP API socket of the compute node's
// galactic-router.
func (s *service) ribSocket(t *testing.T) string {
	t.Helper()
	out, err := nodeExec(computeNode, "sh", "-c", "ls /run/galactic-router/*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socks := strings.Fields(out)
	if len(socks) != 1 {
		t.Fatalf("want one GoBGP API socket on %s, found %v", computeNode, socks)
	}
	return socks[0]
}

// remotePaths returns how many EVPN routes for p the compute node's
// galactic-router holds now.
func (s *service) remotePaths(t *testing.T, socket string, p netip.Prefix) int {
	t.Helper()
	evs, err := runProbe(computeNode, []string{"rib", "-socket", socket, "-prefix", p.String(), "-duration", "100ms"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Paths != nil {
			return *e.Paths
		}
	}
	t.Fatalf("the RIB probe counted nothing: %+v", evs)
	return 0
}

// rowRemoteConvergence stops the provider's process while VPC 10's
// connector holds its route, and measures three events separately against
// the last renewal start: the local cutoff, when probes the compute node's
// workload sends into the /96 stop reaching the packet device; the local
// withdrawal, when the route's advertisement is deleted or reported not
// advertised; and remote convergence, when the compute node's
// galactic-router, polled through its GoBGP API every 200 ms, holds no
// route for the /96. Remote convergence must come within 5 s of the local
// withdrawal.
func (s *service) rowRemoteConvergence(t *testing.T) {
	l, c, pod := s.l, s.c10, s.pod
	pa := netip.MustParsePrefix(c.issued.Prefix)
	inside := pa.Addr().As16()
	inside[15] = 0x99
	w := l.workloadOn(t, c.tn, edgeNode1)
	session := s.connect(t, "convergence-session", c, "h3", 50*time.Second, w.addr)
	var att *galacticv1alpha1.EdgeAttachment
	var r *galacticv1alpha1.EdgeRoute
	eventually(t, time.Minute, 500*time.Millisecond, c.name+"'s route accepted", func() (bool, error) {
		att, r = s.attachment(t, pod, c), l.route(t, svcNS, c.vpcUID, pa)
		return att != nil && r != nil && r.Status.Accepted != nil && r.Status.Accepted.Attachment == att.Name, nil
	})
	socket := s.ribSocket(t)
	eventually(t, 30*time.Second, 200*time.Millisecond, "the compute node learning "+pa.String(), func() (bool, error) {
		return s.remotePaths(t, socket, pa) > 0, nil
	})
	rib, err := startProbe(computeNode, 1, "convergence-rib", "rib", "-socket", socket, "-prefix", pa.String(),
		"-interval", advertisementPoll.String(), "-duration", "42s")
	if err != nil {
		t.Fatal(err)
	}
	sniff, err := startProbe(edgeNode1, podPID(t, edgeNode1, svcNS, pod.Name), "convergence-device", "sniff",
		"-iface", att.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "42s")
	if err != nil {
		t.Fatal(err)
	}
	probe := l.probe(t, c.tn, computeNode, "convergence-probe",
		"["+netip.AddrFrom16(inside).String()+"]:"+strconv.Itoa(echoPort), 40*time.Second)
	stop := make(chan struct{})
	polled := make(chan withdrawal, 1)
	key := client.ObjectKey{Namespace: systemNS, Name: crdnames.EdgeAdvertisementName(string(r.UID))}
	go func() { polled <- pollWithdrawal(l, key, stop) }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			close(stop)
		}
	})
	time.Sleep(3 * time.Second)
	if err := signal(edgeNode1, svcNS, pod.Name, "masque-provider", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(edgeNode1, svcNS, pod.Name, "masque-provider", "CONT")
		}
	}()
	time.Sleep(time.Second)
	last, _ := s.lease(t, pod)
	time.Sleep(25 * time.Second)
	cont := boottime()
	if err := signal(edgeNode1, svcNS, pod.Name, "masque-provider", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	probe.wait(l, t)
	seen := windowed(sniff.wait(l, t))
	session.wait(l, t)
	stopped = true
	close(stop)
	wd := <-polled
	cutoff := l.requireCutoff(t, seen, wd, last, last, cont)
	var learned, gone time.Duration
	for _, e := range rib.wait(l, t) {
		switch {
		case e.Paths == nil:
		case *e.Paths > 0:
			learned, gone = e.T, 0
		case learned != 0 && gone == 0:
			gone = e.T
		}
	}
	switch {
	case learned == 0:
		t.Error("the compute node never held the connector's route during the window")
	case gone == 0:
		t.Error("the compute node kept the connector's route through the window")
	case !wd.seen:
	default:
		l.record(t, "remote convergence after the local withdrawal", gone-wd.at)
		l.record(t, "remote convergence after the local cutoff", gone-cutoff)
		if gone-wd.at > remoteConvergenceTarget {
			t.Errorf("the compute node dropped the route %v after the local withdrawal, target %v", gone-wd.at,
				remoteConvergenceTarget)
		}
	}
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
}

// rowNodeRestart restarts the provider's Kind node container with
// deploy/containerlab/scripts/restart-node.sh, which also restores the
// links and addresses the restart takes with the container's network
// namespace, while VPC 10's connector forwards. The node shares the host's
// kernel, so its boot ID stays the same; the row records it. The old
// process stops renewing; its route's advertisement is withdrawn within the
// local expiry bound of the last renewal and the compute node drops the
// route. A new provider process comes back on the node, in the same pod or
// in the one its Deployment puts in place of a pod the restarted kubelet
// refused, claims the route only after the old lease's deadline, so the two
// never hold forwarding authority at once, and serves the connectors again.
func (s *service) rowNodeRestart(t *testing.T) {
	l, c, pod, ctx := s.l, s.c10, s.pod, context.Background()
	pa := netip.MustParsePrefix(c.issued.Prefix)
	w := l.workloadOn(t, c.tn, edgeNode1)
	session := s.connect(t, "node-restart-session", c, "h3", 30*time.Second, w.addr)
	var att *galacticv1alpha1.EdgeAttachment
	var r *galacticv1alpha1.EdgeRoute
	eventually(t, time.Minute, 500*time.Millisecond, c.name+"'s route accepted", func() (bool, error) {
		att, r = s.attachment(t, pod, c), l.route(t, svcNS, c.vpcUID, pa)
		return att != nil && r != nil && r.Status.Accepted != nil && r.Status.Accepted.Attachment == att.Name, nil
	})
	socket := s.ribSocket(t)
	eventually(t, 30*time.Second, 200*time.Millisecond, "the compute node learning "+pa.String(), func() (bool, error) {
		return s.remotePaths(t, socket, pa) > 0, nil
	})
	beforePID, err := containerPID(edgeNode1, svcNS, pod.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	_, epoch := s.lease(t, pod)
	rib, err := startProbe(computeNode, 1, "node-restart-rib", "rib", "-socket", socket, "-prefix", pa.String(),
		"-interval", advertisementPoll.String(), "-duration", "60s")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	polled := make(chan withdrawal, 1)
	key := client.ObjectKey{Namespace: systemNS, Name: crdnames.EdgeAdvertisementName(string(r.UID))}
	go func() { polled <- pollWithdrawal(l, key, stop) }()
	time.Sleep(3 * time.Second)
	last, _ := s.lease(t, pod)
	restart := exec.CommandContext(ctx, filepath.Join(l.root, "deploy", "containerlab", "scripts", "restart-node.sh"),
		edgeNode1)
	out, err := restart.CombinedOutput()
	l.save(t, "restart-node.txt", out)
	if err != nil {
		close(stop)
		t.Fatalf("restart-node.sh %s: %v: %s", edgeNode1, err, out)
	}
	restarted := boottime()
	ids := regexp.MustCompile(`boot ID (before|after): (\S+)`).FindAllStringSubmatch(string(out), -1)
	if len(ids) != 2 {
		t.Fatalf("restart-node.sh printed no boot IDs: %s", out)
	}
	l.record(t, "boot ID before and after the restart", ids[0][2]+", "+ids[1][2])
	if ids[0][2] != ids[1][2] {
		t.Errorf("the node's boot ID changed across a container restart: %s to %s", ids[0][2], ids[1][2])
	}
	// The probe ran in the node's host network namespace, which the
	// restart replaced; whatever it printed before is enough.
	_ = session.cmd.Wait()
	evs := rib.wait(l, t)
	close(stop)
	wd := <-polled
	switch {
	case !wd.seen:
		t.Error("the route's advertisement was never withdrawn")
	default:
		l.record(t, "local withdrawal after the last renewal start", wd.at-last)
		if wd.at-last > localExpiry+time.Second+advertisementPoll {
			t.Errorf("the route was withdrawn %v after the last renewal start, bound %v plus 1 s and the poll",
				wd.at-last, localExpiry)
		}
	}
	var learned, gone time.Duration
	for _, e := range evs {
		switch {
		case e.Paths == nil:
		case *e.Paths > 0:
			learned, gone = e.T, 0
		case learned != 0 && gone == 0:
			gone = e.T
		}
	}
	if gone == 0 {
		t.Error("the compute node kept the connector's route after the node restarted")
	} else if wd.seen {
		l.record(t, "remote convergence after the local withdrawal", gone-wd.at)
	}
	l.record(t, "node restarted and replumbed after the last renewal start", restarted-last)
	s.waitNodePodsReady(t, edgeNode1)
	l.record(t, "every pod on the node ready after the last renewal start", boottime()-last)
	back := s.waitReady(t, "masque-provider", edgeNode1, "")
	old := &corev1.Pod{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(pod), old); err == nil && back.UID != pod.UID {
		l.record(t, "provider pod", fmt.Sprintf("replaced: the old pod is %s (%s)", old.Status.Phase, old.Status.Reason))
	} else if back.UID == pod.UID {
		l.record(t, "provider pod", "restarted in place")
	} else {
		l.record(t, "provider pod", "replaced; the old pod is gone")
	}
	s.pod = back
	pid, err := containerPID(edgeNode1, svcNS, back.Name, "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "provider process before and after", fmt.Sprintf("%d in pod %s, %d in pod %s", beforePID, pod.UID,
		pid, back.UID))
	s.waitConnected(t, s.c10)
	s.waitConnected(t, s.c20)
	l.record(t, "serving again after the restart", (boottime() - restarted).Round(time.Second))
	logs, err := l.kubectl("-n", svcNS, "logs", back.Name, "-c", "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	l.save(t, "provider.log", []byte(logs))
	if back.UID == pod.UID {
		if _, newEpoch := s.lease(t, back); newEpoch <= epoch {
			t.Errorf("the restarted process forwards under lease epoch %d, not after %d", newEpoch, epoch)
		}
	}
	// The new process may claim the connector's route only once the old
	// lease, last renewed at last, has expired.
	accepted := regexp.MustCompile(`"ts":"([^"]+)"[^\n]*"msg":"route accepted"[^\n]*"route":"` + r.Name + `"`).
		FindStringSubmatch(logs)
	if accepted == nil {
		t.Fatalf("the provider back after the restart logged no acceptance of route %s", r.Name)
	}
	at, err := time.Parse(time.RFC3339Nano, accepted[1])
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "route claimed again after the old lease's last renewal start", wallToBoot(at)-last)
	if wallToBoot(at) < last+leaseDuration-margin {
		t.Errorf("the route was claimed again %v after the old lease's last renewal start, before its %v deadline",
			wallToBoot(at)-last, leaseDuration)
	}
	if cur := l.route(t, svcNS, c.vpcUID, pa); cur == nil || cur.Status.Accepted == nil {
		t.Error("the connector's route is not accepted after the restart")
	}
}

// waitNodePodsReady waits until every pod on node that has not finished is
// ready. The kubelet of a restarted node comes back before the TUN device
// plugin registers again, so it can refuse a pod that requests the device;
// such a pod fails and its controller replaces it.
func (s *service) waitNodePodsReady(t *testing.T, node string) {
	t.Helper()
	eventually(t, 10*time.Minute, 5*time.Second, "every pod on "+node+" ready", func() (bool, error) {
		var pods corev1.PodList
		if err := s.l.c.List(context.Background(), &pods, client.MatchingFields{"spec.nodeName": node}); err != nil {
			return false, err
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || p.DeletionTimestamp != nil {
				continue
			}
			if !podReady(p) {
				return false, fmt.Errorf("%s/%s not ready", p.Namespace, p.Name)
			}
		}
		return true, nil
	})
}

// mtuSteps are the outer MTUs mtu-live-drop sets on the provider pod's
// host-side veth, each for mtuStep. A 1280-byte inner packet needs about
// 1340 bytes of path over HTTP/3, so the last steps are below the floor.
var mtuSteps = []int{1500, 1420, 1400, 1380, 1360, 1340, 1320, 1300}

const (
	mtuStep = 8 * time.Second
	// oversize is the inner packet size the workload sends toward the
	// connector, above the 1280-byte floor.
	oversize = 1400
)

// hostVeth returns the host side of pod's eth0 on its node.
func hostVeth(t *testing.T, pod *corev1.Pod) string {
	t.Helper()
	pid := podPID(t, pod.Spec.NodeName, pod.Namespace, pod.Name)
	out, err := nodeExec(pod.Spec.NodeName, "nsenter", "-t", strconv.Itoa(pid), "-n", "ip", "-o", "link", "show", "eth0")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`eth0@if(\d+):`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no peer index for eth0: %s", out)
	}
	host, err := nodeExec(pod.Spec.NodeName, "ip", "-o", "link")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(host, "\n") {
		if strings.HasPrefix(line, m[1]+": ") {
			return strings.Split(strings.Fields(line)[1], "@")[0]
		}
	}
	t.Fatalf("no host link with index %s", m[1])
	return ""
}

// mtuWindow counts, between from and to, the packetSize-byte echo replies
// and the oversize-byte packets from dst that a tunnel delivered, and the
// Packet Too Big messages captured at ptbs.
func mtuWindow(evs []event, ptbs []time.Duration, dst string, from, to time.Duration) (replies, big, ptb int) {
	for _, e := range evs {
		if e.T < from || e.T >= to {
			continue
		}
		switch {
		case e.Reply == "echo" && e.From == dst && e.Len == packetSize:
			replies++
		case e.Reply == otherReply && e.From == dst && e.Len == oversize:
			big++
		}
	}
	for _, p := range ptbs {
		if p >= from && p < to {
			ptb++
		}
	}
	return replies, big, ptb
}

// capturePacketTooBig captures the ICMPv6 Packet Too Big messages w receives
// for up to d, returning once tcpdump listens. The returned function waits for
// the capture to end and returns tcpdump's output, one message per line.
func capturePacketTooBig(t *testing.T, w workloadRef, d time.Duration) func() string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	cmd := exec.CommandContext(ctx, "docker", "exec", w.node, "timeout", strconv.Itoa(int(d.Seconds())),
		"nsenter", "-t", strconv.Itoa(w.pid), "-n", "tcpdump", "-n", "-l", "-tt", "-i", w.iface,
		"icmp6 and ip6[40] == 2")
	var out strings.Builder
	cmd.Stdout = &out
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	listening, stderrDone := make(chan struct{}), make(chan struct{})
	var startup strings.Builder
	go func() {
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "listening on") {
				close(listening)
				_, _ = io.Copy(io.Discard, stderr)
				return
			}
			startup.WriteString(sc.Text())
			startup.WriteByte('\n')
		}
	}()
	var once sync.Once
	wait := func() string {
		once.Do(func() {
			// Wait closes the pipe, so the reader must finish first.
			<-stderrDone
			_ = cmd.Wait()
			cancel()
		})
		return out.String()
	}
	t.Cleanup(func() {
		cancel()
		wait()
	})
	select {
	case <-listening:
	case <-stderrDone:
		t.Fatalf("tcpdump exited before listening at the workload: %s", startup.String())
	case <-time.After(30 * time.Second):
		t.Fatal("tcpdump did not start listening at the workload")
	}
	return wait
}

// rowMTULiveDrop lowers the MTU of the provider pod's host-side veth step
// by step during an HTTP/3 tunnel of VPC 10's connector, which exchanges
// 1280-byte echo requests and replies with its workload on the provider's
// node while that workload also sends it oversize-byte packets, and VPC
// 10's second connector runs alongside. At each step it records the outer
// MTU, how many 1280-byte replies and oversize-byte packets arrived, the
// ICMPv6 Packet Too Big messages the workload received, and whether the
// tunnel was open. Above the floor, an oversize-byte packet the path no
// longer carries must draw a Packet Too Big to the workload. The workload
// caches the reported MTU and stops sending oversize-byte packets (RFC
// 8201), so each step's window opens by flushing that cache; below it, the
// tunnel must end with the provider counting path_mtu. The second
// connector must never receive a Packet Too Big or anything else not its
// own. The MTU is restored on cleanup.
func (s *service) rowMTULiveDrop(t *testing.T) {
	l, c, pod := s.l, s.c10, s.pod
	veth := hostVeth(t, pod)
	setMTU := func(m int) error {
		_, err := nodeExec(pod.Spec.NodeName, "ip", "link", "set", "dev", veth, "mtu", strconv.Itoa(m))
		return err
	}
	t.Cleanup(func() {
		if err := setMTU(1500); err != nil {
			t.Error(err)
		}
	})
	w := l.workloadOn(t, c.tn, edgeNode1)
	total := time.Duration(len(mtuSteps))*mtuStep + 8*time.Second
	before := s.scrape(t, pod)
	run := s.connect(t, "mtu-live-drop", c, "h3", total, w.addr)
	other := s.connect(t, "mtu-live-drop-other", s.c10b, "h3", total, w.addr)
	time.Sleep(4 * time.Second)
	ptbWait := capturePacketTooBig(t, w, total)
	flushPMTU := func() error {
		_, err := nodeExec(w.node, "nsenter", "-t", strconv.Itoa(w.pid), "-n", "ip", "-6", "route", "flush", "cache")
		return err
	}
	pod10 := l.clientPod(t, c.tn, 2)
	pinging := make(chan struct{})
	go func() {
		defer close(pinging)
		// timeout bounds the ping instead of -w, with which iputils ping
		// exits at its first error, the Packet Too Big.
		_, _ = l.kubectl("-n", pod10.Namespace, execVerb, pod10.Name, "--", "timeout",
			strconv.Itoa(int((total - 6*time.Second).Seconds())), "ping", "-6", "-n", "-q", "-i", "0.2",
			"-s", strconv.Itoa(oversize-48), c.addr())
	}()
	starts := make([]time.Duration, len(mtuSteps))
	for i, m := range mtuSteps {
		if err := setMTU(m); err != nil {
			t.Fatal(err)
		}
		starts[i] = boottime()
		time.Sleep(time.Second)
		// mtuWindow has just opened, so the window's next oversize-byte
		// packet leaves the workload whatever an earlier step's Packet Too
		// Big left in its cache.
		if err := flushPMTU(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(starts[i] + mtuStep - boottime())
	}
	if err := setMTU(1500); err != nil {
		t.Error(err)
	}
	evs := run.wait(l, t)
	oevs := other.wait(l, t)
	<-pinging
	ptbOut := ptbWait()
	l.save(t, "packet-too-big.txt", []byte(ptbOut))
	var ptbs []time.Duration
	for _, line := range strings.Split(ptbOut, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
				ptbs = append(ptbs, wallToBoot(time.Unix(0, int64(sec*1e9))))
			}
		}
	}
	end := slices.IndexFunc(evs, func(e event) bool { return e.End })
	floor := -1
	for i, m := range mtuSteps {
		from, to := starts[i]+time.Second, starts[i]+mtuStep
		replies, big, ptb := mtuWindow(evs, ptbs, w.addr, from, to)
		open := end < 0 || evs[end].T >= to
		l.record(t, fmt.Sprintf("step %d: outer MTU %d", i, m), fmt.Sprintf(
			"%d %d-byte replies, %d %d-byte packets toward the connector, %d Packet Too Big at the workload, tunnel %s",
			replies, packetSize, big, oversize, ptb, map[bool]string{true: "open", false: "ended"}[open]))
		switch {
		case replies > 0 && big == 0 && ptb == 0:
			t.Errorf("outer MTU %d: %d-byte packets toward the connector were dropped without a Packet Too Big "+
				"(#1237)", m, oversize)
		case replies == 0 && floor < 0:
			floor = i
		}
	}
	after := s.scrape(t, pod)
	pathMTU := sum(after, "galactic_connectip_packets_denied_total", "reason", "path_mtu") -
		sum(before, "galactic_connectip_packets_denied_total", "reason", "path_mtu")
	endsMTU := sum(after, "galactic_connectip_tunnel_ends_total", "cause", "path_mtu") -
		sum(before, "galactic_connectip_tunnel_ends_total", "cause", "path_mtu")
	l.record(t, "packets counted path_mtu", pathMTU)
	l.record(t, "tunnels ended path_mtu", endsMTU)
	switch {
	case floor < 0:
		t.Errorf("1280-byte packets crossed every step down to MTU %d; the floor was never reached",
			mtuSteps[len(mtuSteps)-1])
	case end < 0 || evs[end].T >= starts[floor]+mtuStep:
		t.Errorf("below the floor, at outer MTU %d, the tunnel stayed open without carrying 1280-byte packets (#1237)",
			mtuSteps[floor])
	}
	if floor >= 0 && (pathMTU == 0 || endsMTU == 0) {
		t.Errorf("the provider counted %v packets and %v tunnel ends as path_mtu below the floor (#1237)", pathMTU,
			endsMTU)
	}
	for _, e := range oevs {
		if e.Reply == otherReply {
			t.Errorf("the other connector received a packet that was not its reply: %d bytes from %s", e.Len, e.From)
			break
		}
	}
}

// Metric names, log messages and log keys the diagnostics walk reads.
const (
	mRequests        = "galactic_connectip_requests_total"
	mAdmissions      = "galactic_masque_admissions_total"
	logRejected      = "CONNECT-IP request rejected"
	logEnded         = "request ended"
	outcomeForbidden = "forbidden"
	causeLeaseEnded  = "lease_ended"
	keyConnector     = "connector"
	keyOutcome       = "outcome"
	keyTransport     = "transport"
	outcomeUnauth    = "unauthenticated"
)

// logLine is one JSON log line of the provider.
type logLine map[string]any

// providerLogs returns pod's provider log lines since since.
func (s *service) providerLogs(t *testing.T, pod *corev1.Pod, since time.Time) []logLine {
	t.Helper()
	out, err := s.l.kubectl("-n", svcNS, "logs", pod.Name, "-c", "masque-provider",
		"--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var lines []logLine
	for _, raw := range strings.Split(out, "\n") {
		var line logLine
		if json.Unmarshal([]byte(raw), &line) == nil {
			lines = append(lines, line)
		}
	}
	return lines
}

// logged reports whether a line of lines has msg and every key/value pair
// of kv.
func logged(lines []logLine, msg string, kv ...string) bool {
	return slices.ContainsFunc(lines, func(line logLine) bool {
		if line["msg"] != msg {
			return false
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if fmt.Sprint(line[kv[i]]) != kv[i+1] {
				return false
			}
		}
		return true
	})
}

// diagnosis is what docs/edge/troubleshooting.md's connector workflow
// reads for one state: metric deltas that must grow, and log lines that
// must appear.
type diagnosis struct {
	state   string
	metrics [][]string
	logs    [][]string
}

// check fails unless every metric of d grew between before and after and
// every log line of d is in lines.
func (d diagnosis) check(t *testing.T, l *lab, before, after []metric, lines []logLine) {
	t.Helper()
	for _, m := range d.metrics {
		delta := sum(after, m[0], m[1:]...) - sum(before, m[0], m[1:]...)
		l.record(t, d.state+": "+strings.Join(m, " "), delta)
		if delta <= 0 {
			t.Errorf("%s: %s did not grow", d.state, strings.Join(m, " "))
		}
	}
	for _, g := range d.logs {
		ok := logged(lines, g[0], g[1:]...)
		l.record(t, d.state+": log "+strings.Join(g, " "), ok)
		if !ok {
			t.Errorf("%s: no %q log line with %v", d.state, g[0], g[1:])
		}
	}
}

// rowDiagnosticsWalk produces each connector state #983 lists and checks
// that the provider's metrics and log lines identify it the way
// docs/edge/troubleshooting.md's connector workflow says:
//
//   - client denial: an unknown credential on both transports and another
//     VPC's selection, refused by the authority (step 2);
//   - policy denial: HTTP/2 packets from outside the /96 and to a
//     destination outside the grant's routes, counted by the packet policy
//     (step 5);
//   - expired gate: the authority stopped, so the open request's grant is
//     not refreshed and ends at its deadline (step 4);
//   - programmed but not ready, and provider denial: the pod partitioned
//     from the API server, so an open request is programmed with the lease
//     lost (step 3), and a new one is refused for want of a lease (step 2);
//   - unaccepted claim: galactic-controller stopped, so the connector's
//     route claim is written but never accepted (step 2);
//   - remote convergence: once a request ends, its route is released, its
//     advertisement withdrawn and the compute node's route gone (step 5).
func (s *service) rowDiagnosticsWalk(t *testing.T) {
	l, c := s.l, s.c10
	dst := l.workloadOn(t, c.tn, edgeNode1).addr
	since := time.Now().Add(-time.Second)
	connector := c.issued.Connector

	// Client denial.
	before := s.scrape(t, s.pod)
	unknown := &svcConnector{name: "unknown", tn: c.tn, echo: 1,
		issued: issuedGrant{Credential: rand.Text(), Prefix: c.issued.Prefix}}
	foreign := &svcConnector{name: "foreign", tn: svcTenant20, echo: 1, issued: c.issued}
	for _, tr := range []string{"h3", "h2"} {
		if _, err := s.once(s.pod, unknown, tr, dst); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.once(s.pod, foreign, "h3", dst); err != nil {
		t.Fatal(err)
	}
	after := s.scrape(t, s.pod)
	diagnosis{state: "client denial", metrics: [][]string{
		{mRequests, keyTransport, "h3", keyOutcome, outcomeUnauth},
		{mRequests, keyTransport, "h2", keyOutcome, outcomeUnauth},
		{mRequests, keyTransport, "h3", keyOutcome, outcomeForbidden},
		{mAdmissions, keyOutcome, outcomeUnauth},
		{mAdmissions, keyOutcome, outcomeForbidden},
	}, logs: [][]string{
		{logRejected, keyTransport, "h3", keyOutcome, outcomeUnauth},
		{logRejected, keyTransport, "h2", keyOutcome, outcomeUnauth},
		{logRejected, keyTransport, "h3", keyOutcome, outcomeForbidden},
	}}.check(t, l, before, after, s.providerLogs(t, s.pod, since))

	// Policy denial, over HTTP/2, whose client sends what it is given.
	before = after
	outside := netip.MustParsePrefix(svcConnectors).Addr().As16()
	outside[11], outside[15] = 0xff, 1
	spoof, err := startProbe(s.pod.Spec.NodeName, 1, "diagnostics-source", append(s.connectArgs(s.pod, c, "h2",
		3*time.Second, dst), "-src", netip.AddrFrom16(outside).String())...)
	if err != nil {
		t.Fatal(err)
	}
	spoof.wait(l, t)
	off := s.connect(t, "diagnostics-destination", c, "h2", 3*time.Second, l.workloadOn(t, svcTenant20, edgeNode1).addr)
	off.wait(l, t)
	after = s.scrape(t, s.pod)
	diagnosis{state: "policy denial", metrics: [][]string{
		{"galactic_connectip_packets_denied_total", "direction", "to_vpc", "reason", "source"},
		{"galactic_connectip_packets_denied_total", "direction", "to_vpc", "reason", "destination"},
	}}.check(t, l, before, after, nil)

	s.diagnoseExpiredGate(t, c, dst)
	s.diagnoseLeaseLoss(t, c, dst)
	s.diagnoseUnacceptedClaim(t, c, dst)
	s.diagnoseRemoteConvergence(t, c, dst, connector)
}

// diagnoseExpiredGate stops the authority while c forwards: the request's
// grant is not refreshed, so it ends at its deadline as grant_expired, the
// server reporting lease_ended.
func (s *service) diagnoseExpiredGate(t *testing.T, c *svcConnector, dst string) {
	t.Helper()
	l := s.l
	authority := s.waitReady(t, "masque-authority", computeNode, "")
	since := time.Now().Add(-time.Second)
	before := s.scrape(t, s.pod)
	run := s.connect(t, "diagnostics-expired-gate", c, "h3", 50*time.Second, dst)
	s.freshGrants(t, []*svcConnector{c})
	if err := signal(computeNode, svcNS, authority.Name, "masque-authority", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(computeNode, svcNS, authority.Name, "masque-authority", "CONT")
		}
	}()
	stopped := boottime()
	evs := run.wait(l, t)
	if err := signal(computeNode, svcNS, authority.Name, "masque-authority", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	if i := slices.IndexFunc(evs, func(e event) bool { return e.End }); i >= 0 {
		l.record(t, "expired gate: request ended after the authority stopped", evs[i].T-stopped)
	} else {
		t.Error("expired gate: the request ran to its end with the authority stopped")
	}
	after := s.scrape(t, s.pod)
	lines := s.providerLogs(t, s.pod, since)
	// Core drains the attachment MaxSkew before the grant's deadline, so the
	// request can end as attachment_draining before the adapter's own
	// deadline ends it as grant_expired. The failed refresh tells both apart
	// from a drain for another cause.
	ended := sum(after, "galactic_masque_request_ends_total", "reason", "grant_expired") +
		sum(after, "galactic_masque_request_ends_total", "reason", "attachment_draining") -
		sum(before, "galactic_masque_request_ends_total", "reason", "grant_expired") -
		sum(before, "galactic_masque_request_ends_total", "reason", "attachment_draining")
	l.record(t, "expired gate: requests ended grant_expired or attachment_draining", ended)
	if ended <= 0 {
		t.Error("expired gate: no request ended as grant_expired or attachment_draining")
	}
	reason := ""
	for _, line := range lines {
		if line["msg"] == logEnded && line[keyConnector] == c.issued.Connector {
			reason = fmt.Sprint(line["endReason"])
		}
	}
	l.record(t, "expired gate: endReason", reason)
	if reason != "grant_expired" && reason != "attachment_draining" {
		t.Errorf("expired gate: the request ended as %q, want grant_expired or attachment_draining", reason)
	}
	diagnosis{state: "expired gate", metrics: [][]string{
		{"galactic_connectip_tunnel_ends_total", keyTransport, "h3", "cause", causeLeaseEnded},
	}, logs: [][]string{
		{"grant refresh failed; the request keeps its deadline", keyConnector, c.issued.Connector},
		{"CONNECT-IP request ended", keyConnector, c.issued.Connector, "cause", causeLeaseEnded},
	}}.check(t, l, before, after, lines)
	s.waitConnected(t, c)
}

// diagnoseLeaseLoss partitions the pod from the API server while c holds
// an idle request, which sends one echo request and then nothing, and VPC
// 20's connector forwards. Once the lease's deadline passes, a scrape
// shows a request programmed with the lease not held, both requests end as
// lease_lost, and a new request is refused as no_lease.
func (s *service) diagnoseLeaseLoss(t *testing.T, c *svcConnector, dst string) {
	t.Helper()
	l, pod := s.l, s.pod
	since := time.Now().Add(-time.Second)
	before := s.scrape(t, pod)
	idle, err := startProbe(pod.Spec.NodeName, 1, "diagnostics-lease-loss-idle",
		append(s.connectArgs(pod, c, "h3", 45*time.Second, dst), "-interval", "60s")...)
	if err != nil {
		t.Fatal(err)
	}
	busy := s.connect(t, "diagnostics-lease-loss-busy", s.c20, "h3", 45*time.Second,
		l.workloadOn(t, s.c20.tn, edgeNode1).addr)
	s.freshGrants(t, []*svcConnector{c, s.c20})
	_, heal := l.partitionAPI(t, edgeNode1, podPID(t, edgeNode1, svcNS, pod.Name))
	programmed := false
	eventually(t, localExpiry+15*time.Second, 100*time.Millisecond, "the lease lost", func() (bool, error) {
		ms := s.scrape(t, pod)
		if sum(ms, "galactic_masque_lease_held") == 0 && sum(ms, "galactic_masque_requests", "state", "programmed") > 0 {
			programmed = true
		}
		return sum(ms, "galactic_masque_lease_losses_total") > sum(before, "galactic_masque_lease_losses_total"), nil
	})
	// The programmed state lasts at most one renewal attempt past the
	// lease's deadline, so the workflow's step 4 reads the lost lease from
	// the requests' end reasons below; a scrape that caught it is recorded.
	l.record(t, "programmed but not ready: a scrape showed a request programmed with the lease not held", programmed)
	evs, err := s.once(pod, c, "h3", dst)
	if err != nil {
		t.Fatal(err)
	}
	l.record(t, "provider denial: a request without the lease", status(evs))
	heal()
	idle.wait(l, t)
	busy.wait(l, t)
	lines := s.providerLogs(t, pod, since)
	for _, x := range []*svcConnector{c, s.c20} {
		reason, cause := "", ""
		for _, line := range lines {
			if line[keyConnector] != x.issued.Connector {
				continue
			}
			switch line["msg"] {
			case logEnded:
				reason = fmt.Sprint(line["endReason"])
			case "CONNECT-IP request ended":
				cause = fmt.Sprint(line["cause"])
			}
		}
		l.record(t, "lease loss: "+x.name+"'s request ended", "cause "+cause+", endReason "+reason)
		if reason != "lease_lost" || cause != causeLeaseEnded {
			t.Errorf("lease loss: %s's request ended with cause %q and endReason %q, want lease_ended and "+
				"lease_lost (#1239 when it was forwarding)", x.name, cause, reason)
		}
	}
	diagnosis{state: "programmed but not ready, and provider denial", metrics: [][]string{
		{"galactic_masque_lease_losses_total"},
		{mAdmissions, keyOutcome, "no_lease"},
	}, logs: [][]string{
		{"lease lost"},
		{"admission refused", keyOutcome, "no_lease"},
	}}.check(t, l, before, s.scrape(t, pod), lines)
	s.pod = s.waitReady(t, "masque-provider", edgeNode1, "")
	s.waitConnected(t, c)
	s.waitConnected(t, s.c20)
}

// diagnoseUnacceptedClaim stops galactic-controller, core's cell
// controller, while c's attachment is ready and its claim released. The
// next request writes the claim, which core never accepts, so the request
// is refused as route_failed and the route shows the claim unaccepted.
func (s *service) diagnoseUnacceptedClaim(t *testing.T, c *svcConnector, dst string) {
	t.Helper()
	l := s.l
	var ctrl corev1.PodList
	if err := l.c.List(context.Background(), &ctrl, client.InNamespace(systemNS),
		client.MatchingLabels{nameLabel: "galactic-controller"}); err != nil || len(ctrl.Items) != 1 {
		t.Fatalf("want one galactic-controller pod: %v, %d", err, len(ctrl.Items))
	}
	cp := ctrl.Items[0]
	s.waitConnected(t, c)
	since := time.Now().Add(-time.Second)
	before := s.scrape(t, s.pod)
	if err := signal(cp.Spec.NodeName, systemNS, cp.Name, "controller", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(cp.Spec.NodeName, systemNS, cp.Name, "controller", "CONT")
		}
	}()
	p, err := startProbe(s.pod.Spec.NodeName, 1, "diagnostics-unaccepted-claim",
		s.connectArgs(s.pod, c, "h3", 5*time.Second, dst)...)
	if err != nil {
		t.Fatal(err)
	}
	att := s.attachment(t, s.pod, c)
	var r *galacticv1alpha1.EdgeRoute
	eventually(t, 25*time.Second, 200*time.Millisecond, "the claim written", func() (bool, error) {
		r = l.route(t, svcNS, c.vpcUID, netip.MustParsePrefix(c.issued.Prefix))
		return r != nil && r.Spec.Claim != nil && !r.Spec.Claim.Released && att != nil &&
			r.Spec.Claim.Attachment == att.Name, nil
	})
	evs := p.wait(l, t)
	if err := signal(cp.Spec.NodeName, systemNS, cp.Name, "controller", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	l.record(t, "unaccepted claim: request status", status(evs))
	if status(evs) != 503 {
		t.Errorf("unaccepted claim: the request got %d, want 503", status(evs))
	}
	switch {
	case r == nil || r.Spec.Claim == nil:
		t.Error("unaccepted claim: no route claim was written")
	case r.Spec.Claim.Released || meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) &&
		r.Status.Accepted != nil && r.Status.Accepted.Epoch == r.Spec.Claim.Epoch &&
		r.Status.Accepted.Attachment == r.Spec.Claim.Attachment:
		t.Errorf("unaccepted claim: the claim was %+v with status %+v", r.Spec.Claim, r.Status.Accepted)
	default:
		l.record(t, "unaccepted claim: route claim written and not accepted", r.Spec.Claim.Attachment)
	}
	diagnosis{state: "unaccepted claim", metrics: [][]string{
		{mAdmissions, keyOutcome, "route_failed"},
		{"galactic_masque_route_claims_total", keyOutcome, "failed"},
	}, logs: [][]string{
		{"admission refused", keyOutcome, "route_failed"},
	}}.check(t, l, before, s.scrape(t, s.pod), s.providerLogs(t, s.pod, since))
	eventually(t, 3*time.Minute, 2*time.Second, "galactic-controller ready again", func() (bool, error) {
		var pods corev1.PodList
		err := l.c.List(context.Background(), &pods, client.InNamespace(systemNS),
			client.MatchingLabels{nameLabel: "galactic-controller"})
		return err == nil && len(pods.Items) == 1 && podReady(&pods.Items[0]), err
	})
	s.waitConnected(t, c)
}

// diagnoseRemoteConvergence ends a request of c and checks the provider
// logs the route's release, its advertisement is withdrawn and the compute
// node drops the route within remoteConvergenceTarget.
func (s *service) diagnoseRemoteConvergence(t *testing.T, c *svcConnector, dst, connector string) {
	t.Helper()
	l := s.l
	pa := netip.MustParsePrefix(c.issued.Prefix)
	socket := s.ribSocket(t)
	since := time.Now().Add(-time.Second)
	run := s.connect(t, "diagnostics-convergence", c, "h3", 8*time.Second, dst)
	var r *galacticv1alpha1.EdgeRoute
	eventually(t, 30*time.Second, 200*time.Millisecond, "the compute node learning "+pa.String(), func() (bool, error) {
		r = l.route(t, svcNS, c.vpcUID, pa)
		return r != nil && s.remotePaths(t, socket, pa) > 0, nil
	})
	key := client.ObjectKey{Namespace: systemNS, Name: crdnames.EdgeAdvertisementName(string(r.UID))}
	run.wait(l, t)
	ended := time.Now()
	eventually(t, remoteConvergenceTarget+5*time.Second, 200*time.Millisecond, "the compute node dropping "+pa.String(),
		func() (bool, error) { return s.remotePaths(t, socket, pa) == 0, nil })
	l.record(t, "remote convergence: compute node dropped the route after the request ended",
		time.Since(ended).Round(100*time.Millisecond))
	var adv networkv1alpha1.BGPAdvertisement
	if err := l.c.Get(context.Background(), key, &adv); err == nil {
		if cnd := meta.FindStatusCondition(adv.Status.Conditions, "Advertised"); cnd == nil ||
			cnd.Status != metav1.ConditionFalse {
			t.Errorf("remote convergence: advertisement %s still advertised", key.Name)
		}
	}
	diagnosis{state: "remote convergence", logs: [][]string{
		{logEnded, keyConnector, connector, "endReason", "closed"},
		{"route released", "route", r.Name},
	}}.check(t, l, nil, nil, s.providerLogs(t, s.pod, since))
}
