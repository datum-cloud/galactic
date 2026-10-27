// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/edge/timing"
)

// masqueInside is an address in the connector /96 that no client answers:
// a packet to it reaches the fixture's packet device only through an open
// forwarding gate.
const masqueInside = "fd00:ed9e:300:1::99"

// replaceHandoff bounds the gap the client sees between the replaced
// request's last echo reply and the replacement's first: the replacement's
// handshake, its admission and the replaced request's quiesce, which the
// adapter bounds at one second.
const replaceHandoff = 3 * time.Second

// renewStart returns the latest renew-start of the fixture pod's instance
// lease on CLOCK_BOOTTIME.
func (m *masque) renewStart(t *testing.T) time.Duration {
	t.Helper()
	var le coordinationv1.Lease
	key := client.ObjectKey{Namespace: masqueNS, Name: "ei-" + string(m.pod.UID)}
	if err := m.l.c.Get(context.Background(), key, &le); err != nil {
		t.Fatal(err)
	}
	v, err := strconv.ParseInt(le.Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(v)
}

// lastRenewal is renewStart once a renewal already in flight has landed.
func (m *masque) lastRenewal(t *testing.T) time.Duration {
	t.Helper()
	time.Sleep(time.Second)
	return m.renewStart(t)
}

// gateWatch captures, on the fixture's packet device for mt, the probes
// tenant mt's workload on the compute node sends into the connector /96
// for d, while a request of mt's connector holds its route. A probe seen on
// the device passed the route's forwarding gate. It also polls the route's
// advertisement for the moment the holder stops advertising it.
type gateWatch struct {
	sniff, probe, session *probeRun
	stopPoll              chan struct{}
	stopOnce              sync.Once
	polled                chan withdrawal
}

// withdrawal is when a route's advertisement was first seen deleted or
// reported not advertised, on CLOCK_BOOTTIME, and whether it was.
type withdrawal struct {
	at   time.Duration
	seen bool
}

// advertisementPoll is how often gateWatch reads the route's
// advertisement; it bounds the withdrawal measurement's resolution.
const advertisementPoll = 200 * time.Millisecond

func (m *masque) watchGate(t *testing.T, name string, mt *masqueTenant, d time.Duration) *gateWatch {
	t.Helper()
	l := m.l
	att := l.attachmentOf(t, m.pod, mt.svc)
	session := m.connect(t, name+"-session", mt.token, mt.tn.vpc, mt.id, d+5*time.Second, m.workload(t, mt.tn, 2).addr)
	m.waitAcceptedFor(t, 2*time.Second, mt)
	r := l.route(t, masqueNS, mt.vpcUID, netip.MustParsePrefix(masquePrefix))
	if r == nil {
		t.Fatal("the connector's route is gone")
	}
	key := client.ObjectKey{Namespace: systemNS, Name: crdnames.EdgeAdvertisementName(string(r.UID))}
	pid := podPID(t, edgeNode1, masqueNS, m.pod.Name)
	sniff, err := startProbe(edgeNode1, pid, name+"-sniff", "sniff", "-iface", att.Status.PacketDevice,
		"-port", strconv.Itoa(echoPort), "-duration", (d + 2*time.Second).String())
	if err != nil {
		t.Fatal(err)
	}
	probe := l.probe(t, mt.tn, computeNode, name+"-probe", "["+masqueInside+"]:"+strconv.Itoa(echoPort), d)
	g := &gateWatch{sniff: sniff, probe: probe, session: session, stopPoll: make(chan struct{}),
		polled: make(chan withdrawal, 1)}
	go func() {
		g.polled <- pollWithdrawal(l, key, g.stopPoll)
	}()
	// A row that fails before wait still stops the poll.
	t.Cleanup(g.stop)
	time.Sleep(3 * time.Second)
	return g
}

// stop ends the advertisement poll; it may be called more than once.
func (g *gateWatch) stop() { g.stopOnce.Do(func() { close(g.stopPoll) }) }

// pollWithdrawal reads the advertisement at key every advertisementPoll
// until stop closes, and returns the first time it was deleted or reported
// not advertised.
func pollWithdrawal(l *lab, key client.ObjectKey, stop <-chan struct{}) withdrawal {
	t := time.NewTicker(advertisementPoll)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return withdrawal{}
		case <-t.C:
		}
		var adv networkv1alpha1.BGPAdvertisement
		now := boottime()
		err := l.c.Get(context.Background(), key, &adv)
		switch {
		case apierrors.IsNotFound(err):
			return withdrawal{at: now, seen: true}
		case err != nil:
			continue
		}
		if c := meta.FindStatusCondition(adv.Status.Conditions, "Advertised"); c != nil &&
			c.Status == metav1.ConditionFalse {
			return withdrawal{at: now, seen: true}
		}
	}
}

// wait returns the probes captured on the device, in time order, the
// client's events and the route's withdrawal.
func (g *gateWatch) wait(l *lab, t *testing.T) (seen, session []event, w withdrawal) {
	t.Helper()
	g.probe.wait(l, t)
	seen, session = windowed(g.sniff.wait(l, t)), g.session.wait(l, t)
	g.stop()
	return seen, session, <-g.polled
}

// leaseDuration is the instance lease's duration: a node's gate stays open
// for this long after the last renewal start it applied.
const leaseDuration = 15 * time.Second

// requireCutoff checks that the gate was open after last, the last renewal
// start the node can have applied, closed within localExpiry of it and no
// earlier than the lease duration after earliest, the earliest renewal start
// the node can have applied last, and stayed closed until resumed,
// when the fault ended. It records the local cutoff and the local
// withdrawal, the advertisement deleted or reported not advertised, which
// must follow the cutoff, within 1 s plus the poll interval.
func (m *masque) requireCutoff(t *testing.T, seen []event, w withdrawal, last, earliest, resumed time.Duration) {
	t.Helper()
	l := m.l
	if !slices.ContainsFunc(seen, func(e event) bool { return !e.last() && e.T >= last }) {
		t.Fatal("no probe reached the packet device after the last renewal start: the gate was never seen open")
	}
	stop, ok := stopAfter(seen, last)
	if !ok {
		t.Fatal("the connector's gate never closed")
	}
	l.record(t, "local cutoff after the last renewal start", stop-last)
	if stop-last > localExpiry {
		t.Errorf("the gate closed %v after the last renewal start, bound %v", stop-last, localExpiry)
	}
	if stop-earliest < leaseDuration-stopGap-margin {
		t.Errorf("the gate closed %v after the earliest renewal start it can have applied, before the lease "+
			"could expire", stop-earliest)
	}
	if again, ok := resumeAfter(seen, stop+time.Second); ok && again < resumed {
		t.Errorf("the gate reopened %v before the fault ended", resumed-again)
	}
	switch {
	case !w.seen:
		t.Error("the route's advertisement was never withdrawn during the window")
	case w.at < stop-advertisementPoll:
		t.Errorf("the route was withdrawn %v before the cutoff, so the gate did not cause it", stop-w.at)
	default:
		l.record(t, "local withdrawal after the cutoff", w.at-stop)
		if w.at-stop > time.Second+advertisementPoll {
			t.Errorf("the route was withdrawn %v after the cutoff, bound 1 s plus the %v poll", w.at-stop,
				advertisementPoll)
		}
	}
	l.record(t, "remote convergence", "not measured: the compute node's tenant routes are pinned eBPF map "+
		"entries the lab cannot read")
}

// rowReplace opens a second request of a connector while its first is
// forwarding, on the same pod: the first ends before the second forwards,
// the route claim stays held at the same epoch throughout, and the
// handoff is short.
func (m *masque) rowReplace(t *testing.T) {
	l := m.l
	dst := m.workload(t, m.a.tn, 2).addr
	pa := netip.MustParsePrefix(masquePrefix)
	first := m.connect(t, "replace-first", m.a.token, m.a.tn.vpc, m.a.id, 30*time.Second, dst)
	time.Sleep(5 * time.Second)
	before := l.route(t, masqueNS, m.a.vpcUID, pa)
	second := m.connect(t, "replace-second", m.a.token, m.a.tn.vpc, m.a.id+2, 10*time.Second, dst)
	evs2 := second.wait(l, t)
	evs1 := first.wait(l, t)
	m.requireAnswered(t, "replacement request", evs2, 10*time.Second, dst)
	r1, r2 := echoes(evs1, dst), echoes(evs2, dst)
	if len(r1) == 0 || len(r2) == 0 {
		t.Fatalf("the first request had %d replies and the replacement %d", len(r1), len(r2))
	}
	lastOld, firstNew := r1[len(r1)-1].T, r2[0].T
	// The client also reports End when it closes its own stream at the
	// end of its window; only an End near the handoff is the server's.
	if !slices.ContainsFunc(evs1, func(e event) bool { return e.End && e.T < firstNew+replaceHandoff }) {
		t.Error("the server did not close the replaced request's stream at the handoff")
	}
	l.record(t, "replaced request's last reply to the replacement's first", firstNew-lastOld)
	if firstNew <= lastOld {
		t.Errorf("both requests of the connector received replies: the replacement's first came %v before the "+
			"replaced request's last", lastOld-firstNew)
	}
	if firstNew-lastOld > replaceHandoff {
		t.Errorf("the handoff took %v, threshold %v", firstNew-lastOld, replaceHandoff)
	}
	after := l.route(t, masqueNS, m.a.vpcUID, pa)
	if after == nil || before == nil || after.Spec.Claim == nil || before.Spec.Claim == nil ||
		after.Spec.Claim.Epoch != before.Spec.Claim.Epoch || after.UID != before.UID {
		t.Errorf("the route's claim changed across the replacement: before %+v, after %+v", before, after)
	}
	logs, err := l.kubectl("-n", masqueNS, "logs", m.pod.Name, "-c", "masque-provider")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, `"msg":"replacing request"`) {
		t.Error("the fixture did not log the replacement")
	}
}

// rowProviderStall stops the fixture's process while a request holds its
// connector's route. The process can neither renew nor forward, so the
// gate is watched on its packet device: it must close within the local
// expiry bound of the last renewal start and stay closed while the process
// is stopped. The resumed process finds its lease expired, so it ends the
// request and serves the connector again only on a new request.
func (m *masque) rowProviderStall(t *testing.T) {
	l := m.l
	g := m.watchGate(t, "provider-stall", m.a, 45*time.Second)
	if err := signal(edgeNode1, masqueNS, m.pod.Name, "masque-provider", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(edgeNode1, masqueNS, m.pod.Name, "masque-provider", "CONT")
		}
	}()
	last := m.lastRenewal(t)
	time.Sleep(25 * time.Second)
	cont := boottime()
	if err := signal(edgeNode1, masqueNS, m.pod.Name, "masque-provider", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	seen, _, w := g.wait(l, t)
	m.requireCutoff(t, seen, w, last, last, cont)
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
}

// rowAgentStall stops galactic-edge on the fixture's node while the
// fixture keeps renewing: the node's gate expires at the deadline the agent
// last applied and stays closed while the agent is stopped.
func (m *masque) rowAgentStall(t *testing.T) {
	l := m.l
	agent := l.agentPod(t, edgeNode1)
	g := m.watchGate(t, "agent-stall", m.a, 45*time.Second)
	if err := signal(edgeNode1, systemNS, agent, "galactic-edge", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(edgeNode1, systemNS, agent, "galactic-edge", "CONT")
		}
	}()
	// The agent applied no renewal after it stopped, so the latest one it
	// can have applied started no later than this one, and no earlier than
	// one renewal interval before it.
	last := m.renewStart(t)
	time.Sleep(25 * time.Second)
	cont := boottime()
	if err := signal(edgeNode1, systemNS, agent, "galactic-edge", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	seen, _, w := g.wait(l, t)
	m.requireCutoff(t, seen, w, last, last-timing.RenewInterval, cont)
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
}

// rowAPIPartition drops the fixture pod's traffic to the API server while
// its clients and its packet device stay reachable: it can no longer renew,
// so both the node's gate and the adapter's own lease deadline end
// forwarding within the local expiry bound, and the client's request ends.
func (m *masque) rowAPIPartition(t *testing.T) {
	l := m.l
	// The pod's client dials the Service address, which the CNI may
	// translate to an endpoint before the packet leaves the pod: drop both.
	clusterIP, err := l.kubectl("get", "service", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := l.kubectl("get", "endpointslices", "-n", "default", "-l",
		"kubernetes.io/service-name=kubernetes", "-o", "jsonpath={.items[*].endpoints[*].addresses[*]}")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(clusterIP + " " + endpoints)
	apiservers := make([]netip.Addr, 0, len(fields))
	for _, f := range fields {
		addr, err := netip.ParseAddr(f)
		if err != nil {
			t.Fatal(err)
		}
		apiservers = append(apiservers, addr)
	}
	pid := strconv.Itoa(podPID(t, edgeNode1, masqueNS, m.pod.Name))
	nft := func(args ...string) error {
		_, err := nodeExec(edgeNode1, append([]string{"nsenter", "-t", pid, "-n", "nft"}, args...)...)
		return err
	}
	dst := m.workload(t, m.a.tn, 2).addr
	g := m.watchGate(t, "api-partition", m.a, 45*time.Second)
	if err := nft("add", "table", "inet", "masque-partition"); err != nil {
		t.Fatal(err)
	}
	healed := false
	heal := func() {
		if !healed {
			healed = true
			_ = nft("delete", "table", "inet", "masque-partition")
		}
	}
	defer heal()
	if err := nft("add", "chain", "inet", "masque-partition", "out", "{", "type", "filter", "hook", "output",
		"priority", "0", ";", "}"); err != nil {
		t.Fatal(err)
	}
	for _, addr := range apiservers {
		family := "ip"
		if addr.Is6() {
			family = "ip6"
		}
		if err := nft("add", "rule", "inet", "masque-partition", "out", family, "daddr", addr.String(),
			"drop"); err != nil {
			t.Fatal(err)
		}
	}
	l.record(t, "API server addresses dropped", apiservers)
	last := m.lastRenewal(t)
	time.Sleep(25 * time.Second)
	cont := boottime()
	heal()
	seen, session, w := g.wait(l, t)
	m.requireCutoff(t, seen, w, last, last, cont)
	rs := echoes(session, dst)
	if len(rs) == 0 {
		t.Fatal("the client's request never forwarded")
	}
	lastReply := rs[len(rs)-1].T
	l.record(t, "client's last reply after the last renewal start", lastReply-last)
	if lastReply-last > localExpiry {
		t.Errorf("the client received replies %v after the last renewal start, bound %v", lastReply-last,
			localExpiry)
	}
	if !slices.ContainsFunc(session, func(e event) bool { return e.End && e.T < cont }) {
		t.Error("the adapter did not end the client's request while partitioned")
	}
	m.waitConnected(t, m.a)
	m.waitConnected(t, m.b)
}

// rowConnectorRevocation ends one connector's grant while another
// connector keeps the shared instance renewing: VPC 20's service is given a
// deadline, and VPC 20's request stops forwarding by that deadline plus one
// second while VPC 10's continues and the instance keeps its lease epoch. It
// runs last: the expired service drains VPC 20's attachment.
func (m *masque) rowConnectorRevocation(t *testing.T) {
	l, ctx := m.l, context.Background()
	dstA, dstB := m.workload(t, m.a.tn, 2).addr, m.workload(t, m.b.tn, 2).addr
	before := m.renewStart(t)
	var lease coordinationv1.Lease
	leaseKey := client.ObjectKey{Namespace: masqueNS, Name: "ei-" + string(m.pod.UID)}
	if err := l.c.Get(ctx, leaseKey, &lease); err != nil {
		t.Fatal(err)
	}
	epoch := lease.Spec.LeaseTransitions
	a := m.connect(t, "revocation-a", m.a.token, m.a.tn.vpc, m.a.id, 30*time.Second, dstA)
	b := m.connect(t, "revocation-b", m.b.token, m.b.tn.vpc, m.b.id, 30*time.Second, dstB)
	time.Sleep(3 * time.Second)
	until := time.Now().Add(10 * time.Second).Truncate(time.Second)
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(m.b.svc), m.b.svc); err != nil {
		t.Fatal(err)
	}
	m.b.svc.Spec.ValidUntil = &metav1.Time{Time: until}
	if err := l.c.Update(ctx, m.b.svc); err != nil {
		t.Fatal(err)
	}
	evsB, evsA := b.wait(l, t), a.wait(l, t)
	m.requireAnswered(t, "VPC 10's connector across VPC 20's revocation", evsA, 30*time.Second, dstA)
	rs := echoes(evsB, dstB)
	if len(rs) == 0 {
		t.Fatal("VPC 20's connector never forwarded")
	}
	expiry := wallToBoot(until)
	last := rs[len(rs)-1].T
	l.record(t, "VPC 20's last reply relative to its service's validUntil", last-expiry)
	if last > expiry+time.Second {
		t.Errorf("VPC 20's connector forwarded %v past its service's validUntil, bound 1 s", last-expiry)
	}
	if last < expiry-maxSkew-stopGap-margin {
		t.Errorf("VPC 20's connector stopped %v before its service's validUntil; the deadline was never reached",
			expiry-last)
	}
	if err := l.c.Get(ctx, leaseKey, &lease); err != nil {
		t.Fatal(err)
	}
	if after := m.renewStart(t); after <= before || !equalPtr(lease.Spec.LeaseTransitions, epoch) {
		t.Errorf("the shared instance did not keep renewing at the same epoch: renew-start %v to %v, epoch %v to %v",
			before, after, deref(epoch), deref(lease.Spec.LeaseTransitions))
	}
	att := l.attachmentOf(t, m.pod, m.a.svc)
	if att == nil || !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) {
		t.Error("revoking VPC 20's connector took VPC 10's attachment out of service")
	}
}

func equalPtr(a, b *int32) bool { return deref(a) == deref(b) }

func deref(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
