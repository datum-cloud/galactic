// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/trafficpolicy/node"
)

const (
	policyNode     = "node-x"
	policyProvider = "connect"
	providerNS     = "provider"
	tenantA        = "tenant-a"
	tenantB        = "tenant-b"
	tenantService  = "svc"
)

// policyFixture is node X's datapath enforcing traffic policy, with each
// attachment link registered by galactic-edge's registration and its
// snapshots published by galactic-router's EdgeAttachment reconciler, from
// the EdgeServices and TrafficPolicies of two tenants whose VPCs reuse every
// address.
type policyFixture struct {
	*datapathFixture
	c    client.Client
	r    *node.Reconciler
	maps *tpmap.Maps
	// links maps each attachment's name to its host link's ifindex.
	links map[string]uint32
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	f := &policyFixture{datapathFixture: newDatapathFixture(t), links: map[string]uint32{}}
	maps, err := tpmap.OpenPinned(f.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maps.Close)
	f.maps = maps
	// What galactic-cni does on a node with policy enforced, and what it and
	// galactic-router leave on X's ordinary workloads: a row each, bound to a
	// policy that admits everything, so only the attachments' policies decide.
	enforce := tpmap.State{Mode: tpmap.ModeEnforce, Mark: config.DefaultPolicyMark, Capable: true}
	if err := maps.SetState(enforce); err != nil {
		t.Fatal(err)
	}
	all, err := trafficpolicy.Compile(trafficpolicy.Policy{Rules: []trafficpolicy.Rule{{Name: "all", Allow: true}}})
	if err != nil {
		t.Fatal(err)
	}
	row := uint32(0)
	for ifindex, key := range f.hostKeys {
		if !strings.HasSuffix(key, "/"+dpWorkloadAtt) {
			continue
		}
		token, err := tpmap.NewPolicyToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := maps.PutInterface(ifindex, token, tpmap.KindTenant); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
			if err := maps.Publish(ifindex, dir, token, row, all); err != nil {
				t.Fatal(err)
			}
			row++
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	var objs []client.Object
	for _, s := range []struct{ ns, vpc string }{{tenantA, vpcA}, {tenantB, vpcB}} {
		objs = append(objs, &galacticv1alpha1.EdgeService{
			ObjectMeta: metav1.ObjectMeta{Name: tenantService, Namespace: s.ns, UID: types.UID("svc-" + s.ns)},
			Spec: galacticv1alpha1.EdgeServiceSpec{
				ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: policyProvider},
				VPCRef:      galacticv1alpha1.EdgeVPCReference{Name: s.vpc, UID: "vpc-" + s.ns},
			},
		})
	}
	for _, a := range []struct{ name, key, tenant string }{
		{"pod1-a", pod1A, tenantA}, {"pod1-b", pod1B, tenantB}, {"pod3-a", pod3A, tenantA},
	} {
		att := f.atts[a.key]
		f.links[a.name] = uint32(f.results[a.key].HostIndex) //nolint:gosec // a kernel ifindex
		// galactic-edge registers the link before it comes up; the
		// fixture's links are up already, which this test does not rely on.
		f.x.do(t, func() error {
			table, err := vrf.TableID(map[string]string{vrfA: vpcA, vrfB: vpcB}[att.HostVRF])
			if err != nil {
				return err
			}
			return attachreg.RegisterHostLink(f.pinDir, table, f.links[a.name], att.HostLink, att.Address)
		})
		objs = append(objs, &galacticv1alpha1.EdgeAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: a.name, Namespace: providerNS, UID: types.UID("uid-" + a.name)},
			Spec: galacticv1alpha1.EdgeAttachmentSpec{
				ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: policyProvider},
				ServiceRef: galacticv1alpha1.EdgeServiceReference{
					Namespace: a.tenant, Name: tenantService, UID: "svc-" + a.tenant,
				},
			},
			Status: galacticv1alpha1.EdgeAttachmentStatus{
				NodeName: policyNode, HostLink: att.HostLink, Address: att.Address.String(),
				Conditions: []metav1.Condition{{
					Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionTrue, Reason: "Admitted",
				}},
			},
		})
	}
	f.c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	f.r = &node.Reconciler{Client: f.c, NodeName: policyNode, PinDir: f.pinDir}
	return f
}

// reconcile runs galactic-router's EdgeAttachment reconcile for each named
// attachment in node X's namespace, as galactic-router runs there.
func (f *policyFixture) reconcile(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		f.x.do(t, func() error {
			_, err := f.r.ReconcileEdge(context.Background(),
				ctrl.Request{NamespacedName: types.NamespacedName{Namespace: providerNS, Name: name}})
			return err
		})
	}
}

// setPolicy creates or replaces TrafficPolicy name in ns with rules, a JSON
// array.
func (f *policyFixture) setPolicy(t *testing.T, ns, name, rules string) {
	t.Helper()
	ctx := context.Background()
	p := &galacticv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	exists := f.c.Get(ctx, client.ObjectKeyFromObject(p), p) == nil
	p.Spec = galacticv1alpha1.TrafficPolicySpec{}
	if err := json.Unmarshal([]byte(`{"rules":`+rules+`}`), &p.Spec); err != nil {
		t.Fatal(err)
	}
	var err error
	if exists {
		p.Generation++
		err = f.c.Update(ctx, p)
	} else {
		p.UID, p.Generation = types.UID(fmt.Sprintf("%s-%s-uid", ns, name)), 1
		err = f.c.Create(ctx, p)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// bind sets the policies tenant's EdgeService selects.
func (f *policyFixture) bind(t *testing.T, tenant, ingress, egress string) {
	t.Helper()
	ctx := context.Background()
	var svc galacticv1alpha1.EdgeService
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: tenant, Name: tenantService}, &svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.TrafficPolicy = &galacticv1alpha1.TrafficPolicyBindingSpec{}
	if ingress != "" {
		svc.Spec.TrafficPolicy.IngressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: ingress}
	}
	if egress != "" {
		svc.Spec.TrafficPolicy.EgressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: egress}
	}
	if err := f.c.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
}

// unavailable is the link's count of packets denied on their way to the
// attachment for want of a bound policy.
func (f *policyFixture) unavailable(t *testing.T, link uint32) uint64 {
	t.Helper()
	var row prog.UsidTpIfaceValue
	if err := f.maps.Interfaces.Lookup(link, &row); err != nil {
		t.Fatalf("policy row of ifindex %d: %v", link, err)
	}
	pkts, _, err := f.maps.FallbackCounter(link, row.PolicyToken, tpmap.DirIngress, tpmap.ReasonPolicyUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return pkts
}

var (
	remoteCIDR = remoteWorkloadAddr.String() + "/128"
	inboundTCP = fmt.Sprintf(`[{"name":"tcp","action":"Allow","match":{"protocol":"TCP",`+
		`"sourceCIDRs":[%q],"destinationCIDRs":["fd00:aa::1/128"],"destinationPorts":[{"start":%d,"end":%d}]}}]`,
		remoteCIDR, podPort, podPort)
	outboundTCP = fmt.Sprintf(`[{"name":"tcp","action":"Allow","match":{"protocol":"TCP",`+
		`"sourceCIDRs":["fd00:aa::1/128"],"destinationCIDRs":[%q],"sourcePorts":[{"start":%d,"end":%d}]}}]`,
		remoteCIDR, podPort, podPort)
	echoRequest = `[{"name":"echo","action":"Allow","match":{"protocol":"ICMPv6","icmp":{"type":128}}}]`
	echoReply   = `[{"name":"echo","action":"Allow","match":{"protocol":"ICMPv6","icmp":{"type":129}}}]`
	allowAll    = `[{"name":"all","action":"Allow"}]`
)

// TestHostAttachmentTrafficPolicy enforces gVPC traffic policy on host-owned
// attachment links on a real kernel, through what production runs: the
// registration galactic-edge performs writes each link's policy row and
// attaches its programs, and galactic-router's EdgeAttachment reconciler binds
// the policies each attachment's EdgeService selects, in both directions, as
// they change under live traffic. VPC A and VPC B reuse every address, so
// every check is also one of tenant isolation.
func TestHostAttachmentTrafficPolicy(t *testing.T) {
	requireRoot(t)
	f := newPolicyFixture(t)
	socket := f.links["pod1-a"]
	dst := netip.MustParseAddrPort("[fd00:aa::1]:8000")
	attAddr := dst.Addr()

	t.Run("RegisteredLinkDeniesUntilBound", func(t *testing.T) {
		before := f.unavailable(t, socket)
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial to an attachment with no policy bound succeeded")
		}
		if got := f.unavailable(t, socket); got <= before {
			t.Fatalf("policy_unavailable ingress count %d -> %d, want it to grow", before, got)
		}
	})

	t.Run("ServiceWithoutPolicyDeniesEverything", func(t *testing.T) {
		f.reconcile(t, "pod1-a", "pod1-b", "pod3-a")
		for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
			if _, ok, err := f.maps.ReadSnapshot(socket, dir); err != nil || !ok {
				t.Fatalf("direction %d: no snapshot bound (%v)", dir, err)
			}
		}
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded under the built-in default")
		}
		if err := ping(f.wlYA, siteHost, 128); !errors.Is(err, errNoReply) {
			t.Fatalf("ping to the packet attachment's site under the built-in default = %v, want no reply", err)
		}
	})

	t.Run("ServicePolicyAdmitsBothDirections", func(t *testing.T) {
		f.setPolicy(t, tenantA, "inbound", inboundTCP)
		f.setPolicy(t, tenantA, "outbound", outboundTCP)
		f.bind(t, tenantA, "inbound", "outbound")
		f.reconcile(t, "pod1-a")
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
		// Each direction is needed: the reply alone is denied.
		f.bind(t, tenantA, "inbound", "")
		f.reconcile(t, "pod1-a")
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded with the attachment's replies denied")
		}
		f.bind(t, tenantA, "", "outbound")
		f.reconcile(t, "pod1-a")
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded with requests to the attachment denied")
		}
		f.bind(t, tenantA, "inbound", "outbound")
		f.reconcile(t, "pod1-a")
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	})

	t.Run("OverlappingTenantStaysIsolated", func(t *testing.T) {
		// VPC B's attachment has the same address as A's and is reached
		// from a client with the same address as A's, but its service
		// selects nothing.
		if _, err := dialIdentity(f.wlYB, "", dst); err == nil {
			t.Fatal("tenant B's attachment admitted traffic under tenant A's policy")
		}
		// Tenant B naming tenant A's policies, and the provider holding
		// policies of those names that admit everything, grant nothing:
		// a service's references resolve only in its own namespace.
		f.setPolicy(t, providerNS, "inbound", allowAll)
		f.setPolicy(t, providerNS, "outbound", allowAll)
		f.bind(t, tenantB, "inbound", "outbound")
		f.reconcile(t, "pod1-b")
		for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
			if _, ok, err := f.maps.ReadSnapshot(f.links["pod1-b"], dir); err != nil || ok {
				t.Fatalf("tenant B direction %d bound to a policy outside its namespace (%v)", dir, err)
			}
		}
		if _, err := dialIdentity(f.wlYB, "", dst); err == nil {
			t.Fatal("tenant B's attachment admitted traffic through another namespace's policy")
		}
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	})

	t.Run("UpdateUnderLiveTraffic", func(t *testing.T) {
		f.setPolicy(t, tenantA, "inbound", echoRequest)
		f.setPolicy(t, tenantA, "outbound", echoReply)
		f.reconcile(t, "pod1-a")
		p := startPinger(f.wlYA, attAddr)
		defer p.stop()
		p.waitAnswered(t, time.Now(), "echo allowed both ways")

		f.setPolicy(t, tenantA, "inbound", inboundTCP)
		f.reconcile(t, "pod1-a")
		denied := time.Now()
		time.Sleep(time.Second)
		if n := p.answeredAfter(denied); n != 0 {
			t.Fatalf("%d echoes sent after the deny was published were answered", n)
		}
		if n := p.sentAfter(denied); n < 5 {
			t.Fatalf("only %d echoes sent after the deny, want a live stream", n)
		}

		f.setPolicy(t, tenantA, "inbound", echoRequest)
		f.reconcile(t, "pod1-a")
		p.waitAnswered(t, time.Now(), "echo allowed again")
	})

	t.Run("MissingPolicyDeniesAllButLinkOperations", func(t *testing.T) {
		f.setPolicy(t, tenantA, "inbound", inboundTCP)
		f.setPolicy(t, tenantA, "outbound", outboundTCP)
		f.reconcile(t, "pod1-a")
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
		if err := f.c.Delete(context.Background(), &galacticv1alpha1.TrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "inbound", Namespace: tenantA},
		}); err != nil {
			t.Fatal(err)
		}
		f.reconcile(t, "pod1-a")
		if _, ok, err := f.maps.ReadSnapshot(socket, tpmap.DirIngress); err != nil || ok {
			t.Fatalf("ingress still bound after its policy was deleted (%v)", err)
		}
		before := f.unavailable(t, socket)
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded with the ingress policy missing")
		}
		if got := f.unavailable(t, socket); got <= before {
			t.Fatalf("policy_unavailable ingress count %d -> %d, want it to grow", before, got)
		}

		// Neighbor discovery is a link operation, outside the rules: with
		// the node's entry for the attachment gone, a same-node workload's
		// packet makes the node resolve it again, its solicitation passing
		// the link's ingress check and the pod's advertisement, sent from
		// the attachment's own address, its egress check.
		link := f.atts[pod1A].HostLink
		f.x.do(t, func() error {
			l, err := netlink.LinkByName(link)
			if err != nil {
				return err
			}
			return netlink.NeighDel(&netlink.Neigh{LinkIndex: l.Attrs().Index, Family: unix.AF_INET6,
				IP: attAddr.AsSlice()})
		})
		if err := ping(f.wlXA, attAddr, 128); !errors.Is(err, errNoReply) {
			t.Fatalf("ping with the ingress policy missing = %v, want no reply", err)
		}
		resolved := false
		for range 20 {
			state, ok := neighborsOn(t, f.x, link)[attAddr]
			if ok && state&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_DELAY|netlink.NUD_PROBE) != 0 {
				resolved = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !resolved {
			t.Fatalf("the node did not resolve %s on %s: %v", attAddr, link, neighborsOn(t, f.x, link))
		}
	})
}

// pinger sends one echo request every 50 ms from n to dst and records when
// each was sent and whether it was answered.
type pinger struct {
	mu    sync.Mutex
	sent  []time.Time
	ok    []bool
	done  chan struct{}
	ended chan struct{}
}

func startPinger(n testNS, dst netip.Addr) *pinger {
	p := &pinger{done: make(chan struct{}), ended: make(chan struct{})}
	go func() {
		defer close(p.ended)
		for {
			select {
			case <-p.done:
				return
			default:
			}
			at := time.Now()
			err := probe(n, dst, 50*time.Millisecond)
			p.mu.Lock()
			p.sent, p.ok = append(p.sent, at), append(p.ok, err == nil)
			p.mu.Unlock()
		}
	}()
	return p
}

func (p *pinger) stop() {
	close(p.done)
	<-p.ended
}

func (p *pinger) answeredAfter(t0 time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for i, at := range p.sent {
		if at.After(t0) && p.ok[i] {
			n++
		}
	}
	return n
}

func (p *pinger) sentAfter(t0 time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, at := range p.sent {
		if at.After(t0) {
			n++
		}
	}
	return n
}

func (p *pinger) waitAnswered(t *testing.T, t0 time.Time, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.answeredAfter(t0) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s: no echo sent after %s was answered", what, t0.Format(time.RFC3339Nano))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
