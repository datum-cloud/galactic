// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/trafficpolicy"
)

const (
	testNode = "node-a"
	testNS   = "tenant"
	testAtt  = "att-1"
	testVPC  = "vpc-1"

	webPolicy = "web"
)

func TestKeepTransitionTimes(t *testing.T) {
	old := metav1.NewTime(metav1.Now().Add(-3600e9))
	id := &galacticv1alpha1.PolicyIdentity{Name: "p", UID: "u", Generation: 2}
	existing := galacticv1alpha1.NodeBindingStatus{Node: testNode,
		Ingress: &galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, Policy: id,
			LastTransitionTime: &old},
		Egress: &galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, Policy: id,
			LastTransitionTime: &old},
	}
	newer := *id
	newer.Generation = 3
	in := galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, Policy: id}
	eg := galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, Policy: &newer}
	keepTransitionTimes(&[2]*galacticv1alpha1.AppliedPolicy{&in, &eg}, existing)
	if in.LastTransitionTime == nil || !in.LastTransitionTime.Equal(&old) {
		t.Errorf("unchanged ingress: lastTransitionTime = %v, want the old one", in.LastTransitionTime)
	}
	if eg.LastTransitionTime != nil {
		t.Errorf("egress moved to a new generation but kept lastTransitionTime %v", eg.LastTransitionTime)
	}
}

func TestPolicyUIDBytes(t *testing.T) {
	u := "4b6f0e1c-2a3d-4e5f-8a9b-0c1d2e3f4a5b"
	if got := PolicyUIDBytes(u); uuid.UUID(got).String() != u {
		t.Errorf("a Kubernetes UID round-trips to %s", uuid.UUID(got))
	}
	if PolicyUIDBytes("builtin:default-deny-all:v1") == PolicyUIDBytes("builtin:default-deny-all:v2") {
		t.Error("two versions of the built-in identity record the same bytes")
	}
}

func TestFieldOwner(t *testing.T) {
	if got := fieldOwner("node-a"); got != "galactic-router/node-a" {
		t.Errorf("fieldOwner = %q", got)
	}
	long := strings.Repeat("n", 253)
	a, b := fieldOwner(long), fieldOwner(long[:252]+"m")
	if len(a) > 128 || a == b {
		t.Errorf("long names: %q (%d bytes) and %q", a, len(a), b)
	}
}

// TestRuleRows checks a snapshot is matched to a policy only when it holds
// exactly what the policy compiles to, and that a rule compiling to no
// entries is reported as having no row.
func TestRuleRows(t *testing.T) {
	// The middle rule is one the API refuses, kept here because the
	// compiler gives it no entries: ICMPv6 under IPv4.
	v4, icmp6, tcp := trafficpolicy.FamilyIPv4, trafficpolicy.ProtoICMPv6, trafficpolicy.ProtoTCP
	model := trafficpolicy.Policy{Rules: []trafficpolicy.Rule{
		{Name: "dns", Allow: true, Match: trafficpolicy.Match{DestPorts: []trafficpolicy.PortRange{{Start: 53, End: 53}}}},
		{Name: "never", Allow: true, Match: trafficpolicy.Match{Family: &v4, Proto: &icmp6}},
		{Name: "http", Allow: true, Match: trafficpolicy.Match{Proto: &tcp}},
	}}
	entries, err := trafficpolicy.Compile(model)
	if err != nil {
		t.Fatal(err)
	}
	snap := tpmap.Snapshot{CounterBase: 100}
	for _, e := range entries {
		rowed := e
		rowed.Rule = []uint16{7, 0, 3}[e.Rule]
		snap.Raw = append(snap.Raw, tpmap.EncodeEntry(rowed))
	}
	rows, ok := RuleRows(entries, snap, len(model.Rules))
	if !ok || rows[0] != 107 || rows[1] != NoRow || rows[2] != 103 {
		t.Fatalf("RuleRows = %v, %v; want [107 NoRow 103]", rows, ok)
	}
	snap.Raw[0].DportLo++
	if _, ok := RuleRows(entries, snap, len(model.Rules)); ok {
		t.Error("a snapshot with a different entry matched")
	}
}

// TestSweepKeepsReconciledInterfaces: a snapshot bound before a restart on
// an interface this node has reconciled is never swept, even unclaimed, so a
// direction whose reconcile keeps failing keeps what it had.
func TestSweepKeepsReconciledInterfaces(t *testing.T) {
	key := bindingKey{7, tpmap.DirEgress}
	r := &Reconciler{
		adopted:  map[bindingKey]tpmap.Snapshot{key: {}},
		ifaces:   map[types.NamespacedName]iface{{Namespace: testNS, Name: testAtt}: {ifindex: 7}},
		openedAt: time.Now().Add(-2 * resync),
	}
	r.sweepAdopted(context.Background()) // would need maps to unbind anything
	if _, ok := r.adopted[key]; !ok {
		t.Error("swept a snapshot on a reconciled interface")
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to load BPF maps and create an interface; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// fixture is a real API server, the uSID datapath's maps, and a dummy
// interface standing in for a tenant interface.
type fixture struct {
	c       client.Client
	patches atomic.Int32 // status patches through c
	maps    *tpmap.Maps
	link    string
	ifindex uint32
	token   uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	requireRoot(t)
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	var objs prog.UsidObjects
	if err := prog.LoadUsidObjects(&objs, nil); err != nil {
		t.Fatalf("load usid objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	te := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "config", "crd"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	direct, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	f := &fixture{maps: tpmap.FromObjects(&objs), link: "tpt" + hex.EncodeToString(suffix)}
	f.c = interceptor.NewClient(direct, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch,
			opts ...client.SubResourcePatchOption,
		) error {
			f.patches.Add(1)
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	})
	c := f.c
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: f.link}}); err != nil {
		t.Fatalf("create %s: %v", f.link, err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(f.link); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	l, err := netlink.LinkByName(f.link)
	if err != nil {
		t.Fatal(err)
	}
	f.ifindex = uint32(l.Attrs().Index) //nolint:gosec // a kernel ifindex
	if f.token, err = tpmap.NewPolicyToken(); err != nil {
		t.Fatal(err)
	}
	if err := f.maps.PutInterface(f.ifindex, f.token, tpmap.KindTenant); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}}); err != nil {
		t.Fatal(err)
	}
	att := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: testAtt, Namespace: testNS}}
	att.Spec.VPC.Name = testVPC
	att.Spec.Interface.Name = "eth0"
	if err := c.Create(ctx, att); err != nil {
		t.Fatal(err)
	}
	att.Status.Node = testNode
	att.Status.HostInterface = f.link
	if err := c.Status().Update(ctx, att); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) reconciler() *Reconciler {
	return &Reconciler{Client: f.c, NodeName: testNode, PinDir: "unused",
		openMaps: func(string) (*tpmap.Maps, error) { return f.maps, nil }}
}

func (f *fixture) reconcile(t *testing.T, r *Reconciler) {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: testAtt}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func (f *fixture) snapshot(t *testing.T, dir uint32) (tpmap.Snapshot, bool) {
	t.Helper()
	snap, ok, err := f.maps.ReadSnapshot(f.ifindex, dir)
	if err != nil {
		t.Fatal(err)
	}
	return snap, ok
}

func (f *fixture) applyPolicy(t *testing.T, name, rules string) *galacticv1alpha1.TrafficPolicy {
	t.Helper()
	var spec galacticv1alpha1.TrafficPolicySpec
	if err := json.Unmarshal([]byte(`{"rules":`+rules+`}`), &spec); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p := &galacticv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS}}
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(p), p); err == nil {
		p.Spec = spec
		if err := f.c.Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p.Spec = spec
	if err := f.c.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) binding(t *testing.T) *galacticv1alpha1.TrafficPolicyBinding {
	t.Helper()
	var b galacticv1alpha1.TrafficPolicyBinding
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: testAtt}, &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func nodeStatus(t *testing.T, b *galacticv1alpha1.TrafficPolicyBinding) galacticv1alpha1.NodeBindingStatus {
	t.Helper()
	for _, n := range b.Status.Nodes {
		if n.Node == testNode {
			return n
		}
	}
	t.Fatalf("binding has no status entry for %s: %+v", testNode, b.Status.Nodes)
	return galacticv1alpha1.NodeBindingStatus{}
}

const (
	httpRule = `{"name":"http","action":"Allow",` +
		`"match":{"protocol":"TCP","destinationPorts":[{"start":80,"end":80}]}}`
	dnsRule = `{"name":"dns","action":"Allow",` +
		`"match":{"protocol":"UDP","destinationPorts":[{"start":53,"end":53}]}}`
)

// TestReconciler runs the node reconciler through a binding's lifecycle
// against a real API server and the real datapath maps. Each step builds on
// the state the previous one left, so they run in order without subtests.
func TestReconciler(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler()
	stepDefault(t, f, r)
	httpRow := stepBindPolicy(t, f, r)
	stepMetrics(t, r)
	stepOtherNode(t, f, r)
	p := stepInsertRule(t, f, r, httpRow)
	r = stepRestart(t, f, httpRow)
	stepRenameRule(t, f, r, httpRow)
	r = stepRebindFailure(t, f)
	stepMissingPolicy(t, f, r, p)
	stepNodeMove(t, f, r)
	stepAttachmentDeleted(t, f, r)
}

// stepDefault: with no binding, both directions get the built-in default.
func stepDefault(t *testing.T, f *fixture, r *Reconciler) {
	t.Helper()
	f.reconcile(t, r)
	for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
		snap, ok := f.snapshot(t, dir)
		if !ok || snap.Token != f.token || len(snap.Entries) == 0 {
			t.Fatalf("direction %d: default snapshot = %+v, bound %v", dir, snap, ok)
		}
	}
}

// stepBindPolicy: a binding naming a policy for egress publishes it and
// reports it, and a resync with nothing changed leaves the status alone. It
// returns the http rule's counter row.
func stepBindPolicy(t *testing.T, f *fixture, r *Reconciler) uint32 {
	t.Helper()
	p := f.applyPolicy(t, webPolicy, "["+httpRule+"]")
	b := &galacticv1alpha1.TrafficPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: testAtt, Namespace: testNS}}
	b.Spec.EgressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: webPolicy}
	if err := f.c.Create(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, r)
	snap, ok := f.snapshot(t, tpmap.DirEgress)
	if !ok || snap.Generation != p.Generation || uuid.UUID(snap.PolicyUID).String() != string(p.UID) {
		t.Fatalf("egress snapshot = %+v, want generation %d uid %s", snap, p.Generation, p.UID)
	}
	st := nodeStatus(t, f.binding(t))
	if st.Egress == nil || st.Egress.State != galacticv1alpha1.StateApplied || st.Egress.Policy == nil ||
		st.Egress.Policy.UID != string(p.UID) {
		t.Fatalf("egress status = %+v", st.Egress)
	}
	if st.Ingress == nil || st.Ingress.Policy == nil || st.Ingress.Policy.Name != galacticv1alpha1.DefaultPolicyName {
		t.Fatalf("ingress status = %+v, want the built-in default", st.Ingress)
	}

	before := f.patches.Load()
	f.reconcile(t, r)
	if n := f.patches.Load() - before; n != 0 {
		t.Errorf("a no-op resync patched the binding's status %d times", n)
	}
	return r.state[f.egressKey()].rows[0]
}

// stepMetrics: the collector exports the installed rule and the interface's
// fallback rows with the interface's labels.
func stepMetrics(t *testing.T, r *Reconciler) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(r)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if !hasSeries(families, "galactic_cni_traffic_policy_rule_hits_total", map[string]string{
		"namespace": testNS, labelAttachment: testAtt, "vpc": testVPC, labelDirection: "egress", "policy": webPolicy,
		"rule": "http", labelAction: "allow",
	}) {
		t.Errorf("no rule hit series for web/http")
	}
	if !hasSeries(families, "galactic_cni_traffic_policy_fallback_packets_total", map[string]string{
		labelAttachment: testAtt, labelDirection: "ingress", labelReason: "policy_unavailable",
	}) {
		t.Errorf("no fallback series for the interface")
	}
}

// stepInsertRule: a new rule ahead of http keeps http's counter row.
func stepInsertRule(t *testing.T, f *fixture, r *Reconciler, httpRow uint32) *galacticv1alpha1.TrafficPolicy {
	t.Helper()
	p := f.applyPolicy(t, webPolicy, "["+dnsRule+","+httpRule+"]")
	f.reconcile(t, r)
	a := r.state[f.egressKey()]
	if len(a.rows) != 2 || a.rows[1] != httpRow || a.rows[0] == httpRow {
		t.Fatalf("rows after inserting dns = %v, want http to keep row %d", a.rows, httpRow)
	}
	if snap, _ := f.snapshot(t, tpmap.DirEgress); snap.Generation != p.Generation {
		t.Fatalf("egress generation = %d, want %d", snap.Generation, p.Generation)
	}
	return p
}

// stepOtherNode: an attachment on another node, whose binding carries no
// entry for this node, costs no API write.
func stepOtherNode(t *testing.T, f *fixture, r *Reconciler) {
	t.Helper()
	ctx := context.Background()
	other := types.NamespacedName{Namespace: testNS, Name: "att-2"}
	att := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: other.Name, Namespace: testNS}}
	att.Spec.VPC.Name = testVPC
	att.Spec.Interface.Name = "eth0"
	if err := f.c.Create(ctx, att); err != nil {
		t.Fatal(err)
	}
	att.Status.Node = "node-b"
	att.Status.HostInterface = "elsewhere"
	if err := f.c.Status().Update(ctx, att); err != nil {
		t.Fatal(err)
	}
	b := &galacticv1alpha1.TrafficPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: other.Name, Namespace: testNS}}
	if err := f.c.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	before := b.ResourceVersion
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: other}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, other, b); err != nil {
		t.Fatal(err)
	}
	if b.ResourceVersion != before {
		t.Errorf("reconciling another node's attachment wrote its binding: %+v", b.Status)
	}
}

// foreignIfindex is an interface no attachment names, with a snapshot left
// bound from before a restart.
const foreignIfindex = 0x7ffffff0

// stepRestart: a restarted reconciler adopts the bound snapshot and its
// rows, with their counts, and unbinds a snapshot no attachment claims
// within a resync.
func stepRestart(t *testing.T, f *fixture, httpRow uint32) *Reconciler {
	t.Helper()
	f.setCounter(t, httpRow, 5, 500)
	entries, err := trafficpolicy.Compile(trafficpolicy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.maps.Publish(foreignIfindex, tpmap.DirEgress, 1, 200, entries); err != nil {
		t.Fatal(err)
	}

	r := f.reconciler()
	f.reconcile(t, r)
	if got := r.state[f.egressKey()]; got == nil || len(got.rows) != 2 || got.rows[1] != httpRow {
		t.Fatalf("after restart, egress state = %+v, want http on row %d", got, httpRow)
	}
	if packets, bytes, err := f.maps.RuleCounter(httpRow); err != nil || packets != 5 || bytes != 500 {
		t.Errorf("http's counts after restart = %d, %d, %v; want 5, 500", packets, bytes, err)
	}
	foreign := bindingKey{foreignIfindex, tpmap.DirEgress}
	if _, ok := r.adopted[foreign]; !ok || len(r.adopted) != 1 {
		t.Fatalf("adopted = %v, want only the unclaimed snapshot", r.adopted)
	}

	r.openedAt = r.openedAt.Add(-2 * resync)
	f.reconcile(t, r)
	if _, ok, _ := f.maps.ReadSnapshot(foreignIfindex, tpmap.DirEgress); ok {
		t.Error("the unclaimed snapshot is still bound after a resync")
	}
	if _, ok := f.snapshot(t, tpmap.DirEgress); !ok {
		t.Error("the sweep unbound a claimed snapshot")
	}
	if err := r.alloc.Reserve(200, 1); err != nil {
		t.Errorf("the unclaimed snapshot's row was not freed: %v", err)
	}
	r.alloc.Free(200)
	return r
}

// stepRenameRule: renaming a rule starts a new series on a fresh, zeroed
// row, and its old row is freed.
func stepRenameRule(t *testing.T, f *fixture, r *Reconciler, httpRow uint32) {
	t.Helper()
	f.applyPolicy(t, webPolicy, "["+dnsRule+","+strings.Replace(httpRule, `"http"`, `"`+webPolicy+`"`, 1)+"]")
	f.reconcile(t, r)
	a := r.state[f.egressKey()]
	if a.rules[1].name != webPolicy || a.rows[1] == httpRow {
		t.Fatalf("after renaming http, rules %v on rows %v; want a new row", a.rules, a.rows)
	}
	if packets, _, _ := f.maps.RuleCounter(a.rows[1]); packets != 0 {
		t.Errorf("the renamed rule starts at %d packets, want 0", packets)
	}
	if err := r.alloc.Reserve(httpRow, 1); err != nil {
		t.Errorf("http's old row %d was not freed: %v", httpRow, err)
	}
	r.alloc.Free(httpRow)
}

// stepRebindFailure: a rebind to a policy that cannot be installed, here
// for want of counter rows, unbinds the direction rather than leaving the
// old policy's grants. The binding then returns to the old policy.
func stepRebindFailure(t *testing.T, f *fixture) *Reconciler {
	t.Helper()
	ctx := context.Background()
	rules := make([]string, 0, 40)
	for i := range 40 {
		rules = append(rules, fmt.Sprintf(`{"name":"r%d","action":"Allow"}`, i))
	}
	f.applyPolicy(t, "big", "["+strings.Join(rules, ",")+"]")
	r := f.reconciler()
	r.counterRows = 32
	f.reconcile(t, r)

	f.setEgressRef(t, "big")
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: testAtt}}
	if _, err := r.Reconcile(ctx, req); err == nil {
		t.Fatal("a rebind that cannot allocate its rows reconciled cleanly")
	}
	if _, ok := f.snapshot(t, tpmap.DirEgress); ok {
		t.Fatal("egress kept the old policy's snapshot after a failed rebind")
	}
	if st := nodeStatus(t, f.binding(t)).Egress; st.State != galacticv1alpha1.StateFailed || st.Policy != nil {
		t.Fatalf("egress status = %+v, want Failed with nothing installed", st)
	}

	f.setEgressRef(t, webPolicy)
	f.reconcile(t, r)
	if _, ok := f.snapshot(t, tpmap.DirEgress); !ok {
		t.Fatal("egress is unbound after returning to web")
	}
	return r
}

func (f *fixture) setEgressRef(t *testing.T, name string) {
	t.Helper()
	b := f.binding(t)
	b.Spec.EgressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: name}
	if err := f.c.Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

// setCounter writes a rule counter row's totals onto CPU 0.
func (f *fixture) setCounter(t *testing.T, row uint32, packets, bytes uint64) {
	t.Helper()
	per := make([]prog.UsidTpCounter, ebpf.MustPossibleCPU())
	per[0] = prog.UsidTpCounter{Packets: packets, Bytes: bytes}
	if err := f.maps.RuleCounters.Put(row, per); err != nil {
		t.Fatal(err)
	}
}

// stepMissingPolicy: a reference to a missing policy unbinds the direction,
// which then denies as policy_unavailable, and reports why.
func stepMissingPolicy(t *testing.T, f *fixture, r *Reconciler, p *galacticv1alpha1.TrafficPolicy) {
	t.Helper()
	if err := f.c.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, r)
	if _, ok := f.snapshot(t, tpmap.DirEgress); ok {
		t.Fatal("egress is still bound after its policy was deleted")
	}
	if st := nodeStatus(t, f.binding(t)); st.Egress.State != galacticv1alpha1.StatePending {
		t.Fatalf("egress status = %+v, want Pending", st.Egress)
	}
}

// stepNodeMove: an attachment that moves to another node is unbound here and
// this node's status entry is removed.
func stepNodeMove(t *testing.T, f *fixture, r *Reconciler) {
	t.Helper()
	ctx := context.Background()
	var att cloudv1alpha1.VPCAttachment
	if err := f.c.Get(ctx, types.NamespacedName{Namespace: testNS, Name: testAtt}, &att); err != nil {
		t.Fatal(err)
	}
	att.Status.Node = "node-b"
	if err := f.c.Status().Update(ctx, &att); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, r)
	for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
		if _, ok := f.snapshot(t, dir); ok {
			t.Errorf("direction %d is still bound after the attachment moved", dir)
		}
	}
	for _, n := range f.binding(t).Status.Nodes {
		if n.Node == testNode {
			t.Errorf("this node's status entry outlived the move: %+v", n)
		}
	}
	if len(r.state) != 0 {
		t.Errorf("state left after the move: %v", r.state)
	}
}

// stepAttachmentDeleted: a deleted attachment is forgotten.
func stepAttachmentDeleted(t *testing.T, f *fixture, r *Reconciler) {
	t.Helper()
	if err := f.c.Delete(context.Background(), &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: testAtt, Namespace: testNS},
	}); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, r)
	if _, ok := r.ifaces[types.NamespacedName{Namespace: testNS, Name: testAtt}]; ok {
		t.Error("the deleted attachment is still tracked")
	}
}

func (f *fixture) egressKey() bindingKey { return bindingKey{f.ifindex, tpmap.DirEgress} }

func hasSeries(families []*dto.MetricFamily, name string, want map[string]string) bool {
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
	metrics:
		for _, m := range mf.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			for k, v := range want {
				if got[k] != v {
					continue metrics
				}
			}
			return true
		}
	}
	return false
}
