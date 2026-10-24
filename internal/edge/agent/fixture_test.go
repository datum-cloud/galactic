// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/edge/diag/diagtest"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	node = "edge-1"
	vpcA = "00000000a"
	vpcB = "00000000b"
	mtu  = 1500
)

// vrfTables are the canonical host VRFs' tables in the test host.
var vrfTables = map[string]uint32{vpcA: 1001, vpcB: 1002}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN); re-run via sudo")
	}
}

var nsSeq struct {
	sync.Mutex
	n int
}

// newNS creates a named network namespace with lo up and returns its path.
func newNS(t *testing.T) string {
	t.Helper()
	nsSeq.Lock()
	nsSeq.n++
	name := fmt.Sprintf("gedge-%d-%d", os.Getpid(), nsSeq.n)
	nsSeq.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	h, err := netns.NewNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		err = netlink.LinkSetUp(lo)
	}
	if setErr := netns.Set(orig); setErr != nil {
		t.Fatal(setErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netns.DeleteNamed(name) })
	return filepath.Join("/run/netns", name)
}

// in runs fn with the calling thread in the namespace at path.
func in(t *testing.T, path string, fn func() error) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	target, err := netns.GetFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	if err := netns.Set(target); err != nil {
		t.Fatal(err)
	}
	fnErr := fn()
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	if fnErr != nil {
		t.Fatal(fnErr)
	}
}

// resolver maps pod UIDs to namespace paths; a missing UID is unavailable.
type resolver struct {
	sync.Mutex
	paths map[string]string
	// down makes every lookup fail as an unreachable runtime does.
	down bool
}

func (r *resolver) PodNetNS(_ context.Context, podUID string) (string, error) {
	r.Lock()
	defer r.Unlock()
	if r.down {
		return "", errors.New("runtime unreachable")
	}
	if p, ok := r.paths[podUID]; ok {
		return p, nil
	}
	return "", fmt.Errorf("%w: pod %s", ErrNamespaceUnavailable, podUID)
}

func (r *resolver) set(podUID, path string) {
	r.Lock()
	defer r.Unlock()
	if path == "" {
		delete(r.paths, podUID)
		return
	}
	r.paths[podUID] = path
}

// datapath records registrations by ifindex, and marks each registered link
// gated in gates as the pinned datapath does.
type datapath struct {
	sync.Mutex
	rows         map[uint32]uint32
	unregistered []uint32
	// failUnregister fails the next Unregister calls.
	failUnregister int
	// failRegister fails every Register call while set.
	failRegister error
	// onRegister, when set, is called with each link Register is called for.
	onRegister func(ifindex uint32)
	gates      *gates
}

func (d *datapath) Register(vrfTable, ifindex uint32, _ string, addr netip.Addr) error {
	d.Lock()
	defer d.Unlock()
	if d.onRegister != nil {
		d.onRegister(ifindex)
	}
	if d.failRegister != nil {
		return d.failRegister
	}
	d.rows[ifindex] = vrfTable
	d.gates.setLink(ifindex, addr)
	return nil
}

func (d *datapath) Unregister(ifindex uint32) error {
	d.Lock()
	defer d.Unlock()
	if d.failUnregister > 0 {
		d.failUnregister--
		return errors.New("map busy")
	}
	delete(d.rows, ifindex)
	d.unregistered = append(d.unregistered, ifindex)
	d.gates.deleteGates(ifindex)
	return nil
}

func (d *datapath) Forget(ifindex uint32) error {
	d.gates.deleteLink(ifindex)
	return nil
}

// gates is an in-memory forwarding gate.
type gates struct {
	sync.Mutex
	links map[uint32]netip.Addr
	rows  map[uint32]map[netip.Prefix]forwardgatemap.Gate
	// fail fails every call while set.
	fail error
}

func newGates() *gates {
	return &gates{links: map[uint32]netip.Addr{}, rows: map[uint32]map[netip.Prefix]forwardgatemap.Gate{}}
}

func (g *gates) setLink(ifindex uint32, addr netip.Addr) {
	g.Lock()
	defer g.Unlock()
	g.links[ifindex] = addr
}

func (g *gates) deleteGates(ifindex uint32) {
	g.Lock()
	defer g.Unlock()
	delete(g.rows, ifindex)
}

func (g *gates) Links() (map[uint32]netip.Addr, error) {
	g.Lock()
	defer g.Unlock()
	out := map[uint32]netip.Addr{}
	for k, v := range g.links {
		out[k] = v
	}
	return out, g.fail
}

func (g *gates) DeleteLink(ifindex uint32) error {
	g.deleteLink(ifindex)
	return nil
}

func (g *gates) deleteLink(ifindex uint32) {
	g.Lock()
	defer g.Unlock()
	delete(g.links, ifindex)
	delete(g.rows, ifindex)
}

func (g *gates) Link(ifindex uint32) (netip.Addr, bool, error) {
	g.Lock()
	defer g.Unlock()
	a, ok := g.links[ifindex]
	return a, ok, g.fail
}

func (g *gates) Gates(ifindex uint32) (map[netip.Prefix]forwardgatemap.Gate, error) {
	g.Lock()
	defer g.Unlock()
	out := map[netip.Prefix]forwardgatemap.Gate{}
	for p, r := range g.rows[ifindex] {
		out[p] = r
	}
	return out, g.fail
}

func (g *gates) Set(ifindex uint32, prefix netip.Prefix, r forwardgatemap.Gate) error {
	g.Lock()
	defer g.Unlock()
	if g.fail != nil {
		return g.fail
	}
	if g.rows[ifindex] == nil {
		g.rows[ifindex] = map[netip.Prefix]forwardgatemap.Gate{}
	}
	g.rows[ifindex][prefix] = r
	return nil
}

func (g *gates) Delete(ifindex uint32, prefix netip.Prefix) error {
	g.Lock()
	defer g.Unlock()
	if g.fail != nil {
		return g.fail
	}
	delete(g.rows[ifindex], prefix)
	return nil
}

// row returns the gate of prefix on ifindex.
func (g *gates) row(ifindex int, prefix netip.Prefix) (forwardgatemap.Gate, bool) {
	g.Lock()
	defer g.Unlock()
	r, ok := g.rows[uint32(ifindex)][prefix]
	return r, ok
}

func (d *datapath) table(ifindex int) (uint32, bool) {
	d.Lock()
	defer d.Unlock()
	t, ok := d.rows[uint32(ifindex)]
	return t, ok
}

type fixture struct {
	t        *testing.T
	host     string
	hostNS   *hostattach.Namespace
	client   client.Client
	pods     *resolver
	dp       *datapath
	gates    *gates
	stateDir string
	seq      int
	// boot is the node's CLOCK_BOOTTIME, advanced by hand.
	boot time.Duration
	wall time.Time
	// diag is every agent's diagnostics, recording into events and
	// metrics.
	diag    *diag.Recorder
	events  *diagtest.Recorder
	metrics *prometheus.Registry
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	requireRoot(t)
	f := &fixture{
		t: t, host: newNS(t), pods: &resolver{paths: map[string]string{}},
		gates: newGates(), stateDir: t.TempDir(),
		boot: time.Hour, wall: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC),
	}
	f.dp = &datapath{rows: map[uint32]uint32{}, gates: f.gates}
	f.diag, f.events, f.metrics = diagtest.New("node")
	in(t, f.host, func() error {
		for vpc, table := range vrfTables {
			vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)}, Table: table}
			if err := netlink.LinkAdd(vrf); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(vrf); err != nil {
				return err
			}
		}
		return os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644)
	})
	var err error
	if f.hostNS, err = hostattach.OpenNamespace(f.host); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.hostNS.Close() })
	scheme := kruntime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	f.client = fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&galacticv1alpha1.EdgeAttachment{}, &galacticv1alpha1.EdgeRoute{},
			&galacticv1alpha1.EdgeInstance{}, &galacticv1alpha1.EdgeProvider{}).Build()
	return f
}

// agent returns a new agent process for the node, with a new owner ID.
func (f *fixture) agent() *Agent {
	f.t.Helper()
	f.seq++
	auth, err := ownership.New(f.stateDir)
	if err != nil {
		f.t.Fatal(err)
	}
	return &Agent{
		Client: f.client, NodeName: node, Owner: NewOwner(node, time.Unix(int64(f.seq), 0), "test"),
		Ownership: auth, Host: f.hostNS, Namespaces: f.pods, Datapath: f.dp, MTU: mtu,
		APIReader: f.client, Gates: f.gates, Params: gateParams, BootID: bootID,
		BootClock: func() time.Duration { return f.boot }, Now: func() time.Time { return f.wall },
		Diag: f.diag,
	}
}

// counter returns the value of the node's counter name with labels.
func (f *fixture) counter(name string, labels map[string]string) float64 {
	f.t.Helper()
	families, err := f.metrics.Gather()
	if err != nil {
		f.t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			match := true
			for _, l := range m.GetLabel() {
				if v, ok := labels[l.GetName()]; ok && v != l.GetValue() {
					match = false
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// pod creates a provider pod namespace and makes it resolvable.
func (f *fixture) pod(uid string) string {
	path := newNS(f.t)
	f.pods.set(uid, path)
	return path
}

// attach creates an attachment as core leaves it once admitted and
// allocated on node.
func (f *fixture) attach(name, uid, podUID, vpc, addr string, packet bool) *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	a := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: edgeNS, UID: types.UID(uid),
			Finalizers: []string{galacticv1alpha1.EdgeAttachmentFinalizer},
		},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{PodUID: podUID},
	}
	if packet {
		a.Spec.PacketDevice = &galacticv1alpha1.EdgePacketDevice{Owner: 65534, Group: 65534}
	}
	ctx := context.Background()
	if err := f.client.Create(ctx, a); err != nil {
		f.t.Fatal(err)
	}
	a.Status = galacticv1alpha1.EdgeAttachmentStatus{NodeName: node, VPC: vpc, Address: addr}
	if err := f.client.Status().Update(ctx, a); err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *fixture) get(name string) *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	var a galacticv1alpha1.EdgeAttachment
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: edgeNS, Name: name}, &a); err != nil {
		f.t.Fatal(err)
	}
	return &a
}

func (f *fixture) condition(name, typ string) *metav1.Condition {
	return meta.FindStatusCondition(f.get(name).Status.Conditions, typ)
}

func (f *fixture) reconcile(a *Agent) {
	f.t.Helper()
	if err := a.Reconcile(context.Background()); err != nil {
		f.t.Fatalf("reconcile: %v", err)
	}
}

// hostLink returns the attachment's host link in the test host.
func (f *fixture) hostLink(name string) netlink.Link {
	f.t.Helper()
	var link netlink.Link
	in(f.t, f.host, func() error {
		var err error
		link, err = netlink.LinkByName(f.get(name).Status.HostLink)
		return err
	})
	return link
}

// links lists the attachment links in the test host.
func (f *fixture) links() []hostattach.ObservedAttachment {
	f.t.Helper()
	l, err := hostattach.List(f.hostNS)
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

func (f *fixture) programmed(name string) {
	f.t.Helper()
	c := f.condition(name, galacticv1alpha1.EdgeAttachmentProgrammed)
	if c == nil || c.Status != metav1.ConditionTrue {
		f.t.Fatalf("%s not programmed: %+v", name, c)
	}
}
