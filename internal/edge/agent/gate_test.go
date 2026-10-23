// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

const (
	bootID       = "boot-1"
	vpcUID       = "33333333-0000-0000-0000-000000000001"
	providerName = "connect-ip"
	edgeNS       = "edge"
	tenantNS     = "tenant"
	svcName      = "svc"
	vpcName      = "prod"
	contract     = "v1alpha1"
	routeName    = "route"
)

var (
	gateParams = claim.Params{Duration: 15 * time.Second, MaxDrift: 0.001, Margin: 500 * time.Millisecond,
		MaxSkew: 2 * time.Second}
	sitePrefix = netip.MustParsePrefix("fd00:aa:0:f::/80")
)

// grant creates the approved provider and the service granting it the VPC
// and the site prefix, which the attachments the gate tests program use.
func (f *fixture) grant() *galacticv1alpha1.EdgeService {
	f.t.Helper()
	ctx := context.Background()
	p := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: providerName},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			Capabilities: []galacticv1alpha1.EdgeCapability{{Name: route.PrefixReachability, Version: "v1"}},
		},
	}
	if err := f.client.Create(ctx, p); err != nil {
		f.t.Fatal(err)
	}
	p.Status.Approved = true
	if err := f.client.Status().Update(ctx, p); err != nil {
		f.t.Fatal(err)
	}
	svc := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: tenantNS, UID: "svc-uid"},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: providerName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: vpcName, UID: vpcUID},
			Capabilities: []string{"SocketAccess", route.PrefixReachability},
			Prefixes:     []string{"fd00:aa:0:f::/64"},
		},
	}
	if err := f.client.Create(ctx, svc); err != nil {
		f.t.Fatal(err)
	}
	return svc
}

// holder is a provider instance with its lease, and its attachment as core
// and the provider leave it once admitted, allocated and ready.
type holder struct {
	name string
	att  *galacticv1alpha1.EdgeAttachment
	inst *galacticv1alpha1.EdgeInstance
	// incarnation of the lease, as its store reports it; leased reports
	// that the lease exists. The fake client gives objects no UID, so the
	// incarnation is empty.
	incarnation string
	leased      bool
}

// holder creates the gate tests' one provider instance, "a": pod1UID's
// instance and its attachment attA at addr.
func (f *fixture) holder() *holder {
	f.t.Helper()
	ctx := context.Background()
	podUID := pod1UID
	f.pod(podUID)
	h := &holder{name: "a"}
	name := h.name
	h.inst = &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "inst-" + name, Namespace: edgeNS},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
			PodName: name, PodUID: podUID, NodeName: node, BootID: bootID},
	}
	if err := f.client.Create(ctx, h.inst); err != nil {
		f.t.Fatal(err)
	}
	h.att = f.attach(name, attA, podUID, vpcA, addr, false)
	h.att.Spec = galacticv1alpha1.EdgeAttachmentSpec{
		ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
		ServiceRef:  galacticv1alpha1.EdgeServiceReference{Namespace: tenantNS, Name: svcName, UID: "svc-uid"},
		InstanceRef: galacticv1alpha1.EdgeInstanceReference{Name: h.inst.Name},
		PodUID:      podUID, ContractVersion: contract,
		Capabilities: []galacticv1alpha1.EdgeCapability{{Name: "SocketAccess", Version: "v1"}},
	}
	if err := f.client.Update(ctx, h.att); err != nil {
		f.t.Fatal(err)
	}
	for _, c := range []string{galacticv1alpha1.EdgeAttachmentAdmitted, galacticv1alpha1.EdgeAttachmentAllocated,
		galacticv1alpha1.EdgeAttachmentReady} {
		meta.SetStatusCondition(&h.att.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c})
	}
	if err := f.client.Status().Update(ctx, h.att); err != nil {
		f.t.Fatal(err)
	}
	f.lease(h, f.boot)
	return h
}

// leaseEpoch is the epoch the holder's lease is held at.
const leaseEpoch = 1

// lease writes the holder's lease through the provider's store, at
// leaseEpoch, renewed at start on the node's clock.
func (f *fixture) lease(h *holder, start time.Duration) {
	f.t.Helper()
	ctx := context.Background()
	store := provider.InstanceStore{Client: f.client, Namespace: edgeNS}
	if !h.leased {
		r, err := store.Create(ctx, claim.Record{Key: h.inst.Name, Holder: "proc", Epoch: leaseEpoch, RenewStart: start})
		if err != nil {
			f.t.Fatal(err)
		}
		h.incarnation, h.leased = r.Incarnation, true
		return
	}
	r, err := store.Get(ctx, h.inst.Name)
	if err != nil {
		f.t.Fatal(err)
	}
	r.Sequence++
	r.RenewStart = start
	if _, err := store.Update(ctx, r); err != nil {
		f.t.Fatal(err)
	}
}

// accept creates the route for sitePrefix accepted for h at epoch, as core
// leaves it.
func (f *fixture) accept(h *holder, epoch int64) {
	f.t.Helper()
	ctx := context.Background()
	rt := &galacticv1alpha1.EdgeRoute{}
	key := client.ObjectKey{Namespace: edgeNS, Name: routeName}
	if err := f.client.Get(ctx, key, rt); err != nil {
		rt = &galacticv1alpha1.EdgeRoute{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "route-uid"},
			Spec: galacticv1alpha1.EdgeRouteSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
				VPCUID: vpcUID, Prefix: sitePrefix.String(), Incarnation: "inc"},
		}
		if err := f.client.Create(ctx, rt); err != nil {
			f.t.Fatal(err)
		}
	}
	rt.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: h.att.Name, HolderPodUID: h.att.Spec.PodUID,
		HolderInstance: h.inst.Name, InstanceEpoch: leaseEpoch, Epoch: epoch}
	if err := f.client.Update(ctx, rt); err != nil {
		f.t.Fatal(err)
	}
	rt.Status.Accepted = &galacticv1alpha1.EdgeRouteHolder{Epoch: epoch, Attachment: h.att.Name,
		AttachmentUID: string(h.att.UID), Instance: h.inst.Name, InstanceIncarnation: h.incarnation,
		InstanceEpoch: leaseEpoch, Node: node, VPCNamespace: tenantNS}
	meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
		Status: metav1.ConditionTrue, Reason: route.ReasonAccepted})
	if err := f.client.Status().Update(ctx, rt); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) routeObj() *galacticv1alpha1.EdgeRoute {
	f.t.Helper()
	var rt galacticv1alpha1.EdgeRoute
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: edgeNS, Name: routeName}, &rt); err != nil {
		f.t.Fatal(err)
	}
	return &rt
}

func (f *fixture) gate(a *Agent) bool {
	f.t.Helper()
	changed, _, err := a.GateRoute(context.Background(), client.ObjectKey{Namespace: edgeNS, Name: routeName})
	if err != nil {
		f.t.Fatalf("gate: %v", err)
	}
	return changed
}

// gateRow returns h's gate for sitePrefix.
func (f *fixture) gateRow(h *holder) (forwardgatemap.Gate, bool) {
	f.t.Helper()
	return f.gates.row(f.hostLink(h.name).Attrs().Index, sitePrefix)
}

func (f *fixture) expectOpen(h *holder, deadline time.Duration, epoch int64) {
	f.t.Helper()
	g, ok := f.gateRow(h)
	if !ok || g.Deadline != deadline || g.Epoch != uint64(epoch) {
		f.t.Fatalf("gate %+v (%t), want deadline %v at epoch %d", g, ok, deadline, epoch)
	}
}

// TestGateFollowsRenewals opens a gate from the holder's renewal, extends it
// only from newer renewals, routes the prefix to the link only while it is
// open, and keeps a restarted agent from extending it from what it held.
func TestGateFollowsRenewals(t *testing.T) {
	f := newFixture(t)
	f.grant()
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.programmed("a")
	f.boot += time.Second
	f.lease(h, f.boot-time.Second)
	f.accept(h, 1)

	if !f.gate(a) {
		t.Fatal("opening a gate reported no change")
	}
	start := f.boot - time.Second
	f.expectOpen(h, start+gateParams.Duration, 1)
	f.reconcile(a)
	link := f.hostLink("a").Attrs().Index
	if got := f.routeVia(vrfTables[vpcA], sitePrefix.Addr().String()); got != link {
		t.Fatalf("open prefix routed via %d, want the attachment's link %d", got, link)
	}

	// The same renewal, or an older one, extends nothing.
	f.boot += 5 * time.Second
	f.gate(a)
	f.expectOpen(h, start+gateParams.Duration, 1)
	f.lease(h, start-time.Second)
	f.gate(a)
	f.expectOpen(h, start+gateParams.Duration, 1)

	// A newer renewal extends from its own start.
	f.lease(h, f.boot)
	f.gate(a)
	renewed := f.boot
	f.expectOpen(h, renewed+gateParams.Duration, 1)

	// A restarted agent holds nothing from its predecessor: the same
	// renewal extends nothing, a newer one does.
	b := f.agent()
	f.reconcile(b)
	f.boot += time.Second
	f.gate(b)
	f.expectOpen(h, renewed+gateParams.Duration, 1)
	f.lease(h, f.boot)
	f.gate(b)
	f.expectOpen(h, f.boot+gateParams.Duration, 1)
	// The predecessor, fenced, can no longer write a gate.
	f.lease(h, f.boot+time.Second)
	f.boot += 2 * time.Second
	if _, _, err := a.GateRoute(context.Background(), client.ObjectKey{Namespace: edgeNS, Name: routeName}); err == nil {
		t.Fatal("fenced agent wrote a gate")
	}
}

// TestGateExpiry is the node half of failure-matrix rows 10, 11, 14 and 15:
// a holder that stops renewing, or a stalled agent, leaves the gate to close
// at its deadline. The agent then records it closed, removes it once
// recorded, and never reopens that epoch however fresh a later renewal.
func TestGateExpiry(t *testing.T) {
	f := newFixture(t)
	f.grant()
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.lease(h, f.boot)
	f.accept(h, 1)
	f.gate(a)
	deadline := f.boot + gateParams.Duration

	f.boot = deadline
	if !f.gate(a) {
		t.Error("closing an expired gate reported no change, leaving its host routes for the next resync")
	}
	if g, ok := f.gateRow(h); !ok || g.Deadline != 0 || g.Epoch != 1 {
		t.Fatalf("expired gate %+v (%t), want it kept closed", g, ok)
	}
	if got := f.routeObj().Status.ClosedEpoch; got != 1 {
		t.Fatalf("closedEpoch %d after expiry, want 1", got)
	}
	f.lease(h, f.boot)
	f.gate(a)
	if _, ok := f.gateRow(h); ok {
		t.Fatal("gate recorded closed was not removed")
	}
	f.gate(a)
	if _, ok := f.gateRow(h); ok {
		t.Fatal("epoch recorded closed reopened by a fresh renewal")
	}
	f.reconcile(a)
	if got := f.routeVia(vrfTables[vpcA], sitePrefix.Addr().String()); got != 0 {
		t.Fatalf("closed prefix still routed via %d", got)
	}

	// The provider claims again at a new epoch, which core accepts at once
	// for the same attachment: the gate opens from a fresh renewal.
	f.accept(h, 2)
	f.gate(a)
	f.expectOpen(h, f.boot+gateParams.Duration, 2)
}

// TestGateClosesOnRevocation closes the gate, and records it closed, when
// core revokes the route, the holder releases it, the instance's boot is
// not this one, or the attachment stops being ready.
func TestGateClosesOnRevocation(t *testing.T) {
	ctx := context.Background()
	for name, revoke := range map[string]func(*fixture, *holder){
		"revoked": func(f *fixture, _ *holder) {
			rt := f.routeObj()
			meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
				Status: metav1.ConditionFalse, Reason: route.ReasonRevoked})
			if err := f.client.Status().Update(ctx, rt); err != nil {
				f.t.Fatal(err)
			}
		},
		"released": func(f *fixture, _ *holder) {
			rt := f.routeObj()
			rt.Spec.Claim.Released = true
			if err := f.client.Update(ctx, rt); err != nil {
				f.t.Fatal(err)
			}
		},
		"other boot": func(f *fixture, h *holder) {
			if err := f.client.Get(ctx, client.ObjectKeyFromObject(h.inst), h.inst); err != nil {
				f.t.Fatal(err)
			}
			h.inst.Spec.BootID = "boot-0"
			if err := f.client.Update(ctx, h.inst); err != nil {
				f.t.Fatal(err)
			}
		},
		"not ready": func(f *fixture, h *holder) {
			att := f.get(h.name)
			meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentReady, Status: metav1.ConditionFalse, Reason: "Stopped"})
			if err := f.client.Status().Update(ctx, att); err != nil {
				f.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.grant()
			a := f.agent()
			h := f.holder()
			f.reconcile(a)
			f.lease(h, f.boot)
			f.accept(h, 1)
			f.gate(a)
			if _, ok := f.gateRow(h); !ok {
				t.Fatal("gate not opened")
			}
			revoke(f, h)
			f.boot += time.Second
			f.lease(h, f.boot)
			if !f.gate(a) {
				t.Error("closing a gate reported no change")
			}
			if g, ok := f.gateRow(h); !ok || g.Deadline != 0 {
				t.Fatalf("gate %+v (%t) after %s, want closed", g, ok, name)
			}
			if got := f.routeObj().Status.ClosedEpoch; got != 1 {
				t.Fatalf("closedEpoch %d, want 1", got)
			}
		})
	}
}

// TestGateCeiling is failure-matrix row 18's node half: no renewal extends a
// gate past the grant's validUntil less the maximum skew.
func TestGateCeiling(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	svc := f.grant()
	until := metav1.NewTime(f.wall.Add(10 * time.Second))
	svc.Spec.ValidUntil = &until
	if err := f.client.Update(ctx, svc); err != nil {
		t.Fatal(err)
	}
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.lease(h, f.boot)
	f.accept(h, 1)
	f.gate(a)
	ceiling := f.boot + 10*time.Second - gateParams.MaxSkew
	f.expectOpen(h, ceiling, 1)
	f.boot += 4 * time.Second
	f.wall = f.wall.Add(4 * time.Second)
	f.lease(h, f.boot)
	f.gate(a)
	f.expectOpen(h, ceiling, 1)
	f.boot += 4 * time.Second
	f.wall = f.wall.Add(4 * time.Second)
	f.lease(h, f.boot)
	f.gate(a)
	if g, _ := f.gateRow(h); g.Deadline != 0 {
		t.Fatalf("gate %+v at the ceiling, want closed", g)
	}
}

// TestGateIgnoresUntrustedRenewals: a renewal start from the future is not
// on this node's clock, and an API server the agent cannot read extends
// nothing, so the gate closes at its deadline.
func TestGateIgnoresUntrustedRenewals(t *testing.T) {
	f := newFixture(t)
	f.grant()
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.lease(h, f.boot)
	f.accept(h, 1)
	f.gate(a)
	deadline := f.boot + gateParams.Duration
	f.lease(h, f.boot+time.Minute)
	f.gate(a)
	f.expectOpen(h, deadline, 1)

	f.boot += time.Second
	f.lease(h, f.boot)
	a.APIReader = failingReader{}
	f.gate(a)
	f.expectOpen(h, deadline, 1)
}

type failingReader struct{ client.Reader }

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("API server unreachable")
}

// TestSweepRemovesOrphanedGates: an expired gate no accepted route names is
// swept; a live one is left to expire.
func TestSweepRemovesOrphanedGates(t *testing.T) {
	f := newFixture(t)
	f.grant()
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.lease(h, f.boot)
	f.accept(h, 1)
	f.gate(a)
	if err := f.client.Delete(context.Background(), f.routeObj()); err != nil {
		t.Fatal(err)
	}
	if err := a.SweepGates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.gateRow(h); !ok {
		t.Fatal("live gate swept")
	}
	f.boot += gateParams.Duration
	if err := a.SweepGates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.gateRow(h); ok {
		t.Fatal("expired orphaned gate not swept")
	}
}

// TestPrefixMovesBetweenAttachments: when a prefix's gate closes on one
// attachment and opens on another of the same VPC, one pass moves its host
// route, whichever attachment the pass programs first.
func TestPrefixMovesBetweenAttachments(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.pod(pod2UID)
	// "b" is listed, and programmed, before "x".
	f.attach("x", attA, pod1UID, vpcA, addr, true)
	f.attach("b", attB, pod2UID, vpcA, "fd00:aa::2", true)
	f.reconcile(a)
	x, b := f.hostLink("x").Attrs().Index, f.hostLink("b").Attrs().Index
	open := forwardgatemap.Gate{Deadline: f.boot + time.Minute, Epoch: 1}
	if err := f.gates.Set(uint32(x), sitePrefix, open); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	if got := f.routeVia(vrfTables[vpcA], sitePrefix.Addr().String()); got != x {
		t.Fatalf("prefix routed via %d, want x's link %d", got, x)
	}
	if err := f.gates.Set(uint32(x), sitePrefix, forwardgatemap.Gate{Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	open.Epoch = 2
	if err := f.gates.Set(uint32(b), sitePrefix, open); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	if got := f.routeVia(vrfTables[vpcA], sitePrefix.Addr().String()); got != b {
		t.Fatalf("prefix routed via %d after it moved, want b's link %d", got, b)
	}
	f.programmed("b")
	f.programmed("x")
}

// TestReleaseKeepsLinkGated: releasing an attachment closes its gates first
// and removes its link row only once the link is gone; the sweep removes the
// row of a link deleted behind the agent's back.
func TestReleaseKeepsLinkGated(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.pod(pod2UID)
	f.attach("x", attA, pod1UID, vpcA, addr, true)
	f.attach("y", attB, pod2UID, vpcA, "fd00:aa::2", true)
	f.reconcile(a)
	x, y := uint32(f.hostLink("x").Attrs().Index), uint32(f.hostLink("y").Attrs().Index)
	if err := f.gates.Set(x, sitePrefix, forwardgatemap.Gate{Deadline: f.boot + time.Minute, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(ctx, f.get("x")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	if _, ok, _ := f.gates.Link(x); ok {
		t.Fatal("released link's row left behind")
	}
	if rows, _ := f.gates.Gates(x); len(rows) != 0 {
		t.Fatalf("released link's gates left behind: %v", rows)
	}

	// y's link disappears without a release, as when its pod's namespace
	// is destroyed.
	in(t, f.host, func() error {
		l, err := netlink.LinkByIndex(int(y))
		if err != nil {
			return err
		}
		return netlink.LinkDel(l)
	})
	if err := a.SweepGates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.gates.Link(y); ok {
		t.Fatal("the row of a vanished link was not swept")
	}
}

// staleGates is a gate table whose view of links misses some: Link reports
// a hidden link unregistered, as a stale or failed listing would, while its
// rows stay in the map.
type staleGates struct {
	*gates
	hidden map[uint32]bool
}

func (g staleGates) Link(ifindex uint32) (netip.Addr, bool, error) {
	if g.hidden[ifindex] {
		return netip.Addr{}, false, nil
	}
	return g.gates.Link(ifindex)
}

// TestClosedIsRecordedOnlyUnderTheFence: an agent records a route's epoch
// closed only when, inside a commit of the VPC's scope, no gate carries the
// prefix open at that epoch. A predecessor that a newer agent fenced cannot
// record one, even when its own view holds no gate, and an agent that missed
// the holder's link while listing does not either.
func TestClosedIsRecordedOnlyUnderTheFence(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.grant()
	old := f.agent()
	h := f.holder()
	f.reconcile(old)
	f.lease(h, f.boot)
	f.accept(h, 1)
	current := f.agent()
	f.reconcile(current)
	f.gate(current)
	link := uint32(f.hostLink(h.name).Attrs().Index)
	if g, ok := f.gateRow(h); !ok || g.Deadline == 0 {
		t.Fatalf("gate not open: %+v %t", g, ok)
	}
	rt := f.routeObj()
	meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
		Status: metav1.ConditionFalse, Reason: route.ReasonRevoked})
	if err := f.client.Status().Update(ctx, rt); err != nil {
		t.Fatal(err)
	}

	// The fenced predecessor reads a stale map with no gate at all.
	old.Gates = staleGates{gates: newGates(), hidden: map[uint32]bool{}}
	_, _, _ = old.GateRoute(ctx, client.ObjectKey{Namespace: edgeNS, Name: routeName})
	if got := f.routeObj().Status.ClosedEpoch; got != 0 {
		t.Fatalf("a fenced agent recorded epoch %d closed while its successor's gate is open", got)
	}

	// The current agent misses the holder's link while listing: it
	// closes nothing it cannot see, and records nothing.
	current.Gates = staleGates{gates: f.gates, hidden: map[uint32]bool{link: true}}
	f.gate(current)
	if got := f.routeObj().Status.ClosedEpoch; got != 0 {
		t.Fatalf("epoch %d recorded closed with its gate still open on a missed link", got)
	}

	// With the full view it closes the gate, then records it.
	current.Gates = f.gates
	f.gate(current)
	if got := f.routeObj().Status.ClosedEpoch; got != 1 {
		t.Fatalf("closedEpoch %d after the gate closed, want 1", got)
	}
}

// TestGateSharesTheVPCFence: gates commit in the same write-fence scope GC
// and the attachment pass use, and a write by GC, which does not own the
// scope, between two gate commits neither loses the scope nor stops the
// gate from being extended.
func TestGateSharesTheVPCFence(t *testing.T) {
	f := newFixture(t)
	f.grant()
	a := f.agent()
	h := f.holder()
	f.reconcile(a)
	f.lease(h, f.boot)
	f.accept(h, 1)
	scope := ownership.VPCScope(vpcA)
	before, err := a.Ownership.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	f.gate(a)
	after, err := a.Ownership.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision <= before.Revision {
		t.Fatalf("opening a gate left scope %s at revision %d", scope, after.Revision)
	}

	// GC writes the scope under its lock without owning it.
	if err := a.Ownership.Exclusive(scope, func() error { return nil }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.boot += time.Second
	f.lease(h, f.boot)
	f.gate(a)
	f.expectOpen(h, f.boot+gateParams.Duration, 1)
	if err := a.Healthy(nil); err != nil {
		t.Fatalf("a GC write made the agent give up its scope: %v", err)
	}
}
