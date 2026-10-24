// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/edge/diag/diagtest"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/timing"
)

const prefixA = "fd00:10:0:f::/80"

// TestFirstClaimWaitsForNewIndex: the VPC's index is created rebuilt, so
// the first claim is accepted only after the takeover interval, then
// committed to the index before the route's status.
func TestFirstClaimWaitsForNewIndex(t *testing.T) {
	f := startAPI(t)
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.reconcile("r")
	if got := f.claimReason("r"); got != ReasonIndexRebuilt {
		t.Fatalf("first claim: %s, want %s", got, ReasonIndexRebuilt)
	}
	if att, _ := f.accepted("r"); att != "" {
		t.Fatal("first claim accepted during the rebuilt index's quiet period")
	}
	f.clock.advance(params.TakeoverWait() - time.Millisecond)
	f.reconcile("r")
	if att, _ := f.accepted("r"); att != "" {
		t.Fatal("first claim accepted before the takeover interval")
	}
	f.clock.advance(time.Millisecond)
	f.reconcile("r")
	f.expectAccepted("r", a, 1)
	rt := f.route("r")
	if h := rt.Status.Accepted; h.Node != nodeA || h.InstanceIncarnation != a.incarnation || h.InstanceEpoch != 1 ||
		h.VPCNamespace != tenantNS || h.AttachmentUID != string(a.att.UID) {
		t.Fatalf("accepted holder %+v", h)
	}
	entries := f.indexEntries()
	if len(entries) != 1 || entries[0].Epoch != 1 || entries[0].RouteUID != string(rt.UID) || entries[0].Removing != "" {
		t.Fatalf("index %+v", entries)
	}
}

// TestEarlyTakeover is failure-matrix row 13a: another instance claims a
// held route at once. It is not accepted while the holder renews, however
// long that goes on, and is accepted the takeover interval after the holder
// stops, measured from the leader's first read of the unchanged lease.
func TestEarlyTakeover(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.expectAccepted("r", a, 1)

	f.claim("r", b)
	for range 6 {
		f.reconcile("r")
		f.expectAccepted("r", a, 1)
		if got := f.claimReason("r"); got != ReasonWaiting {
			t.Fatalf("pending takeover: %s, want %s", got, ReasonWaiting)
		}
		// Each renewal lands within the takeover interval of the last.
		f.clock.advance(params.TakeoverWait() - time.Second)
		f.renew(a)
	}
	// The holder stops renewing: the wait starts at the leader's first read
	// of the final renewal.
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait() - time.Millisecond)
	f.reconcile("r")
	f.expectAccepted("r", a, 1)
	f.clock.advance(time.Millisecond)
	f.reconcile("r")
	f.expectAccepted("r", b, 2)
	if e := f.indexEntries(); len(e) != 1 || e[0].AttachmentUID != string(b.att.UID) || e[0].Node != nodeB {
		t.Fatalf("index after takeover %+v", e)
	}
}

// TestStaleLeaderView is failure-matrix row 13b: the leader's decisions
// read the API server, not a cache, so a renewal it has not been told about
// still restarts the takeover wait.
func TestStaleLeaderView(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.claim("r", b)
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait() - time.Second)
	// A renewal arrives with no event for the route: the next decision,
	// at what would be the end of the wait, still sees it.
	f.renew(a)
	f.clock.advance(time.Second)
	f.reconcile("r")
	f.expectAccepted("r", a, 1)

	// A renewal written while the leader's final read is in flight: the
	// wait restarts rather than accepting on the earlier read.
	f.clock.advance(params.TakeoverWait())
	// Check reads the lease once, then the wait's first read, then its
	// final one: the renewal lands between the last two.
	f.routes.APIReader = &renewingReader{Reader: f.admin, f: f, h: a, after: 1}
	f.reconcile("r")
	f.routes.APIReader = f.admin
	f.expectAccepted("r", a, 1)
}

// renewingReader renews h once after it has served after reads of h's
// instance.
type renewingReader struct {
	client.Reader
	f     *fixture
	h     *podHolder
	after int
}

func (r *renewingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object,
	opts ...client.GetOption) error {
	err := r.Reader.Get(ctx, key, obj, opts...)
	if _, ok := obj.(*galacticv1alpha1.EdgeInstance); ok && key.Name == r.h.inst.Name {
		if r.after == 0 {
			r.f.renew(r.h)
		}
		r.after--
	}
	return err
}

// TestReleaseWhileRenewing is failure-matrix row 13c: the holder releases
// one route and keeps renewing its instance. Another attachment's claim is
// accepted only once the holder's node records the gate closed.
func TestReleaseWhileRenewing(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.release("r")
	f.claim("r", b)
	for range 3 {
		f.renew(a)
		f.clock.advance(params.TakeoverWait() / 2)
		f.reconcile("r")
		f.expectAccepted("r", a, 1)
	}
	f.closeEpoch("r")
	f.reconcile("r")
	f.expectAccepted("r", b, 2)
}

// TestSpecSwapWithoutAcceptance is failure-matrix row 13d: a sibling pod
// swaps a held route to itself while the holder renews. The holder stays
// accepted, with nothing in its accepted holder or Accepted condition
// changed, so no node changes its gate.
func TestSpecSwapWithoutAcceptance(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeA, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	before := f.route("r").Status
	f.claim("r", b)
	f.renew(a)
	f.reconcile("r")
	after := f.route("r").Status
	if *before.Accepted != *after.Accepted {
		t.Fatalf("accepted holder changed: %+v to %+v", before.Accepted, after.Accepted)
	}
	bc := meta.FindStatusCondition(before.Conditions, galacticv1alpha1.EdgeRouteAccepted)
	ac := meta.FindStatusCondition(after.Conditions, galacticv1alpha1.EdgeRouteAccepted)
	if ac.Status != bc.Status || ac.Reason != bc.Reason || ac.Message != bc.Message {
		t.Fatalf("Accepted changed: %+v to %+v", bc, ac)
	}
	if got := f.claimReason("r"); got != ReasonWaiting {
		t.Fatalf("swapped claim: %s", got)
	}
}

// TestRemovalFencing is failure-matrix row 13e's control-plane half: a
// deleted route's prefix stays in the index, blocking every overlapping
// claim, until the takeover interval after the leader recorded the
// deletion.
func TestRemovalFencing(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	if err := f.admin.Delete(context.Background(), f.route("r")); err != nil {
		t.Fatal(err)
	}
	f.reconcile("r")
	if e := f.indexEntries(); len(e) != 1 || e[0].Removing != RemovingDeleted {
		t.Fatalf("index after deletion %+v", e)
	}
	// The same prefix recreated, and an overlapping one, wait.
	f.newRoute("r2", prefixA)
	f.claim("r2", b)
	f.newRoute("r3", "fd00:10:0:f::/96")
	f.claim("r3", b)
	f.clock.advance(params.TakeoverWait() - time.Millisecond)
	f.reconcile("r2")
	f.reconcile("r3")
	for _, n := range []string{"r2", "r3"} {
		if got := f.claimReason(n); got != ReasonPrefixConflict {
			t.Fatalf("%s before the deleted route is fenced: %s", n, got)
		}
	}
	f.clock.advance(time.Millisecond)
	f.reconcile("r2")
	f.expectAccepted("r2", b, 1)
	f.reconcile("r3")
	if got := f.claimReason("r3"); got != ReasonPrefixConflict {
		t.Fatalf("overlapping route accepted: %s", got)
	}
}

// TestRevocation: an accepted holder whose grant no longer covers the
// prefix is revoked. Its index entry blocks other claims until its node
// records the gate closed; the holder itself must claim a new epoch.
func TestRevocation(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()

	var svc galacticv1alpha1.EdgeService
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(f.svc), &svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.Prefixes = []string{"fd00:10:0:d::/64"}
	if err := f.admin.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	f.reconcile("r")
	rt := f.route("r")
	c := meta.FindStatusCondition(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonRevoked || rt.Status.Accepted.Epoch != 1 {
		t.Fatalf("revoked route: %s", conditions(rt))
	}
	if e := f.indexEntries(); len(e) != 1 || e[0].Removing != RemovingRevoked {
		t.Fatalf("index after revocation %+v", e)
	}
	if got := f.claimReason("r"); got != ReasonRevoked {
		t.Fatalf("revoked claim: %s", got)
	}
	f.closeEpoch("r")
	f.reconcile("r")
	if e := f.indexEntries(); len(e) != 0 {
		t.Fatalf("index after the gate closed %+v", e)
	}

	// The grant restored, a new epoch is accepted at once: same attachment.
	svc.Spec.Prefixes = []string{grantPrefix}
	if err := f.admin.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	f.claim("r", a)
	f.reconcile("r")
	f.expectAccepted("r", a, 2)
}

// TestGrantCeiling is failure-matrix row 18's control-plane half: a claim
// is refused once the grant's validUntil is within the maximum skew, and an
// accepted holder is revoked then.
func TestGrantCeiling(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	var svc galacticv1alpha1.EdgeService
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(f.svc), &svc); err != nil {
		t.Fatal(err)
	}
	until := metav1.NewTime(f.wall.Add(time.Minute))
	svc.Spec.ValidUntil = &until
	if err := f.admin.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.expectAccepted("r", a, 1)
	f.wall = until.Add(-params.MaxSkew)
	f.reconcile("r")
	rt := f.route("r")
	c := meta.FindStatusCondition(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
	if c.Status != metav1.ConditionFalse {
		t.Fatalf("route past its grant's ceiling: %s", conditions(rt))
	}
	f.claim("r", a)
	f.reconcile("r")
	if got := f.claimReason("r"); got != string(admission.GrantExpired) {
		t.Fatalf("claim past the ceiling: %s", got)
	}
}

// TestOverlapRefused: a route overlapping another accepted route of the VPC
// is refused, whoever claims it.
func TestOverlapRefused(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	for i, p := range []string{grantPrefix, "fd00:10:0:f::/112", prefixA} {
		name := fmt.Sprintf("o%d", i)
		f.newRoute(name, p)
		f.claim(name, b)
		f.reconcile(name)
		if got := f.claimReason(name); got != ReasonPrefixConflict {
			t.Fatalf("%s overlapping %s: %s", p, prefixA, got)
		}
	}
	f.newRoute("ok", "fd00:10:0:f:1::/80")
	f.claim("ok", b)
	f.reconcile("ok")
	f.expectAccepted("ok", b, 1)
}

// TestRestartInPlace is failure-matrix row 15a's control-plane half: a
// restarted provider process reacquires its instance at a new epoch and
// claims its routes again, which are accepted at once: same attachment.
func TestRestartInPlace(t *testing.T) {
	f := startAPI(t)
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.setLease(a, 2, 0, false)
	f.reconcile("r")
	// The old instance epoch's holder is not revoked: its gate expires at
	// the node, and the provider claims again.
	f.expectAccepted("r", a, 1)
	f.claim("r", a)
	f.reconcile("r")
	f.expectAccepted("r", a, 2)
	if h := f.route("r").Status.Accepted; h.InstanceEpoch != 2 {
		t.Fatalf("accepted instance epoch %d", h.InstanceEpoch)
	}
}

// TestRefusals: a claim for another pod's attachment, an attachment that is
// not ready, a lease at another epoch and a prefix outside the grant are
// each refused with their reason.
func TestRefusals(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.clearRebuilt()

	set := func(c *galacticv1alpha1.EdgeRouteClaim) {
		t.Helper()
		rt := f.route("r")
		if rt.Spec.Claim != nil {
			c.Epoch = rt.Spec.Claim.Epoch + 1
		}
		rt.Spec.Claim = c
		if err := f.admin.Update(ctx, rt); err != nil {
			t.Fatal(err)
		}
		f.reconcile("r")
	}
	set(&galacticv1alpha1.EdgeRouteClaim{Attachment: b.att.Name, HolderPodUID: string(a.pod.UID),
		HolderInstance: a.inst.Name, InstanceEpoch: 1, Epoch: 1})
	if got := f.claimReason("r"); got != string(admission.IdentityMismatch) {
		t.Fatalf("claim of another pod's attachment: %s", got)
	}
	set(&galacticv1alpha1.EdgeRouteClaim{Attachment: a.att.Name, HolderPodUID: string(a.pod.UID),
		HolderInstance: a.inst.Name, InstanceEpoch: 7, Epoch: 1})
	if got := f.claimReason("r"); got != ReasonLeaseNotHeld {
		t.Fatalf("claim at another lease epoch: %s", got)
	}
	att := a.att.DeepCopy()
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(att), att); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
		Type: galacticv1alpha1.EdgeAttachmentReady, Status: metav1.ConditionFalse, Reason: "NotReady"})
	if err := f.admin.Status().Update(ctx, att); err != nil {
		t.Fatal(err)
	}
	set(&galacticv1alpha1.EdgeRouteClaim{Attachment: a.att.Name, HolderPodUID: string(a.pod.UID),
		HolderInstance: a.inst.Name, InstanceEpoch: 1, Epoch: 1})
	if got := f.claimReason("r"); got != ReasonAttachmentNotLive {
		t.Fatalf("claim through an attachment that is not ready: %s", got)
	}
	f.newRoute("outside", "fd00:10:0:d::/80")
	rt := f.route("outside")
	rt.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: b.att.Name, HolderPodUID: string(b.pod.UID),
		HolderInstance: b.inst.Name, InstanceEpoch: 1, Epoch: 1}
	if err := f.admin.Update(ctx, rt); err != nil {
		t.Fatal(err)
	}
	f.reconcile("outside")
	if got := f.claimReason("outside"); got != string(admission.PrefixNotGranted) {
		t.Fatalf("claim outside the grant: %s", got)
	}
}

// TestReaping: an instance whose pod is gone is deleted the takeover
// interval after the leader first saw its record unchanged, and a route
// whose attachment and instance are gone is deleted.
func TestReaping(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	if err := f.admin.Delete(ctx, a.pod, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(a.inst)}
	reap := func() {
		t.Helper()
		if _, err := f.reaper.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	reap()
	f.clock.advance(params.TakeoverWait() - time.Millisecond)
	reap()
	if err := f.admin.Get(ctx, req.NamespacedName, &galacticv1alpha1.EdgeInstance{}); err != nil {
		t.Fatalf("instance reaped early: %v", err)
	}
	f.renew(a)
	f.clock.advance(time.Millisecond)
	reap()
	if err := f.admin.Get(ctx, req.NamespacedName, &galacticv1alpha1.EdgeInstance{}); err != nil {
		t.Fatalf("instance renewed during the wait was reaped: %v", err)
	}
	reap()
	f.clock.advance(params.TakeoverWait())
	reap()
	if err := f.admin.Get(ctx, req.NamespacedName, &galacticv1alpha1.EdgeInstance{}); err == nil {
		t.Fatal("instance of a deleted pod not reaped")
	}

	f.reconcile("r")
	if f.route("r") == nil {
		t.Fatal("route reaped while its attachment exists")
	}
	if err := f.admin.Delete(ctx, a.att); err != nil {
		t.Fatal(err)
	}
	f.reconcile("r")
	if f.route("r") != nil {
		t.Fatal("route of a deleted attachment and instance not reaped")
	}
}

// TestControllerAsGalacticController runs the reconcilers in a manager as
// galactic-controller, with only the shipped RBAC, on the real monotonic
// clock with a short lease: a first claim is accepted after the new index's
// quiet period, and a takeover after the holder stops renewing.
func TestControllerAsGalacticController(t *testing.T) {
	f := startAPI(t)
	short := claim.Params{Duration: time.Second, MaxDrift: 0.001, Margin: 100 * time.Millisecond, MaxSkew: 2 * time.Second}
	as := rest.CopyConfig(f.cfg)
	as.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:galactic-system:galactic-controller",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:galactic-system", "system:authenticated"},
	}
	mgr, err := ctrl.NewManager(as, ctrl.Options{
		Scheme: f.scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:      cache.Options{ByObject: LeaseCache()},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Setup(mgr, short, timing.BootClock, bgpNamespace, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})

	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	eventually(t, "first claim accepted", func() bool { att, _ := f.accepted("r"); return att == a.att.Name })
	f.claim("r", b)
	start := time.Now()
	var lastRenewal time.Time
	for time.Since(start) < 3*short.TakeoverWait() {
		// Taken before the write, so it is no later than the renewal
		// the leader's wait starts from.
		lastRenewal = time.Now()
		f.renew(a)
		time.Sleep(short.Duration / 4)
		if att, _ := f.accepted("r"); att != a.att.Name {
			t.Fatalf("takeover accepted while the holder renews: %s", conditions(f.route("r")))
		}
	}
	eventually(t, "takeover accepted", func() bool { att, _ := f.accepted("r"); return att == b.att.Name })
	if waited := time.Since(lastRenewal); waited < short.TakeoverWait() {
		t.Fatalf("takeover accepted %v after the last renewal, before the takeover interval %v", waited, short.TakeoverWait())
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestReleasedRouteLeavesIndex: a route released at its accepted epoch
// stops blocking overlapping routes once its node records the gate closed,
// or the takeover interval after the leader marked it.
func TestReleasedRouteLeavesIndex(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		t.Run(fmt.Sprintf("confirmed=%t", confirmed), func(t *testing.T) {
			f := startAPI(t)
			a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
			f.newRoute("r", prefixA)
			f.claim("r", a)
			f.clearRebuilt()
			f.release("r")
			f.newRoute("wider", grantPrefix)
			f.claim("wider", b)
			f.reconcile("r")
			f.reconcile("wider")
			if e := f.indexEntries(); len(e) != 1 || e[0].Removing != RemovingReleased {
				t.Fatalf("index after release %+v", e)
			}
			if got := f.claimReason("wider"); got != ReasonPrefixConflict {
				t.Fatalf("overlapping route before the release is fenced: %s", got)
			}
			if confirmed {
				f.closeEpoch("r")
			} else {
				f.clock.advance(params.TakeoverWait())
			}
			f.reconcile("r")
			f.reconcile("wider")
			f.expectAccepted("wider", b, 1)
		})
	}
}

// pausingClock is a leader clock that jumps ahead once, on its first read
// after armed calls, as a leader paused between its final lease read and its
// commit would see.
type pausingClock struct {
	base  *manualClock
	armed int
	pause time.Duration
}

func (c *pausingClock) read() time.Duration {
	if c.armed > 0 {
		c.armed--
		if c.armed == 0 {
			c.base.advance(c.pause)
		}
	}
	return c.base.read()
}

// TestLeaderPauseBeforeCommit: a leader that stalls after proving the
// previous holder fenced by waiting, with no lease left to fence, does not
// commit on that proof.
func TestLeaderPauseBeforeCommit(t *testing.T) {
	f := startAPI(t)
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	// envtest runs no garbage collector: the lease goes as it would with
	// its instance.
	if err := f.admin.Delete(context.Background(), &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: providerNS, Name: a.inst.Name}}); err != nil {
		t.Fatal(err)
	}
	f.claim("r", b)
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait())
	// The wait reads the clock after its first read and after its final
	// one; the pause lands on the next read, just before the commit.
	pc := &pausingClock{base: f.clock, armed: 3, pause: 20 * time.Second}
	f.routes.Clock = pc.read
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: providerNS, Name: "r"}}
	if _, err := f.routes.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	f.expectAccepted("r", a, 1)
	f.routes.Clock = f.clock.read
}

// leaseRenewingReader reads through base and, right after the at-th read of the
// Lease at key returns, runs hook: a renewal landing after that read.
type leaseRenewingReader struct {
	client.Reader
	key  client.ObjectKey
	at   int
	n    int
	hook func()
}

func (r *leaseRenewingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object,
	opts ...client.GetOption) error {
	err := r.Reader.Get(ctx, key, obj, opts...)
	if _, ok := obj.(*coordinationv1.Lease); ok && key == r.key {
		if r.n++; r.n == r.at {
			r.hook()
		}
	}
	return err
}

// TestRenewalAfterFinalRead: a renewal the previous holder sent before the
// leader's final read, landing after it, keeps the holder accepted, since the
// fence then fails; once the holder stops, the fence lands and a renewal from
// before it fails, so it can never extend the old gate past the takeover.
func TestRenewalAfterFinalRead(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.claim("r", b)
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait())

	// The wait's first read of a's lease, then its final read; a's renewal
	// lands between the final read and the fence.
	reader := f.routes.APIReader
	f.routes.APIReader = &leaseRenewingReader{Reader: reader,
		key: client.ObjectKey{Namespace: providerNS, Name: a.inst.Name}, at: 2, hook: func() { f.renew(a) }}
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: providerNS, Name: "r"}}
	if _, err := f.routes.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	f.routes.APIReader = reader
	f.expectAccepted("r", a, 1)
	if got := f.claimReason("r"); got != ReasonWaiting {
		t.Fatalf("takeover past a renewal landing after the final read: %s", got)
	}
	if l := f.lease(a); l.Epoch != 1 || l.Holder == "" {
		t.Fatalf("a renewing holder's lease fenced: %+v", l)
	}

	// a stops renewing: the leader waits again from its next read, fences
	// a's lease and accepts b. A renewal a built before the fence fails.
	before := f.lease(a)
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait())
	f.reconcile("r")
	f.expectAccepted("r", b, 2)
	if l := f.lease(a); l.Epoch != 2 || l.Holder != "" {
		t.Fatalf("a's lease after the takeover %+v, want epoch 2 with no holder", l)
	}
	before.Sequence++
	before.RenewStart = f.clock.read()
	store := provider.InstanceStore{Client: f.admin, Namespace: providerNS}
	if _, err := store.Update(ctx, before); !errors.Is(err, claim.ErrConflict) {
		t.Fatalf("a's renewal after the fence: %v, want ErrConflict", err)
	}
	proc := &claim.Instance{ID: leaseHolder, Store: store, Clock: f.clock.read, Params: params}
	held := claim.Lease{Key: a.inst.Name, Holder: leaseHolder, Epoch: 1, Incarnation: before.Incarnation,
		Deadline: f.clock.read() + params.Duration}
	if _, err := proc.Renew(ctx, held); !errors.Is(err, claim.ErrLost) {
		t.Fatalf("a's process renewing after the fence: %v, want ErrLost", err)
	}
}

// TestIndexFull: a route is refused, not retried forever, once its VPC's
// index holds its limit.
func TestIndexFull(t *testing.T) {
	f := startAPI(t)
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	idx := &galacticv1alpha1.EdgeRouteIndex{
		ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: string(f.vpc.UID)},
		Spec:       galacticv1alpha1.EdgeRouteIndexSpec{VPCUID: string(f.vpc.UID)},
	}
	for i := range maxIndexEntries {
		idx.Spec.Routes = append(idx.Spec.Routes, galacticv1alpha1.EdgeRouteIndexEntry{
			Prefix: fmt.Sprintf("fd00:10:0:f:ffff::%x/128", i), Route: fmt.Sprintf("edge/r%d", i),
			RouteUID: fmt.Sprintf("uid-%d", i), Epoch: 1, AttachmentUID: "x", Instance: "edge/x",
			InstanceIncarnation: "x", InstanceEpoch: 1, Node: nodeB,
		})
	}
	f.create(idx)
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.reconcile("r")
	if got := f.claimReason("r"); got != ReasonIndexFull {
		t.Fatalf("claim with the index full: %s", got)
	}
}

// TestAbandonedEntryLeavesIndex: an entry committed for a claim whose status
// write never landed stops blocking overlapping routes once that claim is
// released, the takeover interval after the leader marked it. While the
// claim is still pending, it stays.
func TestAbandonedEntryLeavesIndex(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	// The commit landed; the status write did not.
	rt := f.route("r")
	rt.Status = galacticv1alpha1.EdgeRouteStatus{}
	if err := f.admin.Status().Update(ctx, rt); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: tenantNS, Name: string(f.vpc.UID)}}
	reindex := func() {
		t.Helper()
		if _, err := f.index.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	reindex()
	if e := f.indexEntries(); len(e) != 1 || e[0].Removing != "" {
		t.Fatalf("pending entry %+v", e)
	}
	f.release("r")
	reindex()
	if e := f.indexEntries(); len(e) != 1 || e[0].Removing != RemovingAbandoned {
		t.Fatalf("entry after release %+v", e)
	}
	f.newRoute("wider", grantPrefix)
	f.claim("wider", b)
	f.reconcile("wider")
	if got := f.claimReason("wider"); got != ReasonPrefixConflict {
		t.Fatalf("overlapping claim before the abandoned entry left: %s", got)
	}
	f.clock.advance(params.TakeoverWait())
	reindex()
	f.reconcile("wider")
	f.expectAccepted("wider", b, 1)
}

// An entry committed for a later claim that is no longer pending stays while
// the route's earlier accepted holder may still forward, and is removed only
// once that holder's node confirms its gate closed.
func TestAbandonedEntryWaitsForEarlierHolder(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("s", prefixA)
	f.claim("s", a)
	f.reconcile("s")
	f.clock.advance(params.TakeoverWait())
	f.reconcile("s")
	f.expectAccepted("s", a, 1)

	// b's claim at epoch 2 was committed to the index; its status write did
	// not land, and the claim was released since.
	f.claim("s", b)
	key := client.ObjectKey{Namespace: tenantNS, Name: string(f.vpc.UID)}
	var idx galacticv1alpha1.EdgeRouteIndex
	if err := f.admin.Get(ctx, key, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Spec.Routes) != 1 {
		t.Fatalf("index before commit %+v", idx.Spec.Routes)
	}
	// The commit replaces a's entry, so it alone keeps overlapping claims
	// out while a may still forward.
	e := &idx.Spec.Routes[0]
	e.Epoch, e.AttachmentUID, e.Instance = 2, string(b.att.UID), b.inst.Name
	if err := f.admin.Update(ctx, &idx); err != nil {
		t.Fatal(err)
	}
	f.release("s")

	reindex := func() {
		t.Helper()
		if _, err := f.index.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(epoch int64) *galacticv1alpha1.EdgeRouteIndexEntry {
		for _, e := range f.indexEntries() {
			if e.Epoch == epoch {
				return &e
			}
		}
		return nil
	}
	reindex()
	f.clock.advance(params.TakeoverWait())
	reindex()
	if e := entry(2); e == nil || e.Removing != "" {
		t.Fatalf("entry while the earlier holder may forward %+v", e)
	}
	f.closeEpoch("s")
	reindex()
	if e := entry(2); e == nil || e.Removing != RemovingAbandoned {
		t.Fatalf("entry after the earlier holder closed %+v", e)
	}
	reindex()
	f.clock.advance(params.TakeoverWait())
	reindex()
	if e := f.indexEntries(); len(e) != 0 {
		t.Fatalf("abandoned entry stayed %+v", e)
	}
}

// TestRouteDiagnostics: a claim refused for an overlapping prefix and an
// accepted holder revoked each emit one Warning Event at the Route stage,
// naming the provider, route, prefix and epoch, however often decided; a
// claim waiting to fence the previous holder emits none.
func TestRouteDiagnostics(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.reconcile("r")
	if got := f.claimReason("r"); got != ReasonIndexRebuilt {
		t.Fatalf("first claim: %s", got)
	}
	if got := f.events.Events(); len(got) != 0 {
		t.Fatalf("waiting claim emitted %+v", got)
	}
	f.clearRebuilt()
	f.expectAccepted("r", a, 1)

	f.newRoute("o", "fd00:10:0:f::/112")
	f.claim("o", b)
	f.reconcile("o")
	f.reconcile("o")
	refused := f.events.Find(diag.StageRoute, ReasonPrefixConflict)
	if len(refused) != 1 {
		t.Fatalf("refusal events %+v, want 1", refused)
	}
	corr := refused[0].Correlation()
	o := f.route("o")
	for k, v := range map[string]string{"provider": o.Spec.ProviderRef.Name, "route": o.Namespace + "/o",
		"prefix": "fd00:10:0:f::/112", "epoch": "1"} {
		if corr[k] != v {
			t.Errorf("refusal correlation %s=%q, want %q (%q)", k, corr[k], v, refused[0].Note)
		}
	}

	var svc galacticv1alpha1.EdgeService
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(f.svc), &svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.Prefixes = []string{"fd00:10:0:d::/64"}
	if err := f.admin.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	f.reconcile("r")
	f.reconcile("r")
	var revoked []diagtest.Event
	for _, e := range f.events.Events() {
		if e.Name == "r" && e.Action == string(diag.StageRoute) {
			revoked = append(revoked, e)
		}
	}
	if len(revoked) != 1 || !strings.Contains(revoked[0].Note, "epoch 1 revoked") {
		t.Fatalf("revocation events %+v, want 1", revoked)
	}
	corr = revoked[0].Correlation()
	if corr["attachment"] != a.att.Namespace+"/"+a.att.Name || corr["attachmentUID"] != string(a.att.UID) ||
		corr["node"] != nodeA || corr["epoch"] != "1" {
		t.Errorf("revocation correlation %v", corr)
	}
}
