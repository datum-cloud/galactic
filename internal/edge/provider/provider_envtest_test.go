// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package provider

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

const ns = "edge"

var params = claim.Params{Duration: 15 * time.Second, MaxDrift: 0.001, Margin: 500 * time.Millisecond}

func startAPI(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd")},
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
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	return c
}

// clock is a monotonic clock tests advance by hand.
type clock struct {
	mu  sync.Mutex
	now time.Duration
}

func (c *clock) read() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += d
}

func newInstance(t *testing.T, c client.Client, podUID string) *galacticv1alpha1.EdgeInstance {
	t.Helper()
	inst := NewInstance(ns, "connect-ip", "pod-"+podUID, podUID, "edge-1", "boot")
	if err := c.Create(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	return inst
}

// lease is the instance's lease as ReadLease reads it; it fails the test
// when the instance has no lease bound to it.
func lease(t *testing.T, c client.Client, name string) claim.Record {
	t.Helper()
	var inst galacticv1alpha1.EdgeInstance
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &inst); err != nil {
		t.Fatal(err)
	}
	r, ok, err := ReadLease(context.Background(), c, &inst)
	if err != nil || !ok {
		t.Fatalf("lease of %s: bound %v, %v", name, ok, err)
	}
	return r
}

// TestInstanceLease runs internal/edge/claim over an instance's Lease:
// quarantine before the first holder, acquisition, renewal recording its
// start, release, a takeover by a restarted process, and refusal of a write
// from a stale read.
func TestInstanceLease(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	store := InstanceStore{Client: c, Namespace: ns}
	clk := &clock{now: time.Hour}
	inst := newInstance(t, c, "u1")
	holder := &claim.Instance{ID: "p1", Store: store, Clock: clk.read, Params: params}

	if _, err := store.Create(ctx, claim.Record{Key: "missing", Incarnation: "x"}); !errors.Is(err, claim.ErrNotFound) {
		t.Fatalf("lease of a missing instance: %v", err)
	}
	if _, err := holder.Acquire(ctx, inst.Name); !errors.Is(err, claim.ErrHeld) {
		t.Fatalf("first acquisition: %v, want the quarantine's ErrHeld", err)
	}
	var ql coordinationv1.Lease
	if err := c.Get(ctx, client.ObjectKeyFromObject(inst), &ql); err != nil {
		t.Fatal(err)
	}
	if !metav1.IsControlledBy(&ql, inst) || ql.Spec.HolderIdentity != nil ||
		ql.Labels[galacticv1alpha1.EdgeLeaseProviderLabel] != "connect-ip" {
		t.Fatalf("quarantine Lease %+v", ql)
	}
	if q := lease(t, c, inst.Name); q.Holder != "" || q.Incarnation != string(ql.UID) {
		t.Fatalf("quarantine record %+v", q)
	}
	clk.advance(params.TakeoverWait())
	l, err := holder.Acquire(ctx, inst.Name)
	if err != nil {
		t.Fatalf("acquisition after the quarantine: %v", err)
	}
	if got := lease(t, c, inst.Name); got.Holder != "p1" || got.Epoch != 1 || got.RenewStart != clk.read() {
		t.Fatalf("acquired lease %+v", got)
	}

	clk.advance(5 * time.Second)
	if l, err = holder.Renew(ctx, l); err != nil {
		t.Fatalf("renew: %v", err)
	}
	got := lease(t, c, inst.Name)
	if got.Sequence != 1 || got.RenewStart != clk.read() || got.Epoch != 1 {
		t.Fatalf("renewed lease %+v", got)
	}

	// A write built from an earlier read loses.
	stale, err := store.Get(ctx, inst.Name)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second)
	if l, err = holder.Renew(ctx, l); err != nil {
		t.Fatal(err)
	}
	stale.Sequence = 99
	if _, err := store.Update(ctx, stale); !errors.Is(err, claim.ErrConflict) {
		t.Fatalf("stale update: %v, want ErrConflict", err)
	}

	// A restarted process takes over only after the takeover wait.
	restarted := &claim.Instance{ID: "p2", Store: store, Clock: clk.read, Params: params}
	if _, err := restarted.Acquire(ctx, inst.Name); !errors.Is(err, claim.ErrHeld) {
		t.Fatalf("takeover of a renewed lease: %v", err)
	}
	clk.advance(params.TakeoverWait())
	if _, err := holder.Renew(ctx, l); !errors.Is(err, claim.ErrLost) {
		t.Fatalf("renewal of an expired lease: %v, want ErrLost", err)
	}
	l2, err := restarted.Acquire(ctx, inst.Name)
	if err != nil || l2.Epoch != 2 {
		t.Fatalf("takeover: %+v %v", l2, err)
	}
	if err := restarted.Release(ctx, l2); err != nil {
		t.Fatal(err)
	}
	if got := lease(t, c, inst.Name); !got.Released || got.Epoch != 2 {
		t.Fatalf("released lease %+v", got)
	}

}

// TestRecreatedLease: a Lease left by a deleted instance is not the
// recreated instance's, and a write from the old Lease's version is refused,
// not applied to the new Lease.
func TestRecreatedLease(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	store := InstanceStore{Client: c, Namespace: ns}
	inst := newInstance(t, c, "u1")
	if _, err := store.Create(ctx, claim.Record{Key: inst.Name, Holder: "p1", Epoch: 2, Released: true}); err != nil {
		t.Fatal(err)
	}
	old, err := store.Get(ctx, inst.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, inst); err != nil {
		t.Fatal(err)
	}
	recreated := newInstance(t, c, "u1")
	if _, ok, err := ReadLease(ctx, c, recreated); ok || err != nil {
		t.Fatalf("the deleted instance's Lease read as the recreated one's: %v", err)
	}
	// Until the old Lease goes, it is a conflict to retry, not a name
	// another pod holds.
	if _, err := store.Get(ctx, inst.Name); !errors.Is(err, claim.ErrConflict) || errors.Is(err, ErrNameTaken) {
		t.Fatalf("get of the deleted instance's Lease: %v, want ErrConflict", err)
	}
	if _, err := store.Create(ctx, claim.Record{Key: inst.Name}); !errors.Is(err, claim.ErrConflict) ||
		errors.Is(err, ErrNameTaken) {
		t.Fatalf("create over the deleted instance's Lease: %v, want ErrConflict", err)
	}
	// envtest runs no garbage collector.
	stale := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: inst.Name}}
	if err := c.Delete(ctx, stale); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, claim.Record{Key: inst.Name, Incarnation: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Incarnation == old.Incarnation || created.Incarnation == "ignored" {
		t.Fatalf("recreated lease incarnation %q, old %q", created.Incarnation, old.Incarnation)
	}
	old.Holder, old.Released = "p1", false
	if _, err := store.Update(ctx, old); !errors.Is(err, claim.ErrConflict) {
		t.Fatalf("update of a recreated Lease from the old version: %v, want ErrConflict", err)
	}
}

// TestNameTaken: an instance or lease name held by an object naming another
// pod is refused as ErrNameTaken, which acquisition does not retry, while a
// retried create of the pod's own instance succeeds.
func TestNameTaken(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()

	squatted := NewInstance(ns, "connect-ip", "pod-u2", "u2", "edge-1", "boot")
	squatted.Name = InstanceName("u1")
	if err := c.Create(ctx, squatted); err != nil {
		t.Fatal(err)
	}
	_, err := CreateInstance(ctx, c, NewInstance(ns, "connect-ip", "pod-u1", "u1", "edge-1", "boot"))
	if !errors.Is(err, ErrNameTaken) || !errors.Is(err, claim.ErrLost) {
		t.Fatalf("create under a name another pod's instance holds: %v, want ErrNameTaken", err)
	}

	inst, err := CreateInstance(ctx, c, NewInstance(ns, "connect-ip", "pod-u3", "u3", "edge-1", "boot"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := CreateInstance(ctx, c, NewInstance(ns, "connect-ip", "pod-u3", "u3", "edge-1", "boot"))
	if err != nil || again.UID != inst.UID {
		t.Fatalf("retried create of the pod's own instance: %v", err)
	}

	f := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: inst.Name,
		Labels: map[string]string{galacticv1alpha1.EdgeLeaseProviderLabel: "connect-ip"},
		Annotations: map[string]string{galacticv1alpha1.EdgeLeasePodUIDAnnotation: "u4",
			galacticv1alpha1.EdgeLeaseRenewStartAnnotation: "1", galacticv1alpha1.EdgeLeaseSequenceAnnotation: "0",
			galacticv1alpha1.EdgeLeaseReleasedAnnotation: "false"},
	}}
	if err := c.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	store := InstanceStore{Client: c, Namespace: ns}
	if _, err := store.Create(ctx, claim.Record{Key: inst.Name}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("lease create under a name another pod's Lease holds: %v, want ErrNameTaken", err)
	}
	holder := &claim.Instance{ID: "p3", Store: store, Clock: (&clock{now: time.Hour}).read, Params: params}
	if _, err := holder.Acquire(ctx, inst.Name); !errors.Is(err, ErrNameTaken) || !errors.Is(err, claim.ErrLost) {
		t.Errorf("acquire of a lease another pod's Lease holds: %v, want ErrNameTaken, not ErrHeld", err)
	}
}

// TestLeaseContention has two processes acquire a released lease at once:
// exactly one holds it.
func TestLeaseContention(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	store := InstanceStore{Client: c, Namespace: ns}
	clk := &clock{now: time.Hour}
	inst := newInstance(t, c, "u1")
	first := &claim.Instance{ID: "p0", Store: store, Clock: clk.read, Params: params}
	if _, err := first.Acquire(ctx, inst.Name); !errors.Is(err, claim.ErrHeld) {
		t.Fatal(err)
	}
	clk.advance(params.TakeoverWait())
	l, err := first.Acquire(ctx, inst.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	for round := range 10 {
		var wg sync.WaitGroup
		won := make(chan claim.Lease, 2)
		for i := range 2 {
			in := &claim.Instance{ID: string(rune('a'+i)) + "-" + string(rune('0'+round)), Store: store, Clock: clk.read,
				Params: params}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if l, err := in.Acquire(ctx, inst.Name); err == nil {
					won <- l
				}
			}()
		}
		wg.Wait()
		close(won)
		var winners []claim.Lease
		for l := range won {
			winners = append(winners, l)
		}
		if len(winners) != 1 {
			t.Fatalf("round %d: %d holders", round, len(winners))
		}
		in := &claim.Instance{ID: winners[0].Holder, Store: store, Clock: clk.read, Params: params}
		if err := in.Release(ctx, winners[0]); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRouteClaim claims, takes over and releases a route by
// compare-and-swap.
func TestRouteClaim(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	prefix := netip.MustParsePrefix("fd00:5::/64")
	rt := NewRoute(ns, "connect-ip", "vpc-uid", prefix)
	if rt.Name != RouteName("vpc-uid", netip.MustParsePrefix("fd00:5::1/64")) {
		t.Fatalf("route name %s is not derived from the masked prefix", rt.Name)
	}
	if err := c.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	l1 := claim.Lease{Key: "i1", Holder: "p1", Epoch: 1}
	if err := Claim(ctx, c, rt, "a1", "pod-1", l1); err != nil {
		t.Fatal(err)
	}
	if got := rt.Spec.Claim; got.Epoch != 1 || got.Attachment != "a1" || got.InstanceEpoch != 1 {
		t.Fatalf("claim %+v", got)
	}
	stale := rt.DeepCopy()
	if err := Claim(ctx, c, rt, "a1", "pod-1", l1); err != nil {
		t.Fatalf("repeated claim: %v", err)
	}

	// The same pod after its instance lease moved to a new epoch.
	l2 := claim.Lease{Key: "i1", Holder: "p1b", Epoch: 2}
	if err := Claim(ctx, c, rt, "a1", "pod-1", l2); err != nil {
		t.Fatal(err)
	}
	if rt.Spec.Claim.Epoch != 2 || rt.Spec.Claim.InstanceEpoch != 2 {
		t.Fatalf("claim after a new instance epoch %+v", rt.Spec.Claim)
	}
	// A takeover built from the earlier read loses.
	if err := Claim(ctx, c, stale, "a2", "pod-2", claim.Lease{Key: "i2", Epoch: 1}); !apierrors.IsConflict(err) {
		t.Fatalf("stale takeover: %v, want a conflict", err)
	}
	if err := Release(ctx, c, rt, l1); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("release under an earlier lease epoch: %v", err)
	}
	if err := Release(ctx, c, rt, l2); err != nil {
		t.Fatal(err)
	}
	if !rt.Spec.Claim.Released {
		t.Fatal("route not released")
	}
	// A released route is claimed again at the next epoch.
	l3 := claim.Lease{Key: "i2", Epoch: 1}
	if err := Claim(ctx, c, rt, "a2", "pod-2", l3); err != nil {
		t.Fatal(err)
	}
	if rt.Spec.Claim.Epoch != 3 || rt.Spec.Claim.Released {
		t.Fatalf("claim after release %+v", rt.Spec.Claim)
	}
	// Once its node records the epoch's gate closed, the same holder claims
	// a new epoch rather than keeping the ended one.
	rt.Status.ClosedEpoch = 3
	if err := c.Status().Update(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if err := Claim(ctx, c, rt, "a2", "pod-2", l3); err != nil {
		t.Fatal(err)
	}
	if rt.Spec.Claim.Epoch != 4 {
		t.Fatalf("claim after the gate closed %+v, want epoch 4", rt.Spec.Claim)
	}
}

// TestLeaseReacquiredAfterRelease: a lease taken again after a release is
// held, not still marked released, so a third process waits for it rather
// than taking it over at once.
func TestLeaseReacquiredAfterRelease(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	store := InstanceStore{Client: c, Namespace: ns}
	clk := &clock{now: time.Hour}
	inst := newInstance(t, c, "u2")
	first := &claim.Instance{ID: "p1", Store: store, Clock: clk.read, Params: params}
	if _, err := first.Acquire(ctx, inst.Name); !errors.Is(err, claim.ErrHeld) {
		t.Fatal(err)
	}
	clk.advance(params.TakeoverWait())
	l, err := first.Acquire(ctx, inst.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	second := &claim.Instance{ID: "p2", Store: store, Clock: clk.read, Params: params}
	if _, err := second.Acquire(ctx, inst.Name); err != nil {
		t.Fatalf("acquisition of a released lease: %v", err)
	}
	if got := lease(t, c, inst.Name); got.Released || got.Holder != "p2" || got.Epoch != 2 {
		t.Fatalf("reacquired lease %+v, want held by p2 at epoch 2", got)
	}
	third := &claim.Instance{ID: "p3", Store: store, Clock: clk.read, Params: params}
	if _, err := third.Acquire(ctx, inst.Name); !errors.Is(err, claim.ErrHeld) {
		t.Fatalf("acquisition of a held lease: %v, want ErrHeld", err)
	}
}
