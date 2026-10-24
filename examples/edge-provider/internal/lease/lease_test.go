// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lease

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	leaseName = "ei-pod-a"
	leaseNS   = "provider"
)

type fixture struct {
	t    *testing.T
	c    client.Client
	inst *galacticv1alpha1.EdgeInstance
	now  time.Duration
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName, UID: "inst-uid"},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: "echo"},
			PodName: "a", PodUID: "pod-a", NodeName: "edge-1", BootID: "boot"},
	}
	return &fixture{t: t, c: fake.NewClientBuilder().WithScheme(s).WithObjects(inst).Build(), inst: inst,
		now: time.Hour}
}

func (f *fixture) holder(id string) *Holder {
	return &Holder{Client: f.c, Instance: f.inst, ID: id, Clock: func() time.Duration { return f.now },
		Params: Contract}
}

func (f *fixture) stored() *coordinationv1.Lease {
	f.t.Helper()
	var l coordinationv1.Lease
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: leaseNS, Name: leaseName}, &l); err != nil {
		f.t.Fatal(err)
	}
	return &l
}

// acquire acquires through the takeover wait.
func (f *fixture) acquire(h *Holder) Lease {
	f.t.Helper()
	ctx := context.Background()
	for range 3 {
		l, err := h.Acquire(ctx)
		if err == nil {
			return l
		}
		if !errors.Is(err, ErrWaiting) {
			f.t.Fatal(err)
		}
		f.now += Contract.TakeoverWait()
	}
	f.t.Fatal("never acquired")
	return Lease{}
}

func TestTakeoverWait(t *testing.T) {
	if got, want := Contract.TakeoverWait(), 15530030030*time.Nanosecond; got != want {
		t.Fatalf("takeover wait %v, want %v", got, want)
	}
}

func TestAcquireWaitsOnANewLease(t *testing.T) {
	f := newFixture(t)
	h := f.holder("first")
	ctx := context.Background()
	if _, err := h.Acquire(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatalf("first acquire: %v, want ErrWaiting", err)
	}
	l := f.stored()
	if l.Spec.HolderIdentity != nil || ptr.Deref(l.Spec.LeaseTransitions, -1) != 0 {
		t.Fatalf("the new Lease is held: %+v", l.Spec)
	}
	if l.Labels[galacticv1alpha1.EdgeLeaseProviderLabel] != "echo" ||
		l.Annotations[galacticv1alpha1.EdgeLeasePodUIDAnnotation] != "pod-a" ||
		len(l.OwnerReferences) != 1 || l.OwnerReferences[0].UID != "inst-uid" {
		t.Fatalf("the Lease is not bound to its instance: %+v", l.ObjectMeta)
	}
	f.now += Contract.TakeoverWait() - time.Millisecond
	if _, err := h.Acquire(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatalf("acquire before the wait: %v, want ErrWaiting", err)
	}
	f.now += time.Millisecond
	got, err := h.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 1 || got.RenewStart != f.now || got.Deadline != f.now+Contract.Duration {
		t.Fatalf("lease %+v", got)
	}
	if l := f.stored(); ptr.Deref(l.Spec.HolderIdentity, "") != "first" ||
		l.Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation] != strconv.FormatInt(int64(f.now), 10) {
		t.Fatalf("stored %+v %v", l.Spec, l.Annotations)
	}
}

func TestRenewal(t *testing.T) {
	f := newFixture(t)
	h := f.holder("first")
	l := f.acquire(h)
	f.now += Contract.Renew
	l2, err := h.Renew(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Epoch != l.Epoch || l2.Deadline != f.now+Contract.Duration {
		t.Fatalf("renewed %+v", l2)
	}
	if a := f.stored().Annotations; a[galacticv1alpha1.EdgeLeaseSequenceAnnotation] != "1" ||
		a[galacticv1alpha1.EdgeLeaseRenewStartAnnotation] != strconv.FormatInt(int64(f.now), 10) {
		t.Fatalf("annotations %v", a)
	}
}

func TestRestartedProcessWaits(t *testing.T) {
	f := newFixture(t)
	f.acquire(f.holder("first"))
	// A restarted process has a new holder ID and gets nothing from its
	// predecessor's lease until the wait passes.
	h := f.holder("second")
	if _, err := h.Acquire(context.Background()); !errors.Is(err, ErrWaiting) {
		t.Fatalf("got %v, want ErrWaiting", err)
	}
	f.now += Contract.TakeoverWait()
	l, err := h.Acquire(context.Background())
	if err != nil || l.Epoch != 2 {
		t.Fatalf("got %+v %v, want epoch 2", l, err)
	}
}

func TestReleasedLeaseIsTakenAtOnce(t *testing.T) {
	f := newFixture(t)
	first := f.holder("first")
	l := f.acquire(first)
	if err := first.Release(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	got, err := f.holder("second").Acquire(context.Background())
	if err != nil || got.Epoch != 2 {
		t.Fatalf("got %+v %v", got, err)
	}
	if f.stored().Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] != "false" {
		t.Fatal("the new epoch is still released")
	}
}

func TestFencedLeaseIsLost(t *testing.T) {
	f := newFixture(t)
	h := f.holder("first")
	l := f.acquire(h)
	// galactic-controller fences: next epoch, no holder.
	cur := f.stored()
	cur.Spec.HolderIdentity = nil
	cur.Spec.LeaseTransitions = ptr.To(*cur.Spec.LeaseTransitions + 1)
	if err := f.c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Renew(context.Background(), l); !errors.Is(err, ErrLost) {
		t.Fatalf("got %v, want ErrLost", err)
	}
}

func TestLostReplyIsRecovered(t *testing.T) {
	f := newFixture(t)
	h := f.holder("first")
	l := f.acquire(h)
	// A renewal that landed but whose reply was lost: the stored version
	// moved on while still naming this holder and epoch.
	cur := f.stored()
	cur.Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation] = "1"
	if err := f.c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	f.now += Contract.Renew
	l2, err := h.Renew(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Deadline != f.now+Contract.Duration ||
		f.stored().Annotations[galacticv1alpha1.EdgeLeaseSequenceAnnotation] != "2" {
		t.Fatalf("renewed %+v", l2)
	}
}

func TestExpiredLeaseIsNotRenewed(t *testing.T) {
	f := newFixture(t)
	h := f.holder("first")
	l := f.acquire(h)
	before := f.stored().ResourceVersion
	f.now = l.Deadline
	if _, err := h.Renew(context.Background(), l); !errors.Is(err, ErrLost) {
		t.Fatalf("got %v, want ErrLost", err)
	}
	if f.stored().ResourceVersion != before {
		t.Fatal("an expired lease was written")
	}
}

func TestNameTaken(t *testing.T) {
	f := newFixture(t)
	foreign := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName,
		Annotations: map[string]string{galacticv1alpha1.EdgeLeasePodUIDAnnotation: "pod-b"}}}
	if err := f.c.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := f.holder("first").Acquire(context.Background()); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("got %v, want ErrNameTaken", err)
	}
}
