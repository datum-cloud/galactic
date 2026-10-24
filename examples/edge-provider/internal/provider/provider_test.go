// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package provider

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/datum-cloud/galactic/examples/edge-provider/internal/config"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/dataplane"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/lease"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/route"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

type server struct {
	mu     *sync.Mutex
	closed *[]string
	name   string
}

func (s server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.closed = append(*s.closed, s.name)
	return nil
}

type fixture struct {
	t      *testing.T
	c      client.Client
	p      *Provider
	now    time.Duration
	mu     sync.Mutex
	opened []string
	closed []string
	allow  func() bool
}

const (
	svcUID  = "11111111-1111-1111-1111-111111111111"
	podNS   = "edge"
	tunOpen = "tun tun0"
)

var prefix = netip.MustParsePrefix("fd00:ed9e:100:1::/64")

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, now: time.Hour}
	f.c = fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&galacticv1alpha1.EdgeAttachment{}, &galacticv1alpha1.EdgeRoute{}).Build()
	f.p = &Provider{
		Client: f.c, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config: &config.Config{Provider: "echo", Port: 7777, Services: []config.Service{{
			Namespace: "ns10", Name: "svc", UID: svcUID, VPCUID: "vpc-uid",
			Capabilities: []string{config.SocketAccess, config.PacketAccess}, Prefixes: []netip.Prefix{prefix},
		}}},
		Pod: Pod{Namespace: podNS, Name: "p", UID: "pod-uid", Node: "edge-1", BootID: "boot", RunAsUser: 65532,
			RunAsGroup: 65532},
		Clock: func() time.Duration { return f.now }, Params: lease.Contract, Tick: time.Second,
		RetryAfter: 10 * time.Second,
		Echo: func(_ context.Context, _ *slog.Logger, vrf string, _ netip.Addr, _ uint16, _ string,
		) (dataplane.Server, error) {
			return f.open("echo " + vrf), nil
		},
		TUN: func(_ *slog.Logger, device, _ string, allow func() bool) (dataplane.Server, error) {
			f.allow = allow
			return f.open("tun " + device), nil
		},
	}
	inst, err := f.p.register(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.p.instance = inst
	f.p.holder = &lease.Holder{Client: f.c, Instance: inst, ID: "holder", Clock: f.p.Clock, Params: f.p.Params}
	for _, s := range f.p.Config.Services {
		f.p.services = append(f.p.services, &service{cfg: s, routes: map[netip.Prefix]string{}})
	}
	return f
}

func (f *fixture) open(name string) dataplane.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, name)
	return server{mu: &f.mu, closed: &f.closed, name: name}
}

func (f *fixture) reconcile() {
	f.t.Helper()
	if err := f.p.reconcile(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) attachment() *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	var a galacticv1alpha1.EdgeAttachment
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: podNS, Name: AttachmentName("pod-uid",
		svcUID)}, &a); err != nil {
		f.t.Fatal(err)
	}
	return &a
}

// program reports the attachment programmed, as galactic-edge does.
func (f *fixture) program() {
	f.t.Helper()
	a := f.attachment()
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeAttachmentProgrammed,
		Status: metav1.ConditionTrue, Reason: "Programmed"})
	a.Status.Address, a.Status.PodVRF, a.Status.PacketDevice, a.Status.HostLink = "fd00:ed9e:0:1::2", "vrf0",
		"tun0", "host0"
	if err := f.c.Status().Update(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
}

func TestAttachmentLifecycle(t *testing.T) {
	f := newFixture(t)
	f.reconcile()
	a := f.attachment()
	if a.Spec.InstanceRef.Name != InstanceName("pod-uid") || a.Spec.ContractVersion != "v1alpha1" ||
		a.Spec.PacketDevice == nil || a.Spec.PacketDevice.Owner != 65532 || len(a.Spec.Capabilities) != 2 {
		t.Fatalf("attachment spec %+v", a.Spec)
	}
	if meta.IsStatusConditionTrue(a.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) {
		t.Fatal("Ready before galactic-edge programmed the attachment")
	}

	f.program()
	f.reconcile()
	// The lease is still in its takeover wait, so the packet device stays
	// closed, the attachment is not Ready and no route is claimed.
	if c := meta.FindStatusCondition(f.attachment().Status.Conditions, galacticv1alpha1.EdgeAttachmentReady); c == nil ||
		c.Status != metav1.ConditionFalse || c.Reason != "AwaitingLease" {
		t.Fatalf("Ready before the packet device opened: %+v", c)
	}
	if len(f.opened) != 1 || f.opened[0] != "echo vrf0" {
		t.Fatalf("opened %v before the lease was held", f.opened)
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := f.c.List(context.Background(), &routes); err != nil || len(routes.Items) != 0 {
		t.Fatalf("routes claimed without a lease: %v %v", routes.Items, err)
	}

	f.now += lease.Contract.TakeoverWait()
	f.reconcile() // acquires the lease
	f.reconcile() // opens the packet device and claims the route
	if len(f.opened) != 2 || f.opened[1] != tunOpen {
		t.Fatalf("opened %v", f.opened)
	}
	if !meta.IsStatusConditionTrue(f.attachment().Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) {
		t.Fatal("not Ready once serving")
	}
	var r galacticv1alpha1.EdgeRoute
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: podNS, Name: route.Name("vpc-uid", prefix)},
		&r); err != nil {
		t.Fatal(err)
	}
	cl := r.Spec.Claim
	if cl == nil || cl.Attachment != a.Name || cl.HolderPodUID != "pod-uid" || cl.InstanceEpoch != 1 || cl.Epoch != 1 {
		t.Fatalf("claim %+v", cl)
	}

}

// serve brings f's attachment to serving with the lease held and its
// route claimed, and returns the attachment.
func (f *fixture) serve() *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	f.reconcile()
	f.program()
	f.reconcile()
	f.now += lease.Contract.TakeoverWait()
	f.reconcile()
	f.reconcile()
	return f.attachment()
}

func TestShutdownOrder(t *testing.T) {
	f := newFixture(t)
	a := f.serve()
	var r galacticv1alpha1.EdgeRoute
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: podNS, Name: route.Name("vpc-uid", prefix)},
		&r); err != nil {
		t.Fatal(err)
	}
	// Forwarding stops first, then the claim is released, the
	// attachment deleted and the lease released.
	if err := f.p.shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.closed) < 2 || f.closed[0] != tunOpen {
		t.Fatalf("closed %v, want the packet device first", f.closed)
	}
	if err := f.c.Get(context.Background(), client.ObjectKeyFromObject(&r), &r); err != nil || !r.Spec.Claim.Released {
		t.Fatalf("claim not released: %+v %v", r.Spec.Claim, err)
	}
	err := f.c.Get(context.Background(), client.ObjectKeyFromObject(a), a)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("attachment not deleted: %v", err)
	}
	var l coordinationv1.Lease
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: podNS, Name: InstanceName("pod-uid")},
		&l); err != nil || l.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] != "true" {
		t.Fatalf("lease not released: %v %v", l.Annotations, err)
	}
}

func TestLeaseExpiryStopsForwarding(t *testing.T) {
	f := newFixture(t)
	f.reconcile()
	f.program()
	f.now += lease.Contract.TakeoverWait()
	f.reconcile()
	f.reconcile()
	if len(f.opened) != 2 {
		t.Fatalf("opened %v", f.opened)
	}
	// The API stops answering renewals and the reconcile loop does not
	// run: the packet device stops answering at the lease's deadline on its
	// own.
	f.p.Client = failing{f.c}
	f.p.holder.Client = failing{f.c}
	if !f.allow() {
		t.Fatal("the packet device refuses while the lease is valid")
	}
	f.now = f.p.lease.Deadline
	if f.allow() {
		t.Fatal("the packet device answers past the lease's deadline")
	}
	// The next pass closes it.
	_ = f.p.reconcile(context.Background())
	if f.p.lease != nil {
		t.Fatal("the lease is still held past its deadline")
	}
	if len(f.closed) != 1 || f.closed[0] != tunOpen {
		t.Fatalf("closed %v, want the packet device", f.closed)
	}
}

func TestNameTakenStops(t *testing.T) {
	f := newFixture(t)
	other := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: podNS, Name: AttachmentName("pod-uid", svcUID)},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{PodUID: "someone-else",
			ServiceRef: galacticv1alpha1.EdgeServiceReference{UID: svcUID}},
	}
	if err := f.c.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := f.p.reconcile(context.Background()); err == nil {
		t.Fatal("a name held by another pod's attachment was not fatal")
	}
}

// failing refuses every write, as an unreachable API server does.
type failing struct{ client.Client }

func (failing) Update(context.Context, client.Object, ...client.UpdateOption) error {
	return apierrors.NewServiceUnavailable("unreachable")
}

func TestFrozenKeepsAnswering(t *testing.T) {
	f := newFixture(t)
	f.serve()
	// A frozen instance stands in for one that ignores its lease: its
	// packet device keeps answering past the deadline, so only the
	// foundation can stop its forwarding.
	f.p.frozen.Store(true)
	f.now = f.p.lease.Deadline + time.Second
	if !f.allow() {
		t.Fatal("a frozen instance stopped answering at its deadline")
	}
}
