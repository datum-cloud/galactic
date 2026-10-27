// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
)

const (
	testVPCName     = "prod"
	credA1          = "cred-a1"
	testVPCUID      = "vpc-uid"
	testHolder      = "proc"
	testIncarnation = "lease-uid"
	testNS          = "edge"
	testPod         = "pod-uid-1"
	testNode        = "edge-1"
	testVPC         = "000000abc"
)

var (
	svcA = ServiceRef{Namespace: "tenant", Name: "svc-a", UID: "svc-uid-a"}
	svcB = ServiceRef{Namespace: "tenant", Name: "svc-b", UID: "svc-uid-b"}
)

// grants are the test authority's connectors, keyed by credential.
var grants = map[string]Grant{
	credA1: {Connector: "a1", Principal: "a1", VPC: testVPCName, VPCUID: testVPCUID, VPCID: testVPC, Service: svcA,
		Prefix: netip.MustParsePrefix("fd00:10:0:1:1::/96")},
	"cred-a2": {Connector: "a2", Principal: "a2", VPC: testVPCName, VPCUID: testVPCUID, VPCID: testVPC, Service: svcA,
		Prefix: netip.MustParsePrefix("fd00:10:0:1:2::/96")},
	"cred-b": {Connector: "b", Principal: "b", VPC: testVPCName, VPCUID: testVPCUID, VPCID: testVPC, Service: svcB,
		Prefix: netip.MustParsePrefix("fd00:10:0:1:3::/96")},
}

// harness runs an Adapter against a fake API server. Its core stand-in
// admits and programs every attachment and accepts every claim, as
// programAttachment and acceptRoute describe, unless a test changes them.
type harness struct {
	t     *testing.T
	c     client.Client
	a     *Adapter
	clock *testClock

	mu sync.Mutex
	// now is the wall clock grants are checked against.
	now time.Time
	// hosts are the host ends of the packet devices, by device name.
	hosts map[string]*os.File
	// openErr fails OpenDevice.
	openErr error
	// programAttachment sets an attachment's status as core and its node
	// would; nil leaves it untouched.
	programAttachment func(*galacticv1alpha1.EdgeAttachment)
	// acceptRoute sets a route's status as core would; nil leaves it
	// untouched.
	acceptRoute func(*galacticv1alpha1.EdgeRoute)
	// leaseEpoch is the epoch of the lease start gives the adapter; zero
	// means 3.
	leaseEpoch uint64
	// calls records claim releases, attachment deletes and lease releases
	// in order.
	calls []string
}

func (h *harness) record(call string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, call)
}

// leaseStore is the instance's lease record, held by the harness's process.
// It records a release in the harness's calls.
type leaseStore struct {
	h *harness
	r claim.Record
}

func (s *leaseStore) Get(context.Context, string) (claim.Record, error) { return s.r, nil }

func (s *leaseStore) Create(context.Context, claim.Record) (claim.Record, error) {
	return claim.Record{}, claim.ErrConflict
}

func (s *leaseStore) Update(_ context.Context, r claim.Record) (claim.Record, error) {
	if r.Released {
		s.h.record("lease released")
	}
	s.r = r
	return r, nil
}

type testClock struct {
	mu  sync.Mutex
	now time.Duration
}

func (c *testClock) read() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += d
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	h := &harness{
		t: t, clock: &testClock{now: time.Hour}, now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		hosts: map[string]*os.File{},
	}
	// The fake API server assigns no UIDs; the adapter pins them.
	h.c = fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&galacticv1alpha1.EdgeAttachment{}, &galacticv1alpha1.EdgeRoute{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.CreateOption) error {
				obj.SetUID(types.UID(rand.Text()))
				return c.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.UpdateOption) error {
				err := c.Update(ctx, obj, opts...)
				if rt, ok := obj.(*galacticv1alpha1.EdgeRoute); ok && err == nil && rt.Spec.Claim != nil &&
					rt.Spec.Claim.Released {
					h.record("claim released")
				}
				return err
			},
			// The fake API server ignores a delete's UID precondition;
			// this enforces it as the real one does.
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.DeleteOption) error {
				do := &client.DeleteOptions{}
				do.ApplyOptions(opts)
				if do.Preconditions != nil && do.Preconditions.UID != nil {
					cur := obj.DeepCopyObject().(client.Object)
					if err := c.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
						return err
					}
					if cur.GetUID() != *do.Preconditions.UID {
						return apierrors.NewConflict(schema.GroupResource{}, obj.GetName(),
							errors.New("UID precondition failed"))
					}
				}
				err := c.Delete(ctx, obj, opts...)
				if _, ok := obj.(*galacticv1alpha1.EdgeAttachment); ok && err == nil {
					h.record("attachment deleted")
				}
				return err
			},
		}).Build()
	h.programAttachment = h.programmed
	h.acceptRoute = h.accepted
	return h
}

// start creates the adapter, registers its instance and gives it a lease.
func (h *harness) start() {
	h.t.Helper()
	a, err := New(Config{
		Client: h.c, Provider: coreProvider, Authorizer: h, OpenDevice: h.open,
		Pod: Pod{Namespace: testNS, Name: "masque-0", UID: testPod, Node: testNode, BootID: "boot"},
		Claims: &claim.Instance{ID: testHolder, Clock: h.clock.read, Store: &leaseStore{h: h, r: claim.Record{
			Key: provider.InstanceName(testPod), Holder: testHolder, Incarnation: testIncarnation, Epoch: h.epoch(),
			Version: "1"}}}, Now: h.wall,
		Poll: 2 * time.Millisecond, Prepare: 2 * time.Second, Idle: time.Minute,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	a.setLease(&claim.Lease{Key: provider.InstanceName(testPod), Holder: testHolder, Epoch: h.epoch(),
		Incarnation: testIncarnation, Deadline: h.clock.read() + time.Hour})
	h.a = a
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			h.core()
			time.Sleep(time.Millisecond)
		}
	}()
	h.t.Cleanup(func() {
		cancel()
		<-done
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, f := range h.hosts {
			_ = f.Close()
		}
	})
}

func (h *harness) epoch() uint64 {
	if h.leaseEpoch == 0 {
		return 3
	}
	return h.leaseEpoch
}

func (h *harness) wall() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

// Authorize implements Authorizer from grants, with grants expiring an
// hour after the harness's wall clock.
func (h *harness) Authorize(_ context.Context, credential, vpc string) (Grant, error) {
	g, ok := grants[credential]
	if !ok {
		return Grant{}, connectip.ErrUnauthenticated
	}
	if g.VPC != vpc {
		return Grant{}, connectip.ErrForbidden
	}
	g.NotAfter = h.wall().Add(time.Hour)
	return g, nil
}

// open returns one end of a nonblocking packet socket pair as the device
// and keeps the other end as the device's host side.
func (h *harness) open(name string) (*os.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.openErr != nil {
		return nil, h.openErr
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if old := h.hosts[name]; old != nil {
		_ = old.Close()
	}
	h.hosts[name] = os.NewFile(uintptr(fds[1]), name+"-host")
	return os.NewFile(uintptr(fds[0]), name), nil
}

func (h *harness) host(name string) *os.File {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hosts[name]
}

// programmed is the status core and galactic-edge give an admitted,
// programmed PacketAccess attachment.
func (h *harness) programmed(att *galacticv1alpha1.EdgeAttachment) {
	att.Status.NodeName, att.Status.VPC, att.Status.Address = testNode, testVPC, "fd00:10:0:e::1"
	att.Status.HostLink, att.Status.PacketDevice = "eh0", deviceName(att)
	for _, c := range []string{galacticv1alpha1.EdgeAttachmentAdmitted, galacticv1alpha1.EdgeAttachmentAllocated,
		galacticv1alpha1.EdgeAttachmentProgrammed} {
		meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue,
			Reason: c})
	}
}

func deviceName(att *galacticv1alpha1.EdgeAttachment) string {
	return "et-" + att.Spec.ServiceRef.Name
}

// accepted is the status core gives a route whose claim it accepts.
func (h *harness) accepted(rt *galacticv1alpha1.EdgeRoute) {
	cl := rt.Spec.Claim
	if cl == nil || cl.Released {
		return
	}
	var att galacticv1alpha1.EdgeAttachment
	if err := h.c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: cl.Attachment}, &att); err != nil {
		return
	}
	rt.Status.Accepted = &galacticv1alpha1.EdgeRouteHolder{Epoch: cl.Epoch, Attachment: cl.Attachment,
		AttachmentUID: string(att.UID), Instance: cl.HolderInstance, InstanceIncarnation: testIncarnation,
		InstanceEpoch: cl.InstanceEpoch, Node: testNode}
	meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
		Status: metav1.ConditionTrue, Reason: "Accepted"})
}

// core applies programAttachment and acceptRoute once to every object.
func (h *harness) core() {
	ctx := context.Background()
	h.mu.Lock()
	program, accept := h.programAttachment, h.acceptRoute
	h.mu.Unlock()
	var atts galacticv1alpha1.EdgeAttachmentList
	if err := h.c.List(ctx, &atts); err == nil && program != nil {
		for i := range atts.Items {
			att := &atts.Items[i]
			if meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted) != nil {
				continue
			}
			program(att)
			_ = h.c.Status().Update(ctx, att)
		}
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := h.c.List(ctx, &routes); err == nil && accept != nil {
		for i := range routes.Items {
			rt := &routes.Items[i]
			if rt.Spec.Claim == nil || (rt.Status.Accepted != nil && rt.Status.Accepted.Epoch == rt.Spec.Claim.Epoch) {
				continue
			}
			accept(rt)
			_ = h.c.Status().Update(ctx, rt)
		}
	}
}

func (h *harness) setCore(program func(*galacticv1alpha1.EdgeAttachment), accept func(*galacticv1alpha1.EdgeRoute)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.programAttachment, h.acceptRoute = program, accept
}

func (h *harness) admit(credential string) connectip.Lease {
	h.t.Helper()
	l, err := h.a.Admit(context.Background(), credential, testVPCName)
	if err != nil {
		h.t.Fatalf("admit %s: %v", credential, err)
	}
	return l
}

func (h *harness) attachment(svc ServiceRef) *galacticv1alpha1.EdgeAttachment {
	h.t.Helper()
	var att galacticv1alpha1.EdgeAttachment
	err := h.c.Get(context.Background(), client.ObjectKey{Namespace: testNS,
		Name: provider.AttachmentName(svc.UID, testPod)}, &att)
	if err != nil {
		h.t.Fatalf("read attachment of %s: %v", svc.Name, err)
	}
	return &att
}

func (h *harness) route(credential string) *galacticv1alpha1.EdgeRoute {
	h.t.Helper()
	g := grants[credential]
	var rt galacticv1alpha1.EdgeRoute
	err := h.c.Get(context.Background(), client.ObjectKey{Namespace: testNS,
		Name: provider.RouteName(g.VPCUID, g.Prefix)}, &rt)
	if err != nil {
		h.t.Fatalf("read route of %s: %v", credential, err)
	}
	return &rt
}

func ready(att *galacticv1alpha1.EdgeAttachment) metav1.ConditionStatus {
	c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady)
	if c == nil {
		return ""
	}
	return c.Status
}

// packet is an IPv6 packet to dst.
func packet(dst string) []byte {
	p := make([]byte, 48)
	p[0] = 0x60
	p[6] = 59
	p[7] = 64
	src := netip.MustParseAddr("fd00:10::5").As16()
	copy(p[8:24], src[:])
	d := netip.MustParseAddr(dst).As16()
	copy(p[24:40], d[:])
	return p
}

// expectRead waits for s to read a packet to dst.
func expectRead(t *testing.T, s connectip.BackendSession, dst string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 1500)
	n, err := s.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatalf("read packet to %s: %v", dst, err)
	}
	if got := netip.AddrFrom16([16]byte(buf[24:40])); n != 48 || got != netip.MustParseAddr(dst) {
		t.Fatalf("read %d bytes to %s, want a packet to %s", n, got, dst)
	}
}

func expectDone(t *testing.T, l connectip.Lease, what string) {
	t.Helper()
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not end the request", what)
	}
}

func expectLive(t *testing.T, l connectip.Lease, what string) {
	t.Helper()
	select {
	case <-l.Done():
		t.Fatalf("%s ended the request", what)
	default:
	}
}

func TestAdmitServesProgrammedAttachment(t *testing.T) {
	h := newHarness(t)
	h.start()
	l := h.admit(credA1)
	defer func() { _ = l.Close() }()

	info := l.Info()
	att, rt := h.attachment(svcA), h.route(credA1)
	if info.Attachment != att.Name || info.Claim != rt.Name || info.Epoch != uint64(rt.Spec.Claim.Epoch) ||
		info.Connector != "a1" || info.VPC != "prod" || info.Prefix != grants[credA1].Prefix {
		t.Fatalf("session info %+v does not name attachment %s and route %s", info, att.Name, rt.Name)
	}
	if ready(att) != metav1.ConditionTrue {
		t.Fatalf("attachment Ready = %q, want True", ready(att))
	}
	want := []galacticv1alpha1.EdgeCapability{{Name: PacketAccess, Version: "v1"}}
	if att.Spec.ContractVersion != ContractVersion || len(att.Spec.Capabilities) != 1 ||
		att.Spec.Capabilities[0] != want[0] {
		t.Fatalf("attachment requests %s %v, want %s %v", att.Spec.ContractVersion, att.Spec.Capabilities,
			ContractVersion, want)
	}
	cl := rt.Spec.Claim
	if cl.Attachment != att.Name || cl.HolderPodUID != testPod || cl.InstanceEpoch != 3 {
		t.Fatalf("route claim %+v, want attachment %s of pod %s at lease epoch 3", cl, att.Name, testPod)
	}

	s, err := h.a.Open(context.Background(), info)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	host := h.host(deviceName(att))
	if _, err := host.Write(packet("fd00:10:0:1:1::9")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, s, "fd00:10:0:1:1::9")
	if err := s.WritePacket(packet("fd00:10::5")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = host.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := host.Read(buf); err != nil || n != 48 {
		t.Fatalf("device received %d bytes, %v; want the client's packet", n, err)
	}
}

func TestAdmitFailsClosed(t *testing.T) {
	refuse := func(reason string) func(*galacticv1alpha1.EdgeAttachment) {
		return func(att *galacticv1alpha1.EdgeAttachment) {
			meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionFalse, Reason: reason,
				Message: "refused by core"})
		}
	}
	for _, tc := range []struct {
		name       string
		credential string
		vpc        string
		program    func(h *harness) func(*galacticv1alpha1.EdgeAttachment)
		openErr    error
		noLease    bool
		want       error
		wantText   string
		// wantReady is the attachment's Ready status afterwards, or "" when
		// the adapter must not report it at all.
		wantReady metav1.ConditionStatus
	}{
		{name: "unknown credential", credential: "nope", want: connectip.ErrUnauthenticated},
		{name: "other VPC", credential: credA1, vpc: "staging", want: connectip.ErrForbidden},
		{name: "unsupported capability", credential: credA1, want: ErrUnavailable,
			wantText: "UnsupportedCapability",
			program: func(*harness) func(*galacticv1alpha1.EdgeAttachment) {
				return refuse("UnsupportedCapability")
			}},
		{name: "unauthorized service", credential: credA1, want: ErrUnavailable, wantText: "ServiceNotGranted",
			program: func(*harness) func(*galacticv1alpha1.EdgeAttachment) { return refuse("ServiceNotGranted") }},
		{name: "attachment in another VPC", credential: credA1, want: ErrUnavailable, wantText: "not the grant's",
			wantReady: metav1.ConditionFalse,
			program: func(h *harness) func(*galacticv1alpha1.EdgeAttachment) {
				return func(att *galacticv1alpha1.EdgeAttachment) {
					h.programmed(att)
					att.Status.VPC = "000000xyz"
				}
			}},
		{name: "attachment on another node", credential: credA1, want: ErrUnavailable, wantText: "on node",
			wantReady: metav1.ConditionFalse,
			program: func(h *harness) func(*galacticv1alpha1.EdgeAttachment) {
				return func(att *galacticv1alpha1.EdgeAttachment) {
					h.programmed(att)
					att.Status.NodeName = "edge-2"
				}
			}},
		{name: "no packet device", credential: credA1, want: ErrUnavailable, wantText: "without a packet device",
			wantReady: metav1.ConditionFalse,
			program: func(h *harness) func(*galacticv1alpha1.EdgeAttachment) {
				return func(att *galacticv1alpha1.EdgeAttachment) {
					h.programmed(att)
					att.Status.PacketDevice = ""
				}
			}},
		{name: "packet device unavailable", credential: credA1, want: ErrUnavailable, wantText: "open packet device",
			openErr: unix.ENODEV, wantReady: metav1.ConditionFalse},
		{name: "draining", credential: credA1, want: ErrUnavailable, wantText: "draining",
			program: func(h *harness) func(*galacticv1alpha1.EdgeAttachment) {
				return func(att *galacticv1alpha1.EdgeAttachment) {
					h.programmed(att)
					meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
						Type: galacticv1alpha1.EdgeAttachmentDraining, Status: metav1.ConditionTrue, Reason: "Draining"})
				}
			}},
		{name: "never programmed", credential: credA1, want: ErrUnavailable, wantText: "program attachment",
			program: func(*harness) func(*galacticv1alpha1.EdgeAttachment) {
				return func(att *galacticv1alpha1.EdgeAttachment) {
					meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
						Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionTrue, Reason: "Admitted"})
				}
			}},
		{name: "no lease", credential: credA1, noLease: true, want: ErrUnavailable, wantText: "no lease"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.program != nil {
				h.programAttachment = tc.program(h)
			}
			h.openErr = tc.openErr
			h.start()
			h.a.cfg.Prepare = 200 * time.Millisecond
			if tc.noLease {
				h.a.setLease(nil)
			}
			vpc := tc.vpc
			if vpc == "" {
				vpc = testVPCName
			}
			l, err := h.a.Admit(context.Background(), tc.credential, vpc)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Admit = %v, %v; want %v containing %q", l, err, tc.want, tc.wantText)
			}
			var routes galacticv1alpha1.EdgeRouteList
			if err := h.c.List(context.Background(), &routes); err != nil {
				t.Fatal(err)
			}
			if len(routes.Items) != 0 {
				t.Fatalf("a refused request claimed route %s", routes.Items[0].Name)
			}
			if !errors.Is(tc.want, ErrUnavailable) || tc.noLease {
				return
			}
			if got := ready(h.attachment(svcA)); got != tc.wantReady {
				t.Fatalf("attachment Ready = %q, want %q", got, tc.wantReady)
			}
		})
	}
}

func TestInvalidGrantFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*Grant){
		"expired":         func(g *Grant) { g.NotAfter = now },
		"other VPC":       func(g *Grant) { g.VPC = "staging" },
		"no service UID":  func(g *Grant) { g.Service.UID = "" },
		"no VPC ID":       func(g *Grant) { g.VPCID = "" },
		"not a /96":       func(g *Grant) { g.Prefix = netip.MustParsePrefix("fd00:10:0:1::/64") },
		"unmasked":        func(g *Grant) { g.Prefix = netip.MustParsePrefix("fd00:10:0:1:1::1/96") },
		"IPv4":            func(g *Grant) { g.Prefix = netip.MustParsePrefix("10.0.0.0/8") },
		"unmasked route":  func(g *Grant) { g.Routes = []netip.Prefix{netip.MustParsePrefix("fd00:10::1/48")} },
		"no connector id": func(g *Grant) { g.Connector = "" },
	} {
		t.Run(name, func(t *testing.T) {
			g := grants[credA1]
			g.NotAfter = now.Add(time.Hour)
			mutate(&g)
			if err := g.validate("prod", now); err == nil {
				t.Fatalf("grant %+v validated", g)
			}
		})
	}
}

// TestSharedAttachment admits two connectors of one service, which share
// its attachment and device, and checks that ending one request leaves the
// other's device, route claim and packet stream intact.
func TestSharedAttachment(t *testing.T) {
	h := newHarness(t)
	h.start()
	l1, l2 := h.admit(credA1), h.admit("cred-a2")
	defer func() { _ = l2.Close() }()
	if l1.Info().Attachment != l2.Info().Attachment {
		t.Fatalf("connectors of one service use attachments %s and %s", l1.Info().Attachment, l2.Info().Attachment)
	}
	s1, err := h.a.Open(context.Background(), l1.Info())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := h.a.Open(context.Background(), l2.Info())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	host := h.host(deviceName(h.attachment(svcA)))
	for _, dst := range []string{"fd00:10:0:1:1::9", "fd00:10:0:1:2::9"} {
		if _, err := host.Write(packet(dst)); err != nil {
			t.Fatal(err)
		}
	}
	expectRead(t, s1, "fd00:10:0:1:1::9")
	expectRead(t, s2, "fd00:10:0:1:2::9")

	// The transport ends the first request: packet path first, then lease.
	_ = s1.Close()
	_ = l1.Close()
	expectLive(t, l2, "closing another connector's request")
	if !h.route(credA1).Spec.Claim.Released {
		t.Fatal("the ended connector's claim was not released")
	}
	if h.route("cred-a2").Spec.Claim.Released {
		t.Fatal("ending one connector released another's claim")
	}
	att := h.attachment(svcA)
	if att.DeletionTimestamp != nil || ready(att) != metav1.ConditionTrue {
		t.Fatal("ending one request took the shared attachment out of service")
	}
	if _, err := host.Write(packet("fd00:10:0:1:2::a")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, s2, "fd00:10:0:1:2::a")
	if err := s2.WritePacket(packet("fd00:10::5")); err != nil {
		t.Fatalf("the remaining request cannot write: %v", err)
	}
}

// TestDuplicateRequest refuses a second request of a connector that already
// has one open, before any preparation, and leaves the first request's
// claim and stream intact.
func TestDuplicateRequest(t *testing.T) {
	h := newHarness(t)
	h.start()
	l1 := h.admit(credA1)
	defer func() { _ = l1.Close() }()
	s1, err := h.a.Open(context.Background(), l1.Info())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s1.Close() }()
	if l2, err := h.a.Admit(context.Background(), credA1, testVPCName); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "already has an open request") {
		t.Fatalf("second request of the connector = %v, %v; want a refusal", l2, err)
	}
	expectLive(t, l1, "a refused duplicate request")
	if h.route(credA1).Spec.Claim.Released {
		t.Fatal("a refused duplicate request released the connector's claim")
	}
	if _, err := h.host(deviceName(h.attachment(svcA))).Write(packet("fd00:10:0:1:1::9")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, s1, "fd00:10:0:1:1::9")
}

// TestReleaseRacesReacquire drops a connector's only request and, before
// that request's release runs, admits the connector's next request, which
// claims the route again. The late release leaves the new claim held.
func TestReleaseRacesReacquire(t *testing.T) {
	h := newHarness(t)
	h.start()
	l1 := h.admit(credA1)
	r := l1.(*session).rt
	h.a.mu.Lock()
	delete(h.a.sessions, l1.Info().ID)
	h.a.mu.Unlock()
	if !h.a.dropRoute(r) {
		t.Fatal("the only request's reference was not the last")
	}
	l2 := h.admit(credA1)
	defer func() { _ = l2.Close() }()
	h.a.releaseUnused(context.Background(), r)
	expectLive(t, l2, "the previous request's late release")
	if h.route(credA1).Spec.Claim.Released {
		t.Fatal("the previous request's late release released the next request's claim")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestLeaseChangeEndsRequests loses the lease and acquires a later epoch:
// the old request ends, and the next one forwards only under a claim at the
// new epoch.
func TestLeaseChangeEndsRequests(t *testing.T) {
	h := newHarness(t)
	h.start()
	l1 := h.admit(credA1)
	h.a.loseLease("test")
	expectDone(t, l1, "losing the lease")
	h.a.setLease(&claim.Lease{Key: provider.InstanceName(testPod), Holder: testHolder, Epoch: 4,
		Incarnation: testIncarnation, Deadline: h.clock.read() + time.Hour})
	_ = l1.Close()
	l2 := h.admit(credA1)
	defer func() { _ = l2.Close() }()
	if cl := h.route(credA1).Spec.Claim; cl.InstanceEpoch != 4 || cl.Released {
		t.Fatalf("claim after the lease changed: %+v, want an unreleased claim at lease epoch 4", cl)
	}
	if s := l2.(*session); s.leaseEpoch != 4 || !s.forwarding() {
		t.Fatalf("the new request forwards under lease epoch %d", s.leaseEpoch)
	}
}

// TestClaimMovingAttachmentEndsRequests gives two connectors of different
// services the same /96 in one VPC: the second's claim moves the route to
// its attachment, and the first's request, on the other attachment, ends.
func TestClaimMovingAttachmentEndsRequests(t *testing.T) {
	g := grants[credA1]
	g.Connector, g.Principal, g.Service = "dup", "dup", svcB
	grants["cred-dup"] = g
	defer delete(grants, "cred-dup")
	h := newHarness(t)
	h.start()
	l1 := h.admit(credA1)
	defer func() { _ = l1.Close() }()
	l2 := h.admit("cred-dup")
	defer func() { _ = l2.Close() }()
	expectDone(t, l1, "the route's claim moving to another attachment")
	if l1.(*session).forwarding() {
		t.Fatal("a request on the attachment the claim left still forwards")
	}
	if l2.Info().Attachment == l1.Info().Attachment {
		t.Fatal("the two services share an attachment")
	}
}

// TestQueuedRequestHonorsDeadline holds one request in a preparation that
// never completes and checks that another request of the same service gives
// up at its own deadline instead of waiting for the first.
func TestQueuedRequestHonorsDeadline(t *testing.T) {
	h := newHarness(t)
	h.programAttachment = nil
	h.start()
	h.a.cfg.Prepare = 5 * time.Second
	first := make(chan error, 1)
	go func() {
		_, err := h.a.Admit(context.Background(), credA1, testVPCName)
		first <- err
	}()
	waitFor(t, "the first request to request the attachment", func() bool {
		var list galacticv1alpha1.EdgeAttachmentList
		return h.c.List(context.Background(), &list) == nil && len(list.Items) == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := h.a.Admit(ctx, "cred-a2", testVPCName); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("queued request = %v, want unavailable", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("queued request waited %v, past its own deadline", d)
	}
	if err := <-first; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first request = %v, want unavailable once its preparation timed out", err)
	}
}

func TestOpenRejectsUnknownRequest(t *testing.T) {
	h := newHarness(t)
	h.start()
	l := h.admit(credA1)
	defer func() { _ = l.Close() }()
	forged := l.Info()
	forged.Epoch++
	if _, err := h.a.Open(context.Background(), forged); err == nil {
		t.Fatal("Open accepted a request with another claim epoch")
	}
	forged = l.Info()
	forged.ID += 100
	if _, err := h.a.Open(context.Background(), forged); err == nil {
		t.Fatal("Open accepted a request that was never admitted")
	}
}

// TestForwardingStops checks each way a request's authority ends: its
// packets stop at once and its lease reports Done.
func TestForwardingStops(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stop ends the authority; check is whether the adapter's check
		// must run to notice it.
		stop  func(h *harness)
		check bool
	}{
		{name: "lease lost", stop: func(h *harness) { h.a.loseLease("test") }},
		{name: "lease expired", stop: func(h *harness) { h.clock.advance(2 * time.Hour) }},
		{name: "grant expired", stop: func(h *harness) {
			h.mu.Lock()
			h.now = h.now.Add(2 * time.Hour)
			h.mu.Unlock()
		}},
		{name: "attachment draining", check: true, stop: func(h *harness) {
			att := h.attachment(svcA)
			meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentDraining, Status: metav1.ConditionTrue, Reason: "Draining"})
			if err := h.c.Status().Update(context.Background(), att); err != nil {
				h.t.Fatal(err)
			}
		}},
		{name: "attachment reprogrammed", check: true, stop: func(h *harness) {
			att := h.attachment(svcA)
			att.Status.HostLink = "eh1"
			if err := h.c.Status().Update(context.Background(), att); err != nil {
				h.t.Fatal(err)
			}
		}},
		{name: "attachment deleted", check: true, stop: func(h *harness) {
			if err := h.c.Delete(context.Background(), h.attachment(svcA)); err != nil {
				h.t.Fatal(err)
			}
		}},
		{name: "route revoked", check: true, stop: func(h *harness) {
			rt := h.route(credA1)
			meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
				Status: metav1.ConditionFalse, Reason: "Revoked"})
			if err := h.c.Status().Update(context.Background(), rt); err != nil {
				h.t.Fatal(err)
			}
		}},
		{name: "route gate closed", check: true, stop: func(h *harness) {
			rt := h.route(credA1)
			rt.Status.ClosedEpoch = rt.Spec.Claim.Epoch
			if err := h.c.Status().Update(context.Background(), rt); err != nil {
				h.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.start()
			l := h.admit(credA1)
			defer func() { _ = l.Close() }()
			s, err := h.a.Open(context.Background(), l.Info())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if err := s.WritePacket(packet("fd00:10::5")); err != nil {
				t.Fatal(err)
			}
			h.setCore(nil, nil)
			tc.stop(h)
			if tc.check {
				h.a.check(context.Background())
				expectDone(t, l, tc.name)
			}
			if err := s.WritePacket(packet("fd00:10::5")); !errors.Is(err, errStopped) {
				t.Fatalf("after %s, WritePacket = %v, want %v", tc.name, err, errStopped)
			}
		})
	}
}

// TestFullDeviceDropsPackets fills the device and checks that the request
// counts the drops and keeps forwarding.
func TestFullDeviceDropsPackets(t *testing.T) {
	h := newHarness(t)
	h.start()
	l := h.admit(credA1)
	defer func() { _ = l.Close() }()
	s, err := h.a.Open(context.Background(), l.Info())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	pkt := packet("fd00:10::5")
	for range 10000 {
		if err := s.WritePacket(pkt); err != nil {
			t.Fatalf("a full device ended the request: %v", err)
		}
		if l.(*session).drops.Load() > 0 {
			break
		}
	}
	if l.(*session).drops.Load() == 0 {
		t.Fatal("the device never filled")
	}
	expectLive(t, l, "a full device")
}

// TestIdleAttachmentDeleted checks that an attachment left with no request
// is deleted after the idle period, and one in use is kept.
func TestIdleAttachmentDeleted(t *testing.T) {
	h := newHarness(t)
	h.start()
	la, lb := h.admit(credA1), h.admit("cred-b")
	defer func() { _ = lb.Close() }()
	_ = la.Close()
	h.clock.advance(2 * time.Minute)
	h.a.check(context.Background())
	var att galacticv1alpha1.EdgeAttachment
	err := h.c.Get(context.Background(), client.ObjectKey{Namespace: testNS,
		Name: provider.AttachmentName(svcA.UID, testPod)}, &att)
	if err == nil {
		t.Fatal("the idle attachment was kept")
	}
	if b := h.attachment(svcB); b.DeletionTimestamp != nil {
		t.Fatal("the attachment in use was deleted")
	}
	expectLive(t, lb, "deleting another service's idle attachment")
}

// TestRestartAdoptsOwnAttachments starts a second process of the same pod:
// it adopts that pod's attachments, leaves other pods' alone, serves an
// adopted attachment on request and deletes the others once idle.
func TestRestartAdoptsOwnAttachments(t *testing.T) {
	h := newHarness(t)
	h.start()
	la, lb := h.admit(credA1), h.admit("cred-b")
	other := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS,
		Name: provider.AttachmentName(svcA.UID, "pod-uid-2")}}
	other.Spec.PodUID, other.Spec.ServiceRef.UID = "pod-uid-2", svcA.UID
	if err := h.c.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	// The first process dies without shutting down.
	_, _ = la, lb

	h2 := &harness{t: t, c: h.c, clock: h.clock, now: h.now, hosts: map[string]*os.File{}, leaseEpoch: 4}
	h2.programAttachment, h2.acceptRoute = h2.programmed, h2.accepted
	h2.start()
	if n := len(h2.a.attachments); n != 2 {
		t.Fatalf("adopted %d attachments, want the pod's 2", n)
	}
	for _, svc := range []ServiceRef{svcA, svcB} {
		if got := ready(h2.attachment(svc)); got != metav1.ConditionFalse {
			t.Fatalf("adopted attachment of %s reports Ready=%q before it is served again", svc.Name, got)
		}
	}
	l := h2.admit(credA1)
	defer func() { _ = l.Close() }()
	if l.Info().Attachment != provider.AttachmentName(svcA.UID, testPod) {
		t.Fatalf("restart served %s, not the adopted attachment", l.Info().Attachment)
	}
	if cl := h2.route(credA1).Spec.Claim; cl.InstanceEpoch != 4 {
		t.Fatalf("the restarted process forwards under a claim at lease epoch %d, want 4", cl.InstanceEpoch)
	}
	if got := ready(h2.attachment(svcA)); got != metav1.ConditionTrue {
		t.Fatalf("the adopted attachment served again reports Ready=%q", got)
	}
	h2.clock.advance(2 * time.Minute)
	h2.a.check(context.Background())
	var att galacticv1alpha1.EdgeAttachment
	err := h.c.Get(context.Background(), client.ObjectKey{Namespace: testNS,
		Name: provider.AttachmentName(svcB.UID, testPod)}, &att)
	if err == nil {
		t.Fatal("the unused adopted attachment was kept")
	}
	if err := h.c.Get(context.Background(), client.ObjectKeyFromObject(other), &att); err != nil {
		t.Fatalf("another pod's attachment was touched: %v", err)
	}
	if a := h2.attachment(svcA); a.DeletionTimestamp != nil {
		t.Fatal("the adopted attachment in use was deleted")
	}
}

// TestShutdownReleasesInOrder checks that shutdown ends every request
// before releasing its claim, then deletes the attachment, then releases the
// lease, and that nothing fails.
func TestShutdownReleasesInOrder(t *testing.T) {
	h := newHarness(t)
	h.start()
	l := h.admit(credA1)
	s, err := h.a.Open(context.Background(), l.Info())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := h.a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectDone(t, l, "shutdown")
	if err := s.WritePacket(packet("fd00:10::5")); !errors.Is(err, errStopped) {
		t.Fatalf("after shutdown, WritePacket = %v", err)
	}
	h.mu.Lock()
	calls := strings.Join(h.calls, ", ")
	h.mu.Unlock()
	if want := "claim released, attachment deleted, lease released"; calls != want {
		t.Fatalf("shutdown did %q, want %q", calls, want)
	}
	if _, err := h.a.Admit(context.Background(), credA1, testVPCName); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Admit after shutdown = %v", err)
	}
}

// TestConcurrentRequestsOfOneConnector admits several requests of one
// connector at once: exactly one is admitted, the rest are refused.
func TestConcurrentRequestsOfOneConnector(t *testing.T) {
	h := newHarness(t)
	h.start()
	const n = 8
	type result struct {
		l   connectip.Lease
		err error
	}
	results := make(chan result, n)
	for range n {
		go func() {
			l, err := h.a.Admit(context.Background(), credA1, testVPCName)
			results <- result{l, err}
		}()
	}
	admitted := 0
	for range n {
		r := <-results
		switch {
		case r.err == nil:
			admitted++
			defer func() { _ = r.l.Close() }()
		case !errors.Is(r.err, ErrUnavailable) || !strings.Contains(r.err.Error(), "already has an open request"):
			t.Errorf("concurrent request: %v", r.err)
		}
	}
	if admitted != 1 {
		t.Fatalf("%d concurrent requests of one connector were admitted, want 1", admitted)
	}
}

// TestDeleteLeavesForeignReplacement deletes an idle attachment whose name
// another pod's object now holds: the object is left alone and the adapter
// stops tracking the name.
func TestDeleteLeavesForeignReplacement(t *testing.T) {
	h := newHarness(t)
	h.start()
	name := provider.AttachmentName(svcA.UID, testPod)
	foreign := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name}}
	foreign.Spec.PodUID, foreign.Spec.ServiceRef.UID = "pod-uid-2", svcA.UID
	if err := h.c.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	e := &attachment{svc: svcA, name: name, uid: "stale-uid", prep: newPrepLock()}
	h.a.mu.Lock()
	h.a.attachments[svcA.UID] = e
	h.a.mu.Unlock()
	if err := h.a.deleteAttachment(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if _, tracked := h.a.attachments[svcA.UID]; tracked {
		t.Fatal("the adapter still tracks a name another pod's object holds")
	}
	var cur galacticv1alpha1.EdgeAttachment
	if err := h.c.Get(context.Background(), client.ObjectKeyFromObject(foreign), &cur); err != nil {
		t.Fatalf("another pod's attachment was removed: %v", err)
	}
}

// TestNoAttachmentAfterShutdown checks that a preparation still running when
// Shutdown starts requests no attachment.
func TestNoAttachmentAfterShutdown(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.a.mu.Lock()
	h.a.closing = true
	h.a.mu.Unlock()
	g := grants[credA1]
	e := &attachment{svc: svcA, name: provider.AttachmentName(svcA.UID, testPod), prep: newPrepLock()}
	if _, err := h.a.prepareOnce(context.Background(), e, &g); err == nil {
		t.Fatal("a preparation after shutdown started went on")
	}
	var list galacticv1alpha1.EdgeAttachmentList
	if err := h.c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatal("an attachment was requested after shutdown started")
	}
}

// TestShutdownStopsPreparation shuts down while a request waits for its
// attachment to be programmed: the request gives up at once, and the
// attachment it requested is deleted with the rest.
func TestShutdownStopsPreparation(t *testing.T) {
	h := newHarness(t)
	h.programAttachment = nil
	h.start()
	h.a.cfg.Prepare = time.Minute
	admitted := make(chan error, 1)
	go func() {
		_, err := h.a.Admit(context.Background(), credA1, testVPCName)
		admitted <- err
	}()
	waitFor(t, "the request to request its attachment", func() bool {
		var list galacticv1alpha1.EdgeAttachmentList
		return h.c.List(context.Background(), &list) == nil && len(list.Items) == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := h.a.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("shutdown waited %v for the preparation", d)
	}
	if err := <-admitted; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("request prepared across shutdown = %v, want unavailable", err)
	}
	var list galacticv1alpha1.EdgeAttachmentList
	if err := h.c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatal("shutdown left the attachment the interrupted request asked for")
	}
}

// TestAdoptTerminatingAttachment restarts with an attachment of the pod
// that is being deleted: the process adopts it without marking it, a request
// waits for its release, and once it is gone the next request gets a new
// attachment.
func TestAdoptTerminatingAttachment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	name := provider.AttachmentName(svcA.UID, testPod)
	old := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name,
		Finalizers: []string{galacticv1alpha1.EdgeAttachmentFinalizer}}}
	old.Spec.PodUID, old.Spec.ServiceRef = testPod, galacticv1alpha1.EdgeServiceReference{
		Namespace: svcA.Namespace, Name: svcA.Name, UID: svcA.UID}
	old.Spec.ProviderRef.Name, old.Spec.InstanceRef.Name = coreProvider, provider.InstanceName(testPod)
	if err := h.c.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := h.c.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	h.start()
	if _, adopted := h.a.attachments[svcA.UID]; !adopted {
		t.Fatal("the terminating attachment was not adopted")
	}
	if got := ready(h.attachment(svcA)); got != "" {
		t.Fatalf("the terminating attachment was marked Ready=%q", got)
	}
	h.a.cfg.Prepare = 200 * time.Millisecond
	if _, err := h.a.Admit(ctx, credA1, testVPCName); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "being released") {
		t.Fatalf("request while the attachment is released = %v, want a wait for its release", err)
	}
	cur := h.attachment(svcA)
	cur.Finalizers = nil
	if err := h.c.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	h.a.cfg.Prepare = 2 * time.Second
	l := h.admit(credA1)
	defer func() { _ = l.Close() }()
	if att := h.attachment(svcA); att.UID == old.UID {
		t.Fatal("the request was served on the released attachment")
	}
}
