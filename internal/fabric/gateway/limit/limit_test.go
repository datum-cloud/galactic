// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/fabric/errcode"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const (
	leaseNS   = "ns"
	leaseName = "lease"
	holderA   = "gw-a_1"
)

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if got := errcode.Of(err); got != code {
		t.Fatalf("code = %q (%v), want %q", got, err, code)
	}
}

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Limits){
		"zero rate":            func(l *Limits) { l.PacketCell.PerSecond = 0 },
		"NaN rate":             func(l *Limits) { l.PacketCell.PerSecond = math.NaN() },
		"infinite rate":        func(l *Limits) { l.PacketHost.PerSecond = math.Inf(1) },
		"negative burst":       func(l *Limits) { l.RequestCell.Burst = -1 },
		"burst over 120 s":     func(l *Limits) { l.PacketHost = Rate{PerSecond: 1, Burst: 121} },
		"short burst":          func(l *Limits) { l.PacketPrefix.Burst = 19 },
		"project above cell":   func(l *Limits) { l.RequestProject.Burst = 9 },
		"principal above cell": func(l *Limits) { l.PacketPrincipal.PerSecond = 101 },
		"slots above max":      func(l *Limits) { l.Slots = 9 },
		"principal slots":      func(l *Limits) { l.PrincipalSlots = 9 },
		"queue above max":      func(l *Limits) { l.Queue = 257 },
		"principal queue":      func(l *Limits) { l.Queue, l.PrincipalQueue = 16, 32 },
		"streams":              func(l *Limits) { l.ProjectStreams = 17 },
		"project keys":         func(l *Limits) { l.ProjectKeys = MaxProjectKeys + 1 },
		"destination keys":     func(l *Limits) { l.DestinationKeys = 0 },
		"attempt bytes":        func(l *Limits) { l.AttemptBytes = MaxAttemptBytes + 1 },
		"queue wait":           func(l *Limits) { l.QueueWait = 11 * time.Second },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			l := Defaults()
			mod(&l)
			if err := l.Validate(); err == nil {
				t.Fatal("invalid limits accepted")
			}
		})
	}
}

func TestBucketsStartEmptyAndRefill(t *testing.T) {
	b := NewBuckets(Defaults(), t0)
	// Project: 0.2/s, burst 2. Nothing at the reset instant.
	err := b.ChargeRequest("p", t0)
	wantCode(t, err, errcode.Throttled)
	if d, _ := errcode.RetryDelay(err); d != 5*time.Second {
		t.Fatalf("retry = %s, want 5s (1 token at 0.2/s)", d)
	}
	md := errcode.Metadata(err)
	if md[errcode.MetadataScope] != "project" || md[errcode.MetadataExecutionStarted] != "false" {
		t.Fatalf("metadata = %v", md)
	}
	// A refused charge debits nothing, the cell bucket included.
	if err := b.ChargeRequest("p", t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.ChargeRequest("p", t0.Add(10*time.Second)); err != nil {
		t.Fatalf("second token: %v", err)
	}
	wantCode(t, b.ChargeRequest("p", t0.Add(10*time.Second)), errcode.Throttled)
	// Another project is independent, but shares the cell's 2/s.
	if err := b.ChargeRequest("q", t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestBucketsRetryIsLargestDeficit(t *testing.T) {
	b := NewBuckets(Defaults(), t0)
	dst := netip.MustParseAddr("192.0.2.10")
	// At 1 s: cell 100, principal 20, host 20, prefix 40. A traceroute (20)
	// fits once; then host and principal are 20 short (1 s at 20/s) and
	// prefix 0 short.
	now := t0.Add(time.Second)
	if err := b.ChargePackets("p", dst, TraceroutePackets, now); err != nil {
		t.Fatal(err)
	}
	err := b.ChargePackets("p", dst, TraceroutePackets, now)
	wantCode(t, err, errcode.Throttled)
	if d, _ := errcode.RetryDelay(err); d != time.Second {
		t.Fatalf("retry = %s, want 1s", d)
	}
	// Another host in the same /24 under another principal draws on the
	// prefix's remaining 20.
	if err := b.ChargePackets("q", netip.MustParseAddr("192.0.2.11"), TraceroutePackets, now); err != nil {
		t.Fatal(err)
	}
	err = b.ChargePackets("r", netip.MustParseAddr("192.0.2.12"), TraceroutePackets, now)
	wantCode(t, err, errcode.Throttled)
	if errcode.Metadata(err)[errcode.MetadataScope] != "destination" {
		t.Fatalf("scope = %v, want destination", errcode.Metadata(err))
	}
}

func TestDestinationKeys(t *testing.T) {
	for in, want := range map[string][2]string{
		"192.0.2.10":         {"192.0.2.10/32", "192.0.2.0/24"},
		"::ffff:192.0.2.10":  {"192.0.2.10/32", "192.0.2.0/24"},
		"2001:db8:1:2:3::4":  {"2001:db8:1:2:3::4/128", "2001:db8:1:2::/64"},
		"2001:db8::1":        {"2001:db8::1/128", "2001:db8::/64"},
		"2001:db8:0:ffff::1": {"2001:db8:0:ffff::1/128", "2001:db8:0:ffff::/64"},
	} {
		h, p := DestinationKeys(netip.MustParseAddr(in))
		if h != want[0] || p != want[1] {
			t.Errorf("%s: %s %s, want %v", in, h, p, want)
		}
	}
}

func TestBucketsKeyBoundNeverEvictsDebt(t *testing.T) {
	l := Defaults()
	l.ProjectKeys = 2
	b := NewBuckets(l, t0)
	now := t0.Add(time.Minute)
	for _, p := range []string{"a", "b"} {
		if err := b.ChargeRequest(p, now); err != nil {
			t.Fatal(err)
		}
	}
	// Both keys are refilling: a third is refused rather than evicting one.
	wantCode(t, b.ChargeRequest("c", now), errcode.LimiterUnavailable)
	if p, _ := b.Keys(); p != 2 {
		t.Fatalf("project keys = %d", p)
	}
	// Once "a" and "b" have refilled (1 token at 0.2/s = 5 s), one is
	// discarded for "c".
	later := now.Add(5 * time.Second)
	if err := b.ChargeRequest("c", later); err != nil {
		t.Fatalf("after refill: %v", err)
	}
	if p, _ := b.Keys(); p != 2 {
		t.Fatalf("project keys = %d", p)
	}
}

func TestBucketsReset(t *testing.T) {
	b := NewBuckets(Defaults(), t0)
	now := t0.Add(time.Hour)
	if err := b.ChargeRequest("p", now); err != nil {
		t.Fatal(err)
	}
	b.Reset(now)
	wantCode(t, b.ChargeRequest("p", now), errcode.Throttled)
}

// TestPacketEnvelope charges a fan-out of mixed projects and hosts in one
// prefix every 100 ms for a minute and checks that, for every window of
// length T, the prefix bucket admitted at most burst + rate × T packets.
func TestPacketEnvelope(t *testing.T) {
	l := Defaults()
	b := NewBuckets(l, t0)
	type charge struct {
		at time.Time
		n  int
	}
	var admitted []charge
	for i := range 600 {
		now := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		for j := range 8 {
			dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(j)})
			if b.ChargePackets(fmt.Sprintf("project-%d", (i+j)%5), dst, TraceroutePackets, now) == nil {
				admitted = append(admitted, charge{now, TraceroutePackets})
			}
		}
	}
	r := l.PacketPrefix
	for i := range admitted {
		sum := 0
		for j := i; j < len(admitted); j++ {
			sum += admitted[j].n
			window := admitted[j].at.Sub(admitted[i].at).Seconds()
			if float64(sum) > r.Burst+r.PerSecond*window+1e-9 {
				t.Fatalf("%d packets in %.1f s exceeds %g + %g×T", sum, window, r.Burst, r.PerSecond)
			}
		}
	}
	if len(admitted) == 0 {
		t.Fatal("nothing admitted")
	}
}

func TestAttempts(t *testing.T) {
	l := Defaults()
	l.Attempts = 2
	a := NewAttempts(l)
	exp := t0.Add(30 * time.Second)
	if err := a.Register("k1", "d1", exp, t0); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.Register("k1", "d1", exp, t0), errcode.DuplicateRequest)
	wantCode(t, a.Register("k1", "d2", exp, t0), errcode.DuplicateConflict)
	if err := a.Register("k2", "d", exp, t0); err != nil {
		t.Fatal(err)
	}
	// Full of live keys: fail closed.
	wantCode(t, a.Register("k3", "d", exp, t0), errcode.LimiterUnavailable)
	// A key lives until expiry + 2 s.
	wantCode(t, a.Register("k1", "d1", exp, exp.Add(time.Second)), errcode.DuplicateRequest)
	if err := a.Register("k3", "d", exp.Add(time.Minute), exp.Add(AttemptGrace)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if a.Len() != 1 {
		t.Fatalf("len = %d after purge", a.Len())
	}
}

func TestAttemptsByteBound(t *testing.T) {
	l := Defaults()
	l.AttemptBytes = 200
	a := NewAttempts(l)
	exp := t0.Add(time.Minute)
	if err := a.Register(strings.Repeat("k", 100), "d", exp, t0); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.Register(strings.Repeat("j", 100), "d", exp, t0), errcode.LimiterUnavailable)
}

// leaseClient serves the election Lease and can fail its reads.
type leaseClient struct {
	client.Client
	fail bool
}

func newLease(t *testing.T, holder string, renew time.Time) *leaseClient {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	lc := &leaseClient{}
	lc.Client = fake.NewClientBuilder().WithScheme(s).WithObjects(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName, UID: "u1"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: ptr.To(holder), LeaseDurationSeconds: ptr.To[int32](15),
			RenewTime: &metav1.MicroTime{Time: renew},
		},
	}).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			if lc.fail {
				return errors.New("api unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	return lc
}

// set replaces the Lease with one of uid held by holderA, renewed at renew.
func (lc *leaseClient) set(t *testing.T, uid string, renew time.Time) {
	t.Helper()
	old := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName}}
	if err := lc.Delete(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := lc.Create(t.Context(), &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: leaseNS, Name: leaseName, UID: types.UID(uid)},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: ptr.To(holderA), LeaseDurationSeconds: ptr.To[int32](15),
			RenewTime: &metav1.MicroTime{Time: renew},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func TestAuthorityRecoveryHold(t *testing.T) {
	clk := &clock{now: t0}
	lc := newLease(t, holderA, t0)
	buckets := NewBuckets(Defaults(), t0.Add(-time.Hour))
	a := &Authority{Reader: lc, Namespace: leaseNS, Name: leaseName, Identity: holderA, Buckets: buckets, Now: clk.Now}

	// Process start: held for the full 125 s.
	_, _, err := a.Check(t.Context())
	wantCode(t, err, errcode.LimiterUnavailable)
	if d, _ := errcode.RetryDelay(err); d != RecoveryHold {
		t.Fatalf("remaining hold = %s", d)
	}
	clk.now = t0.Add(RecoveryHold - time.Millisecond)
	lc.set(t, "u1", clk.now)
	_, _, err = a.Check(t.Context())
	wantCode(t, err, errcode.LimiterUnavailable)

	// After the hold: admitted, and the buckets restart empty from now.
	clk.now = t0.Add(RecoveryHold)
	lc.set(t, "u1", clk.now)
	epoch, ctx, err := a.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if epoch.String() != "u1/gw-a_1" {
		t.Fatalf("epoch = %s", epoch)
	}
	wantCode(t, buckets.ChargeRequest("p", clk.now), errcode.Throttled)

	// A failed read refuses, cancels the epoch's work, and the next valid
	// read holds again.
	lc.fail = true
	_, _, err = a.Check(t.Context())
	wantCode(t, err, errcode.OwnershipLost)
	if ctx.Err() == nil {
		t.Fatal("epoch context survived a failed lease read")
	}
	lc.fail = false
	_, _, err = a.Check(t.Context())
	wantCode(t, err, errcode.LimiterUnavailable)
}

func TestAuthorityRefusesOtherHolderAndExpiry(t *testing.T) {
	clk := &clock{now: t0}
	lc := newLease(t, "gw-b_2", t0)
	a := &Authority{Reader: lc, Namespace: leaseNS, Name: leaseName, Identity: holderA,
		Buckets: NewBuckets(Defaults(), t0), Now: clk.Now, Hold: time.Second}
	_, _, err := a.Check(t.Context())
	wantCode(t, err, errcode.OwnershipLost)

	lc.set(t, "u1", t0)
	if _, _, err := a.Check(t.Context()); errcode.Of(err) != errcode.LimiterUnavailable {
		t.Fatalf("first check: %v", err)
	}
	clk.now = t0.Add(time.Second)
	_, ctx, err := a.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The term lapses without renewal.
	clk.now = t0.Add(16 * time.Second)
	_, _, err = a.Check(t.Context())
	wantCode(t, err, errcode.OwnershipLost)
	if ctx.Err() == nil {
		t.Fatal("epoch context survived an expired lease")
	}
}

func TestAuthorityNewEpochHolds(t *testing.T) {
	clk := &clock{now: t0}
	lc := newLease(t, holderA, t0)
	a := &Authority{Reader: lc, Namespace: leaseNS, Name: leaseName, Identity: holderA,
		Buckets: NewBuckets(Defaults(), t0), Now: clk.Now, Hold: time.Second}
	_, _, _ = a.Check(t.Context())
	clk.now = t0.Add(time.Second)
	lc.set(t, "u1", clk.now)
	_, ctx, err := a.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The Lease is recreated under the same holder: a new epoch.
	lc.set(t, "u2", clk.now)
	_, _, err = a.Check(t.Context())
	wantCode(t, err, errcode.LimiterUnavailable)
	if ctx.Err() == nil {
		t.Fatal("old epoch's context survived a new epoch")
	}
}

// A caller that gives up during the Lease read is refused for itself
// alone: the authority stays active and its epoch's work keeps running.
func TestAuthorityIgnoresCallerCancellation(t *testing.T) {
	clk := &clock{now: t0}
	lc := newLease(t, holderA, t0)
	var block chan struct{}
	reader := interceptor.NewClient(lc.Client.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			if block != nil {
				<-block
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	a := &Authority{Reader: reader, Namespace: leaseNS, Name: leaseName, Identity: holderA,
		Buckets: NewBuckets(Defaults(), t0), Now: clk.Now, Hold: time.Second}
	_, _, _ = a.Check(t.Context())
	clk.now = t0.Add(time.Second)
	_, epochCtx, err := a.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	block = make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := a.Check(ctx)
		done <- err
	}()
	cancel()
	time.Sleep(10 * time.Millisecond)
	close(block)
	wantCode(t, <-done, errcode.Cancelled)
	if epochCtx.Err() != nil {
		t.Fatal("a caller's cancellation cancelled the epoch's work")
	}
	if _, _, err := a.Check(t.Context()); err != nil {
		t.Fatalf("authority left its active state: %v", err)
	}
}
