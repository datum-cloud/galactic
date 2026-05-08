// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconciler

import (
	"context"
	"net"
	"sync"
	"testing"

	agentbgp "go.datum.net/galactic/internal/agent/bgp"
	agentcache "go.datum.net/galactic/internal/agent/cache"
)

// fakeBGP records originate/withdraw calls and lets the test answer
// "did the reconciler advertise this prefix yet?".
type fakeBGP struct {
	mu        sync.Mutex
	origCalls []agentbgp.PathKey
	withdraws []agentbgp.PathKey
	failNext  error
}

func (f *fakeBGP) Originate(_ context.Context, key agentbgp.PathKey, _ *net.IPNet, _, _ string, _, _ net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.origCalls = append(f.origCalls, key)
	return nil
}

func (f *fakeBGP) Withdraw(_ context.Context, key agentbgp.PathKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdraws = append(f.withdraws, key)
	return nil
}

// fakeEgress records kernel egress route calls. Records the (vpcHex,
// attachHex, prefix) tuple — a regression in the hex/base62 boundary
// would surface here as "egress called with base62 instead of hex," not
// as a silent kernel miss.
type fakeEgress struct {
	mu      sync.Mutex
	added   []egressCall
	deleted []egressCall
}

type egressCall struct {
	vpcHex, attachHex, prefix string
}

func (f *fakeEgress) Add(vpcHex, attachHex string, prefix *net.IPNet, _ []net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, egressCall{vpcHex, attachHex, prefix.String()})
	return nil
}

func (f *fakeEgress) Delete(vpcHex, attachHex string, prefix *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, egressCall{vpcHex, attachHex, prefix.String()})
	return nil
}

// fakeIngress records routeingress.Add/Delete calls and asserts that
// the strings reaching it are base62 (the kernel-facing form). This is
// the regression guard for the hex→base62 boundary on the ingress
// side.
type fakeIngress struct {
	mu       sync.Mutex
	addCalls []ingressCall
	delCalls []ingressCall
}

type ingressCall struct {
	sid               string
	vpcB62, attachB62 string
}

func (f *fakeIngress) Add(sid *net.IPNet, vpcB62, attachB62 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls = append(f.addCalls, ingressCall{sid.IP.String(), vpcB62, attachB62})
	return nil
}

func (f *fakeIngress) Delete(sid *net.IPNet, vpcB62, attachB62 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCalls = append(f.delCalls, ingressCall{sid.IP.String(), vpcB62, attachB62})
	return nil
}

// fakeCache lets a test toggle a (vpcHex, attachHex) attachment's
// readiness on demand, simulating the informer.
type fakeCache struct {
	mu    sync.Mutex
	byKey map[[2]string]agentcache.AttachmentInfo
	byRT  map[string][]agentcache.AttachmentInfo
}

func newFakeCache() *fakeCache {
	return &fakeCache{
		byKey: map[[2]string]agentcache.AttachmentInfo{},
		byRT:  map[string][]agentcache.AttachmentInfo{},
	}
}

func (f *fakeCache) put(info agentcache.AttachmentInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := [2]string{info.VPCHex, info.AttachHex}
	if prev, ok := f.byKey[k]; ok && prev.RouteTarget != info.RouteTarget {
		// rewire byRT
		for rt, list := range f.byRT {
			next := list[:0]
			for _, e := range list {
				if e.VPCHex != info.VPCHex || e.AttachHex != info.AttachHex {
					next = append(next, e)
				}
			}
			f.byRT[rt] = next
		}
	}
	f.byKey[k] = info
	if info.Ready && info.RouteTarget != "" {
		f.byRT[info.RouteTarget] = append(f.byRT[info.RouteTarget], info)
	}
}

func (f *fakeCache) drop(vpcHex, attachHex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byKey, [2]string{vpcHex, attachHex})
	for rt, list := range f.byRT {
		next := list[:0]
		for _, e := range list {
			if e.VPCHex != vpcHex || e.AttachHex != attachHex {
				next = append(next, e)
			}
		}
		f.byRT[rt] = next
	}
}

func (f *fakeCache) Lookup(vpcHex, attachHex string) (agentcache.AttachmentInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.byKey[[2]string{vpcHex, attachHex}]
	return info, ok
}

func (f *fakeCache) FindByRT(rt string) []agentcache.AttachmentInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]agentcache.AttachmentInfo(nil), f.byRT[rt]...)
}

// readyAttachment returns a fixture VPCAttachmentInfo with valid
// SID/RT/RD for a (vpcHex, attachHex) pair.
func readyAttachment(vpcHex, attachHex string, podIP string) agentcache.AttachmentInfo {
	return agentcache.AttachmentInfo{
		VPCHex:             vpcHex,
		AttachHex:          attachHex,
		ServiceSID:         "fc00::1234:5678:9abc:0",
		RouteTarget:        "65000:1",
		RouteDistinguisher: "65000:1",
		PodPrefixes:        []string{podIP + "/24"},
		Ready:              true,
		Namespace:          "default",
		Name:               "att",
	}
}

// newReconciler wires the four fakes into a Reconciler.
func newReconciler() (*Reconciler, *fakeBGP, *fakeEgress, *fakeIngress, *fakeCache) {
	bgp := &fakeBGP{}
	eg := &fakeEgress{}
	ing := &fakeIngress{}
	cc := newFakeCache()
	r := New(Config{
		BGP:      bgp,
		Egress:   eg,
		Ingress:  ing,
		Cache:    cc,
		NodeNext: net.ParseIP("2001:db8::1"),
	})
	return r, bgp, eg, ing, cc
}

// ---- Test cases ----

func TestRegisterBeforeInformer_NoOriginate(t *testing.T) {
	r, bgp, _, ing, _ := newReconciler()
	r.OnRegister(context.Background(), "00000001", "0001")
	if got := len(bgp.origCalls); got != 0 {
		t.Errorf("originate called %d times, want 0 (cache empty)", got)
	}
	if got := len(ing.addCalls); got != 0 {
		t.Errorf("ingress.Add called %d times, want 0", got)
	}
	if got := r.PendingCount(); got != 1 {
		t.Errorf("pending count = %d, want 1", got)
	}
}

func TestInformerAfterRegister_Originates(t *testing.T) {
	r, bgp, _, ing, cc := newReconciler()
	ctx := context.Background()

	r.OnRegister(ctx, "00000001", "0001")

	// Informer fires with the ready attachment.
	info := readyAttachment("00000001", "0001", "10.0.0.5")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	if got := len(bgp.origCalls); got != 1 {
		t.Fatalf("originate called %d times, want 1", got)
	}
	if got := bgp.origCalls[0].Prefix; got != "10.0.0.5/32" {
		t.Errorf("originated prefix = %q, want %q", got, "10.0.0.5/32")
	}
	if got := len(ing.addCalls); got != 1 {
		t.Fatalf("ingress.Add called %d times, want 1", got)
	}
	// Hex 00000001 -> base62 1; hex 0001 -> base62 1.
	if got := ing.addCalls[0].vpcB62; got != "1" {
		t.Errorf("ingress.Add vpcB62 = %q, want %q (regression guard for hex/base62 boundary)", got, "1")
	}
	if got := ing.addCalls[0].attachB62; got != "1" {
		t.Errorf("ingress.Add attachB62 = %q, want %q", got, "1")
	}

	// A second informer event for the same key is a no-op.
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventUpdate, Current: info})
	if got := len(bgp.origCalls); got != 1 {
		t.Errorf("re-fired informer caused %d originate calls, want 1 (idempotent)", got)
	}
	if got := len(ing.addCalls); got != 1 {
		t.Errorf("re-fired informer caused %d ingress adds, want 1", got)
	}
}

func TestInformerBeforeRegister_NoOriginateUntilRegister(t *testing.T) {
	r, bgp, _, _, cc := newReconciler()
	ctx := context.Background()

	info := readyAttachment("00000002", "0002", "10.0.0.6")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	if got := len(bgp.origCalls); got != 0 {
		t.Errorf("originate called %d times before register, want 0", got)
	}

	r.OnRegister(ctx, "00000002", "0002")
	if got := len(bgp.origCalls); got != 1 {
		t.Errorf("originate after register: %d, want 1", got)
	}
}

func TestDeregisterBeforeInformer_NoLeak(t *testing.T) {
	r, bgp, eg, ing, _ := newReconciler()
	ctx := context.Background()

	r.OnRegister(ctx, "00000003", "0003")
	r.OnDeregister(ctx, "00000003", "0003")

	if got := len(bgp.origCalls); got != 0 {
		t.Errorf("originate called %d, want 0", got)
	}
	if got := len(bgp.withdraws); got != 0 {
		t.Errorf("withdraw called %d (nothing to withdraw), want 0", got)
	}
	if got := len(ing.delCalls); got != 0 {
		t.Errorf("ingress.Delete called %d (nothing installed), want 0", got)
	}
	if got := len(eg.deleted); got != 0 {
		t.Errorf("egress.Delete called %d (nothing programmed), want 0", got)
	}
	if got := r.PendingCount(); got != 0 {
		t.Errorf("pending entry remained after deregister, want 0")
	}
}

func TestDeregisterAfterOriginate_FullTeardown(t *testing.T) {
	r, bgp, eg, ing, cc := newReconciler()
	ctx := context.Background()

	r.OnRegister(ctx, "00000004", "0004")
	info := readyAttachment("00000004", "0004", "10.0.0.7")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	// Simulate a remote UPDATE that matched this RT, so we have
	// kernel egress state to tear down too.
	prefix := mustParseCIDR("10.0.1.99/32")
	r.handleReceivedRoute(ctx, agentbgp.ReceivedRoute{
		Prefix: prefix, RouteDistinguisher: "65000:99",
		RouteTargets: []string{"65000:1"},
		ServiceSID:   net.ParseIP("fc00::dead:beef:0:0"),
	})

	r.OnDeregister(ctx, "00000004", "0004")

	if got := len(bgp.withdraws); got != 1 {
		t.Errorf("withdraw count = %d, want 1", got)
	}
	if got := len(ing.delCalls); got != 1 {
		t.Fatalf("ingress.Delete count = %d, want 1", got)
	}
	// Regression guard for the OnDeregister bug previously in the
	// plan: the first arg must be the SERVICE SID, not the pod prefix.
	if got := ing.delCalls[0].sid; got != "fc00::1234:5678:9abc:0" {
		t.Errorf("ingress.Delete sid = %q, want service SID, not pod prefix", got)
	}
	// programmedKernel-driven teardown.
	if got := len(eg.deleted); got != 1 {
		t.Errorf("egress.Delete count = %d, want 1 (programmedKernel-driven)", got)
	}
	if got := eg.deleted[0].prefix; got != "10.0.1.99/32" {
		t.Errorf("egress.Delete prefix = %q, want %q", got, "10.0.1.99/32")
	}
}

func TestStatusGoesAway_TearsDownButKeepsPending(t *testing.T) {
	r, bgp, eg, ing, cc := newReconciler()
	ctx := context.Background()

	r.OnRegister(ctx, "00000005", "0005")
	info := readyAttachment("00000005", "0005", "10.0.0.8")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	// Simulate a received route programmed into this attachment.
	prefix := mustParseCIDR("10.0.2.50/32")
	r.handleReceivedRoute(ctx, agentbgp.ReceivedRoute{
		Prefix: prefix, RouteDistinguisher: "65000:50",
		RouteTargets: []string{"65000:1"},
		ServiceSID:   net.ParseIP("fc00::aaaa:bbbb:0:0"),
	})

	// Status goes away. Tombstone delivers the last-known info; the
	// reconciler tears down active/ingress/programmedKernel but
	// keeps pending in place.
	cc.drop("00000005", "0005")
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventDelete, Current: info})

	if got := len(bgp.withdraws); got != 1 {
		t.Errorf("withdraw count = %d, want 1", got)
	}
	if got := len(ing.delCalls); got != 1 {
		t.Errorf("ingress.Delete count = %d, want 1 (SID-from-ingress)", got)
	}
	if got := len(eg.deleted); got != 1 {
		t.Errorf("egress.Delete count = %d, want 1", got)
	}
	if got := r.PendingCount(); got != 1 {
		t.Errorf("pending count = %d, want 1 (kept across status loss)", got)
	}
}

func TestReceivedRouteWithoutLocalAttachment_FilesAndReplaysOnReady(t *testing.T) {
	r, _, eg, _, cc := newReconciler()
	ctx := context.Background()

	// Receive a route before the local attachment has materialized.
	prefix := mustParseCIDR("10.0.3.7/32")
	r.handleReceivedRoute(ctx, agentbgp.ReceivedRoute{
		Prefix: prefix, RouteDistinguisher: "65000:7",
		RouteTargets: []string{"65000:1"},
		ServiceSID:   net.ParseIP("fc00::cafe:beef:0:0"),
	})
	if got := len(eg.added); got != 0 {
		t.Errorf("egress.Add fired with no local attachment: %d, want 0", got)
	}

	// Local attachment materializes; reconciler replays.
	info := readyAttachment("00000006", "0006", "10.0.0.9")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	if got := len(eg.added); got != 1 {
		t.Errorf("egress.Add after replay: %d, want 1", got)
	}
}

func TestReceivedWithdraw_RemovesEntryAndKernel(t *testing.T) {
	r, _, eg, _, cc := newReconciler()
	ctx := context.Background()

	info := readyAttachment("00000007", "0007", "10.0.0.10")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	prefix := mustParseCIDR("10.0.4.5/32")
	r.handleReceivedRoute(ctx, agentbgp.ReceivedRoute{
		Prefix: prefix, RouteDistinguisher: "65000:5",
		RouteTargets: []string{"65000:1"},
		ServiceSID:   net.ParseIP("fc00::dead:0:0:0"),
	})
	if got := len(eg.added); got != 1 {
		t.Fatalf("expected 1 add, got %d", got)
	}

	r.handleReceivedRoute(ctx, agentbgp.ReceivedRoute{
		Prefix: prefix, RouteDistinguisher: "65000:5",
		RouteTargets: []string{"65000:1"},
		IsWithdraw:   true,
	})
	if got := len(eg.deleted); got != 1 {
		t.Errorf("expected 1 delete, got %d", got)
	}
	// receivedRoutes must have lost the entry.
	r.mu.Lock()
	_, stillThere := r.receivedRoutes[receivedKey{prefix.String(), "65000:5"}]
	r.mu.Unlock()
	if stillThere {
		t.Errorf("receivedRoutes retained the WITHDRAW entry; should be gone")
	}
}

func TestSessionEstablished_ReoriginatesActive(t *testing.T) {
	r, bgp, _, _, cc := newReconciler()
	ctx := context.Background()

	r.OnRegister(ctx, "00000008", "0008")
	info := readyAttachment("00000008", "0008", "10.0.0.11")
	cc.put(info)
	r.handleAttachmentEvent(ctx, agentcache.Event{Type: agentcache.EventAdd, Current: info})

	if got := len(bgp.origCalls); got != 1 {
		t.Fatalf("setup: originate count = %d, want 1", got)
	}

	// Simulate a session flap: state goes Established again. Reconciler
	// re-issues every active path. The fake BGP records each call;
	// after replay we should see the originate count double.
	r.handleSession(ctx, agentbgp.SessionEvent{State: agentbgp.SessionStateEstablished})

	if got := len(bgp.origCalls); got != 2 {
		t.Errorf("originate count after replay = %d, want 2 (replay re-issued)", got)
	}
}
