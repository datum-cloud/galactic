// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
)

var errSidecarReturnTest = errors.New("test failure")

// The operations_total results.
const (
	opSuccess = "success"
	opError   = "error"
)

// fakeSidecarReturn stands in for the pinned maps: it fails the install of
// any endpoint whose address is in failAddrs.
type fakeSidecarReturn struct {
	failAddrs map[string]bool
	installed []string
}

func (f *fakeSidecarReturn) install(_ uint64, e sidecarEndpoint) error {
	if f.failAddrs[e.addr.String()] {
		return errSidecarReturnTest
	}
	f.installed = append(f.installed, e.addr.String())
	return nil
}

func (f *fakeSidecarReturn) Close() error { return nil }

// sidecarReturnHarness replaces the datapath half of a pass for one test.
type sidecarReturnHarness struct {
	dp          *fakeSidecarReturn
	registerErr error
	pruneErr    error
}

func newSidecarReturnHarness(t *testing.T) *sidecarReturnHarness {
	t.Helper()
	h := &sidecarReturnHarness{dp: &fakeSidecarReturn{failAddrs: map[string]bool{}}}
	open, prune := openSidecarReturnDatapath, pruneSidecarReturnRoutesFn
	t.Cleanup(func() { openSidecarReturnDatapath, pruneSidecarReturnRoutesFn = open, prune })
	openSidecarReturnDatapath = func(uint64, uint16) (sidecarReturnDatapath, error) {
		if h.registerErr != nil {
			return nil, h.registerErr
		}
		return h.dp, nil
	}
	pruneSidecarReturnRoutesFn = func(map[uint32]netip.Addr) error { return h.pruneErr }
	return h
}

// sidecarReturnClient holds BGPRouters and advertisements together, and
// fails every List when listErr is set.
func sidecarReturnClient(t *testing.T, listErr error, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...)
	if listErr != nil {
		b = b.WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return listErr
			},
		})
	}
	return b.Build()
}

const (
	testReturnAddr2 = "fd30:e2e:3a5:6094::2"
	testReturnAddr3 = "fd30:e2e:3a5:6094::3"
)

func twoGatewayAdvs() []client.Object {
	return []client.Object{
		gatewayAdv("2", testSidecarNode, testReturnAddr2+"/128", 2),
		gatewayAdv("3", testSidecarNode, testReturnAddr3+"/128", 3),
	}
}

// sidecarReturnSeries reads one series back from reg's text exposition.
func sidecarReturnSeries(t *testing.T, reg *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "galactic_sidecar_return_"+name {
			continue
		}
	next:
		for _, m := range f.GetMetric() {
			for i := 0; i+1 < len(labels); i += 2 {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == labels[i] && lp.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue next
				}
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue()
			}
			return m.GetCounter().GetValue()
		}
	}
	t.Fatalf("no series galactic_sidecar_return_%s%v", name, labels)
	return 0
}

// TestSidecarReturnPassAccounting: each pass's result and endpoint counts
// come from what actually happened to each endpoint, not from the pass's
// error alone.
func TestSidecarReturnPassAccounting(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return at }
	withRouter := append(twoGatewayAdvs(), router(testSidecarNode, testLocator, 6))

	for _, tc := range []struct {
		name                           string
		objs                           []client.Object
		setup                          func(*sidecarReturnHarness)
		wantErr                        bool
		result                         string
		desired, applied               float64
		installs, installErrs, regErrs float64
		pruneErrs                      float64
	}{
		{name: "no advertisements", result: metrics.SidecarReturnSuccess},
		{name: "no node identity yet", objs: twoGatewayAdvs(),
			result: metrics.SidecarReturnWaitingIdentity, desired: 2},
		{name: "all installed", objs: withRouter,
			result: metrics.SidecarReturnSuccess, desired: 2, applied: 2, installs: 2},
		{name: "one install fails", objs: withRouter, wantErr: true,
			setup:  func(h *sidecarReturnHarness) { h.dp.failAddrs[testReturnAddr3] = true },
			result: metrics.SidecarReturnPartial, desired: 2, applied: 1, installs: 1, installErrs: 1},
		{name: "register fails", objs: withRouter, wantErr: true,
			setup:  func(h *sidecarReturnHarness) { h.registerErr = errSidecarReturnTest },
			result: metrics.SidecarReturnError, desired: 2, regErrs: 1},
		{name: "prune fails", objs: withRouter,
			setup:  func(h *sidecarReturnHarness) { h.pruneErr = errSidecarReturnTest },
			result: metrics.SidecarReturnPartial, desired: 2, applied: 2, installs: 2, pruneErrs: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSidecarReturnHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			reg := prometheus.NewPedanticRegistry()
			rec := metrics.NewSidecarReturn(reg)
			err := ensureSidecarReturnPath(context.Background(), sidecarReturnClient(t, nil, tc.objs...),
				testNamespace, testSidecarNode, rec, clock)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			for _, r := range []string{metrics.SidecarReturnSuccess, metrics.SidecarReturnPartial,
				metrics.SidecarReturnWaitingIdentity, metrics.SidecarReturnError} {
				want := 0.0
				if r == tc.result {
					want = 1
				}
				if got := sidecarReturnSeries(t, reg, "reconcile_total", "result", r); got != want {
					t.Errorf("reconcile_total{result=%q} = %v, want %v", r, got, want)
				}
			}
			for _, c := range []struct {
				label string
				want  float64
			}{
				{"desired", tc.desired},
				{"applied", tc.applied},
				{"pending", tc.desired - tc.applied},
			} {
				if got := sidecarReturnSeries(t, reg, "endpoints", "state", c.label); got != c.want {
					t.Errorf("endpoints{state=%q} = %v, want %v", c.label, got, c.want)
				}
			}
			for _, c := range []struct {
				op, result string
				want       float64
			}{
				{metrics.SidecarReturnOpInstall, opSuccess, tc.installs},
				{metrics.SidecarReturnOpInstall, opError, tc.installErrs},
				{metrics.SidecarReturnOpRegister, opError, tc.regErrs},
				{metrics.SidecarReturnOpPrune, opError, tc.pruneErrs},
				{metrics.SidecarReturnOpPrune, opSuccess, 1 - tc.pruneErrs},
			} {
				if got := sidecarReturnSeries(t, reg, "operations_total", "operation", c.op, "result", c.result); got != c.want {
					t.Errorf("operations_total{%s,%s} = %v, want %v", c.op, c.result, got, c.want)
				}
			}
			if got := sidecarReturnSeries(t, reg, "last_completed_timestamp_seconds"); got != float64(at.Unix()) {
				t.Errorf("last completed = %v, want the pass's end", got)
			}
		})
	}
}

// TestSidecarReturnFailedDiscoveryKeepsTheSnapshot: a pass that cannot list
// the advertisements must not read as a healthy node with none. The counts
// and the timestamp stay at the last pass that listed them.
func TestSidecarReturnFailedDiscoveryKeepsTheSnapshot(t *testing.T) {
	newSidecarReturnHarness(t)
	reg := prometheus.NewPedanticRegistry()
	rec := metrics.NewSidecarReturn(reg)
	first := time.Unix(1_700_000_000, 0)
	objs := append(twoGatewayAdvs(), router(testSidecarNode, testLocator, 6))
	if err := ensureSidecarReturnPath(context.Background(), sidecarReturnClient(t, nil, objs...),
		testNamespace, testSidecarNode, rec, func() time.Time { return first }); err != nil {
		t.Fatal(err)
	}

	err := ensureSidecarReturnPath(context.Background(), sidecarReturnClient(t, errSidecarReturnTest, objs...),
		testNamespace, testSidecarNode, rec, func() time.Time { return first.Add(time.Minute) })
	if err == nil {
		t.Fatal("a failed list returned no error")
	}
	if got := sidecarReturnSeries(t, reg, "endpoints", "state", "desired"); got != 2 {
		t.Errorf("desired = %v after a failed list, want the last listed 2", got)
	}
	if got := sidecarReturnSeries(t, reg, "last_completed_timestamp_seconds"); got != float64(first.Unix()) {
		t.Errorf("last completed = %v, want the pass before the failure", got)
	}
	if got := sidecarReturnSeries(t, reg, "reconcile_total", "result", metrics.SidecarReturnError); got != 1 {
		t.Errorf("reconcile_total{error} = %v, want 1", got)
	}
}

// TestSidecarReturnSeries: every series exists from the start, and the
// total is fixed.
func TestSidecarReturnSeries(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	metrics.NewSidecarReturn(reg)
	n, err := testutil.GatherAndCount(reg)
	if err != nil {
		t.Fatal(err)
	}
	// 3 endpoint states, 1 timestamp, 4 results, 4 operations x 2 results.
	if n != 16 {
		t.Errorf("%d series, want 16", n)
	}
	if got := sidecarReturnSeries(t, reg, "last_completed_timestamp_seconds"); got != 0 {
		t.Errorf("last completed = %v before any pass, want 0", got)
	}
	var nilRec *metrics.SidecarReturn
	nilRec.Completed(time.Now(), metrics.SidecarReturnSuccess, 1, 1)
	nilRec.DiscoveryFailed()
	nilRec.Operation(metrics.SidecarReturnOpReap, nil)
}

// TestSidecarReturnPruneFailureWhileWaiting: a failed prune on a pass that
// ends waiting for identity shows in operations_total, the result being the
// waiting state.
func TestSidecarReturnPruneFailureWhileWaiting(t *testing.T) {
	h := newSidecarReturnHarness(t)
	h.pruneErr = errSidecarReturnTest
	reg := prometheus.NewPedanticRegistry()
	rec := metrics.NewSidecarReturn(reg)
	if err := ensureSidecarReturnPath(context.Background(), sidecarReturnClient(t, nil, twoGatewayAdvs()...),
		testNamespace, testSidecarNode, rec, time.Now); err != nil {
		t.Fatal(err)
	}
	if got := sidecarReturnSeries(t, reg, "reconcile_total", "result", metrics.SidecarReturnWaitingIdentity); got != 1 {
		t.Errorf("reconcile_total{waiting_identity} = %v, want 1", got)
	}
	if got := sidecarReturnSeries(t, reg, "operations_total",
		"operation", metrics.SidecarReturnOpPrune, "result", opError); got != 1 {
		t.Errorf("operations_total{prune,error} = %v, want 1", got)
	}
}

// TestReconcileSidecarReturnPathCountsReap: the wrapper Run calls counts the
// reaper's outcome as well as the pass.
func TestReconcileSidecarReturnPathCountsReap(t *testing.T) {
	newSidecarReturnHarness(t)
	reg := prometheus.NewPedanticRegistry()
	st := ebpfDatapathState{
		k8sClient: sidecarReturnClient(t, nil), namespace: testNamespace, nodeName: testSidecarNode,
		sidecarReap: &sidecarReaper{}, sidecarReturn: metrics.NewSidecarReturn(reg),
	}
	reconcileSidecarReturnPath(context.Background(), st)
	if got := sidecarReturnSeries(t, reg, "operations_total",
		"operation", metrics.SidecarReturnOpReap, "result", opSuccess); got != 1 {
		t.Errorf("operations_total{reap,success} = %v, want 1", got)
	}
	if got := sidecarReturnSeries(t, reg, "reconcile_total", "result", metrics.SidecarReturnSuccess); got != 1 {
		t.Errorf("reconcile_total{success} = %v, want 1", got)
	}
}

// TestSidecarReturnScrapeSeesOnePass: a scrape during a run of passes always
// reads counts that partition desired and come from one pass.
func TestSidecarReturnScrapeSeesOnePass(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	rec := metrics.NewSidecarReturn(reg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 20000 {
			// Each pass's desired is its timestamp, so a torn read shows.
			rec.Completed(time.Unix(int64(i), 0), metrics.SidecarReturnPartial, i, i/2)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		vals := map[string]float64{}
		var ts float64
		for _, f := range families {
			switch f.GetName() {
			case "galactic_sidecar_return_endpoints":
				for _, m := range f.GetMetric() {
					vals[m.GetLabel()[0].GetValue()] = m.GetGauge().GetValue()
				}
			case "galactic_sidecar_return_last_completed_timestamp_seconds":
				ts = f.GetMetric()[0].GetGauge().GetValue()
			}
		}
		if vals["applied"]+vals["pending"] != vals["desired"] || vals["desired"] != ts {
			t.Fatalf("torn read: %v at %v", vals, ts)
		}
	}
}
