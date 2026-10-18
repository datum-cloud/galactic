// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/crdnames"
)

const (
	mSlices      = "galactic_ingress_sidecar_endpoint_slices"
	mEvaluations = "galactic_ingress_sidecar_endpoint_slice_evaluations_total"
)

func inputRegistry(t *testing.T) (*InputMetrics, *prometheus.Registry) {
	t.Helper()
	m := NewInputMetrics()
	reg := prometheus.NewPedanticRegistry()
	m.MustRegister(reg)
	return m, reg
}

func inputValue(t *testing.T, reg *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			for i := 0; i+1 < len(labels); i += 2 {
				if got[labels[i]] != labels[i+1] {
					continue series
				}
			}
			return m.GetGauge().GetValue() + m.GetCounter().GetValue()
		}
	}
	return -1
}

// sliceStates asserts the endpoint_slices gauge for each state.
func sliceStates(t *testing.T, reg *prometheus.Registry, ready, waiting, invalid float64) {
	t.Helper()
	for state, want := range map[string]float64{InputReady: ready, InputWaitingSID: waiting, InputInvalid: invalid} {
		if v := inputValue(t, reg, mSlices, "state", state); v != want {
			t.Errorf("endpoint_slices{state=%q} = %v, want %v", state, v, want)
		}
	}
}

func evaluations(t *testing.T, reg *prometheus.Registry, source, result string) float64 {
	t.Helper()
	return inputValue(t, reg, mEvaluations, "source", source, "result", result)
}

// namedSlice is a selected slice called name: ready when sid is set, waiting
// for its SID otherwise.
func namedSlice(name, sid string) *discoveryv1.EndpointSlice {
	s := readySlice("vpc1-att1", sid, "fd00::1")
	s.Name = name
	return s
}

func malformedSlice(name string) *discoveryv1.EndpointSlice {
	s := namedSlice(name, "fd00:99::1")
	s.Annotations[crdnames.AnnotationTenantID] = testMalformedTenantID
	return s
}

func TestInputMetricsInitialState(t *testing.T) {
	_, reg := inputRegistry(t)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]dto.MetricType{mSlices: dto.MetricType_GAUGE, mEvaluations: dto.MetricType_COUNTER}
	if len(families) != len(want) {
		t.Errorf("exported %d families, want %d", len(families), len(want))
	}
	for _, f := range families {
		if f.GetType() != want[f.GetName()] || strings.TrimSpace(f.GetHelp()) == "" {
			t.Errorf("%s: type %v, help %q", f.GetName(), f.GetType(), f.GetHelp())
		}
	}
	sliceStates(t, reg, 0, 0, 0)
	// 3 states, and 2 sources x 4 results.
	if n := testutil.CollectAndCount(reg); n != 3+8 {
		t.Errorf("%d series, want %d", n, 3+8)
	}
}

func TestClassifySlice(t *testing.T) {
	for _, tt := range []struct {
		name  string
		slice *discoveryv1.EndpointSlice
		want  string
	}{
		{"ready", namedSlice("a", "fd00:99::1"), InputReady},
		{"no SID yet", namedSlice("a", ""), InputWaitingSID},
		{"malformed", malformedSlice("a"), InputInvalid},
		{"unlabeled", &discoveryv1.EndpointSlice{}, InputNotSelected},
	} {
		if got, _, _ := classifySlice(tt.slice); got != tt.want {
			t.Errorf("%s: classifySlice = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// reconcileSlice runs the reconciler once for name.
func reconcileSlice(t *testing.T, r *Reconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: name},
	}); err != nil {
		t.Fatalf("Reconcile %s: %v", name, err)
	}
}

// TestWatchTracksEachSlice: the watch classifies every reconcile, repeated
// reconciles of one slice do not inflate the gauge, and a slice moves between
// states and leaves when deleted or deselected.
func TestWatchTracksEachSlice(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(
		namedSlice("ready", "fd00:99::1"), namedSlice("waiting", ""), malformedSlice("bad"),
	).Build()
	store := NewStore(newFakeBackend(), testGrace, nil)
	m, reg := inputRegistry(t)
	store.SetInputMetrics(m)
	r := &Reconciler{Client: c, Store: store}

	for range 3 {
		for _, name := range []string{"ready", "waiting", "bad"} {
			reconcileSlice(t, r, name)
		}
	}
	sliceStates(t, reg, 1, 1, 1)
	if v := evaluations(t, reg, SourceWatch, InputReady); v != 3 {
		t.Errorf("watch evaluations ready = %v, want 3", v)
	}

	// The waiting slice gets its SID; the malformed one is fixed.
	ctx := context.Background()
	updateSlice(t, c, "waiting", func(s *discoveryv1.EndpointSlice) {
		s.Annotations[crdnames.AnnotationSID] = "fd00:99::2"
	})
	updateSlice(t, c, "bad", func(s *discoveryv1.EndpointSlice) {
		s.Annotations[crdnames.AnnotationTenantID] = "vpc1-att1"
	})
	reconcileSlice(t, r, "waiting")
	reconcileSlice(t, r, "bad")
	sliceStates(t, reg, 3, 0, 0)

	// One is deleted; the reconciler finds the other without the tenant
	// label. Whether a label removal reaches the reconciler at all is the
	// watch predicate's business, not this index's.
	if err := c.Delete(ctx, namedSlice("ready", "")); err != nil {
		t.Fatal(err)
	}
	updateSlice(t, c, "waiting", func(s *discoveryv1.EndpointSlice) {
		delete(s.Labels, crdnames.LabelTenantID)
	})
	reconcileSlice(t, r, "ready")
	reconcileSlice(t, r, "waiting")
	sliceStates(t, reg, 1, 0, 0)
	if v := evaluations(t, reg, SourceWatch, InputNotSelected); v != 1 {
		t.Errorf("watch evaluations not_selected = %v, want 1", v)
	}
	if n := m.tracked(); n != 1 {
		t.Errorf("tracking %d slices, want 1", n)
	}
}

// updateSlice applies change to the stored slice called name.
func updateSlice(t *testing.T, c client.Client, name string, change func(*discoveryv1.EndpointSlice)) {
	t.Helper()
	ctx := context.Background()
	s := &discoveryv1.EndpointSlice{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "ns", Name: name}, s); err != nil {
		t.Fatal(err)
	}
	change(s)
	if err := c.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
}

// TestSeedClassifiesEverySlice: the startup seed records each listed slice's
// state, counted as seed evaluations.
func TestSeedClassifiesEverySlice(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(
		namedSlice("ready", "fd00:99::1"), namedSlice("waiting", ""), malformedSlice("bad"),
	).Build()
	store := NewStore(newFakeBackend(), testGrace, nil)
	m, reg := inputRegistry(t)
	store.SetInputMetrics(m)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatal(err)
	}
	sliceStates(t, reg, 1, 1, 1)
	for _, result := range []string{InputReady, InputWaitingSID, InputInvalid} {
		if v := evaluations(t, reg, SourceSeed, result); v != 1 {
			t.Errorf("seed evaluations %s = %v, want 1", result, v)
		}
	}
}

// TestWatchWinsOverASeed: during a seed, a slice the watch has seen keeps
// the watch's state, and one the watch found deleted is not brought back,
// whatever the seed's older list says. The seed's evaluations still count.
func TestWatchWinsOverASeed(t *testing.T) {
	m, reg := inputRegistry(t)
	m.beginSeed()
	m.observeWatch("ns/updated", InputInvalid)
	m.forget("ns/deleted")
	m.observeSeed("ns/updated", InputReady)
	m.observeSeed("ns/deleted", InputReady)
	m.observeSeed("ns/untouched", InputWaitingSID)
	m.endSeed()

	sliceStates(t, reg, 0, 1, 1)
	if v := evaluations(t, reg, SourceSeed, InputReady); v != 2 {
		t.Errorf("seed evaluations ready = %v, want 2", v)
	}

	// After the seed, the watch applies as always.
	m.observeWatch("ns/updated", InputReady)
	sliceStates(t, reg, 1, 1, 0)
}

// TestSeedAndWatchConcurrently: a seed and the watch updating overlapping
// slices at once leave gauges that match the tracked states, and every slice
// the watch touched holds the watch's state.
func TestSeedAndWatchConcurrently(t *testing.T) {
	m, reg := inputRegistry(t)
	const n = 500
	m.beginSeed()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range n {
			m.observeSeed(fmt.Sprintf("ns/s%d", i), InputReady)
		}
	}()
	go func() {
		defer wg.Done()
		for i := range n {
			if i%2 == 0 {
				m.observeWatch(fmt.Sprintf("ns/s%d", i), InputInvalid)
			} else {
				m.forget(fmt.Sprintf("ns/s%d", i))
			}
		}
	}()
	wg.Wait()
	m.endSeed()

	// Every key was touched by the watch, so the seed's results lost: half
	// are invalid, half deleted.
	sliceStates(t, reg, 0, 0, n/2)
	if got := m.tracked(); got != n/2 {
		t.Errorf("tracking %d slices, want %d", got, n/2)
	}
}

// TestInputBookkeepingShrinks: state is held only for live selected slices.
func TestInputBookkeepingShrinks(t *testing.T) {
	m, reg := inputRegistry(t)
	for i := range 1000 {
		m.observeWatch(fmt.Sprintf("ns/s%d", i), InputReady)
	}
	for i := range 1000 {
		if i%2 == 0 {
			m.forget(fmt.Sprintf("ns/s%d", i))
		} else {
			m.observeWatch(fmt.Sprintf("ns/s%d", i), InputNotSelected)
		}
	}
	if n := m.tracked(); n != 0 {
		t.Errorf("tracking %d slices after all were deleted or deselected", n)
	}
	sliceStates(t, reg, 0, 0, 0)
}

// tracked is how many slices m holds state for.
func (m *InputMetrics) tracked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state)
}

func TestInputMetricsNilIsInert(t *testing.T) {
	var m *InputMetrics
	m.beginSeed()
	m.observeSeed("k", InputReady)
	m.observeWatch("k", InputReady)
	m.forget("k")
	m.endSeed()

	// The reconciler and seed run unchanged without input metrics.
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(namedSlice("a", "fd00:99::1")).Build()
	store := NewStore(newFakeBackend(), testGrace, nil)
	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatal(err)
	}
	reconcileSlice(t, &Reconciler{Client: c, Store: store}, "a")
}

// TestSeedRacingTheReconciler drives the real seed and reconciler together:
// while the seed's list is in flight, the reconciler sees one slice updated
// and another deleted, and those observations survive the seed's older list.
func TestSeedRacingTheReconciler(t *testing.T) {
	listing, release := make(chan struct{}), make(chan struct{})
	base := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(
		namedSlice("updated", "fd00:99::1"), namedSlice("deleted", "fd00:99::2"),
	).Build()
	// The seed's reader lists what existed before the reconciler ran.
	var before discoveryv1.EndpointSliceList
	if err := base.List(context.Background(), &before); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
			close(listing)
			<-release
			before.DeepCopyInto(list.(*discoveryv1.EndpointSliceList))
			return nil
		},
	}).Build()

	store := NewStore(newFakeBackend(), testGrace, nil)
	m, reg := inputRegistry(t)
	store.SetInputMetrics(m)
	seeded := make(chan error, 1)
	go func() { seeded <- SeedFromAPI(context.Background(), reader, store) }()
	<-listing

	r := &Reconciler{Client: base, Store: store}
	updateSlice(t, base, "updated", func(s *discoveryv1.EndpointSlice) {
		s.Annotations[crdnames.AnnotationTenantID] = testMalformedTenantID
	})
	if err := base.Delete(context.Background(), namedSlice("deleted", "")); err != nil {
		t.Fatal(err)
	}
	reconcileSlice(t, r, "updated")
	reconcileSlice(t, r, "deleted")
	close(release)
	if err := <-seeded; err != nil {
		t.Fatal(err)
	}

	sliceStates(t, reg, 0, 0, 1) // updated is invalid; deleted stays gone
	if v := evaluations(t, reg, SourceSeed, InputReady); v != 2 {
		t.Errorf("seed evaluations ready = %v, want both stale results counted", v)
	}
}

// TestFailedSeedAttemptEndsTheSeed: a seed whose list fails leaves no seed
// in progress, so later watch observations are not marked against it.
func TestFailedSeedAttemptEndsTheSeed(t *testing.T) {
	reader := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errTest
		},
	}).Build()
	store := NewStore(newFakeBackend(), testGrace, nil)
	m, _ := inputRegistry(t)
	store.SetInputMetrics(m)
	if err := SeedFromAPI(context.Background(), reader, store); err == nil {
		t.Fatal("SeedFromAPI succeeded with a failing list")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seeding || m.watched != nil {
		t.Errorf("seeding = %v, watched = %v after a failed attempt", m.seeding, m.watched)
	}
}
