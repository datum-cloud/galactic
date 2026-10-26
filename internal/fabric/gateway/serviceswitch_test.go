// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

const testSwitchName = "fabric-api-service"

// switchConfig serves the service ConfigMap, whose reads fail while failing
// is set.
type switchConfig struct {
	client.Client
	mu      sync.Mutex
	failing bool
}

func newSwitchConfig(t *testing.T) *switchConfig {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := &switchConfig{}
	c.Client = fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			c.mu.Lock()
			failing := c.failing
			c.mu.Unlock()
			if failing {
				return errors.New("api unavailable")
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}).Build()
	return c
}

// set writes the ConfigMap's service value; remove deletes it.
func (c *switchConfig) set(t *testing.T, value string) {
	t.Helper()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultNamespace, Name: testSwitchName},
		Data:       map[string]string{ServiceSwitchKey: value},
	}
	if err := c.Update(t.Context(), cm); err != nil {
		if err := c.Create(t.Context(), cm); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *switchConfig) remove(t *testing.T) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: DefaultNamespace, Name: testSwitchName}}
	if err := c.Delete(t.Context(), cm); err != nil {
		t.Fatal(err)
	}
}

func (c *switchConfig) fail(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failing = on
}

// Only the exact value "enabled" turns the service on; everything else,
// including a failed read, turns it off.
func TestServiceSwitchWatch(t *testing.T) {
	cfg := newSwitchConfig(t)
	w := &ServiceSwitch{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Watch(ctx, cfg, DefaultNamespace, testSwitchName, 10*time.Millisecond)
	}()
	want := func(step string, on bool) {
		t.Helper()
		within(t, step, time.Now(), time.Second, func() bool {
			got, _ := w.State()
			return got == on
		})
	}
	want("missing ConfigMap", false)
	cfg.set(t, ServiceSwitchEnabled)
	want("enabled", true)
	cfg.set(t, ServiceSwitchDisabled)
	want("disabled", false)
	cfg.set(t, ServiceSwitchEnabled)
	want("enabled again", true)
	cfg.set(t, "Enabled")
	want("invalid value", false)
	cfg.set(t, ServiceSwitchEnabled)
	want("enabled after an invalid value", true)
	cfg.fail(true)
	want("unreadable", false)
	cfg.fail(false)
	want("readable again", true)
	cfg.set(t, "")
	want("empty value", false)
	cfg.set(t, ServiceSwitchEnabled)
	want("enabled before removal", true)
	cfg.remove(t)
	want("removed", false)
	cfg.set(t, ServiceSwitchEnabled)
	want("recreated", true)
	cancel()
	<-done
	if on, _ := w.State(); on {
		t.Error("the switch stayed on after its watch ended")
	}
}

// Turning the switch off cancels a running request within the contract's
// 2 s, ends its stream with Cancelled coverage, and refuses new requests
// with ServiceDisabled; the limiter keeps its state and operator probes
// keep running.
func TestServiceDisableCancelsRunningWork(t *testing.T) {
	a := newCancelAnswer()
	nodes := &routerNodes{answers: map[string]routerAnswer{routerA: a.answer}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 8)
	events, done := run(t, svc, validRequest(time.Now()), 0)
	if next(t, events).GetSnapshot() == nil {
		t.Fatal("first event is not the snapshot")
	}
	<-a.started

	start := time.Now()
	svc.Switch.Set(false)
	within(t, "running router cancelled", start, releaseBound, a.cancelled)
	var rest []*servicev1.DiagnosticEvent
	for ev := range events {
		rest = append(rest, ev)
	}
	if err := <-done; err != nil {
		t.Fatalf("stream ended with %v, want OK with complete", err)
	}
	within(t, "execution released", start, releaseBound, func() bool { return idle(svc) })
	last := rest[len(rest)-1].GetComplete()
	if last.GetReason() != string(errcode.Cancelled) {
		t.Fatalf("terminal reason = %q", last.GetReason())
	}
	for _, ev := range rest {
		if o := ev.GetOutcome(); o.GetNode() == routerA && o.GetFailure().GetReason() != string(errcode.Cancelled) {
			t.Errorf("router-a outcome = %v", o)
		}
	}

	if _, err := collect(t, svc, validRequest(time.Now())); errcode.Of(err) != errcode.ServiceDisabled {
		t.Fatalf("request while disabled: %v", err)
	}
	if s := svc.Admission.Authority.State(); s != limit.StateReady {
		t.Fatalf("limiter state after disabling = %s", s)
	}
	nodes.mu.Lock()
	nodes.answers = nil
	nodes.mu.Unlock()
	ping, err := query.Canonicalize(query.Query{Type: query.TypePing, Target: probeTarget6})
	if err != nil {
		t.Fatal(err)
	}
	out := svc.Runner.Run(t.Context(), operatorPrincipal("ops"), testRequestID, ping,
		[]Node{{Name: routerA, PodUID: podA, Selected: true}}, nil, time.Now().Add(30*time.Second))
	if len(out) != 1 || out[0].Err != nil {
		t.Fatalf("operator probe while the service is off: %v", out)
	}
}

// Routine telemetry carries attribution and counts, never a target, a
// result or node error text, and no metric label names a project,
// request, node or target.
func TestServiceTelemetryCarriesNoPayload(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	nodes := &routerNodes{answers: map[string]routerAnswer{routerB: failAnswer(errcode.FRRUnavailable)}}
	svc := newService(t, routerPods(routerA, routerB), nodes, 8)
	adm := withAdmission(t, svc, limit.Defaults())
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, func() float64 { return 0 })
	m.RegisterService(svc.Switch)
	m.RegisterAdmission(adm, func() error { return nil })
	svc.Metrics, svc.Runner.Metrics, adm.Metrics = m, m, m

	ping := string(query.TypePing)
	// The project's request burst is 2: the third is throttled.
	for i := range 3 {
		events, err := collect(t, svc, requestFor(testProject, i+1, nil))
		if i < 2 {
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			if r := events[len(events)-1].GetComplete().GetReason(); r != CompletePartialResults {
				t.Fatalf("request %d reason = %q", i, r)
			}
			continue
		}
		wantRetry(t, err, errcode.Throttled, string(limit.ScopeProject))
	}

	for labels, want := range map[[2]string]float64{
		{ping, CompletePartialResults}:    2,
		{ping, string(errcode.Throttled)}: 1,
	} {
		if got := testutil.ToFloat64(m.serviceRequests.WithLabelValues(labels[0], labels[1])); got != want {
			t.Errorf("service requests %v = %g, want %g", labels, got, want)
		}
	}
	for labels, want := range map[[2]string]float64{
		{ping, "OK"}:                           2,
		{ping, string(errcode.FRRUnavailable)}: 2,
	} {
		if got := testutil.ToFloat64(m.serviceOutcomes.WithLabelValues(labels[0], labels[1])); got != want {
			t.Errorf("router outcomes %v = %g, want %g", labels, got, want)
		}
	}
	if got := testutil.ToFloat64(m.admissionRefusals.WithLabelValues("service", "project", "Throttled")); got != 1 {
		t.Errorf("throttled refusals = %g", got)
	}
	if got := testutil.ToFloat64(m.packetsCharged.WithLabelValues("service")); got != 4*limit.PingPackets {
		t.Errorf("charged packets = %g", got)
	}

	forbidden := []string{testProject, testRequestID[:8], "2001:db8", routerA, routerB, podA, "raw failure",
		testService}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				for _, bad := range forbidden {
					if strings.Contains(l.GetValue(), bad) {
						t.Errorf("%s label %s=%q names %q", f.GetName(), l.GetName(), l.GetValue(), bad)
					}
				}
			}
		}
	}

	out := logs.String()
	for _, bad := range []string{"2001:db8", "raw failure", "replies", "192.0.2.1"} {
		if strings.Contains(out, bad) {
			t.Errorf("logs carry %q:\n%s", bad, out)
		}
	}
	if strings.Count(out, `"msg":"Looking Glass request finished"`) != 2 ||
		!strings.Contains(out, `"project":"project-a"`) || !strings.Contains(out, `"reason":"PartialResults"`) ||
		!strings.Contains(out, `"msg":"Looking Glass request refused"`) {
		t.Errorf("logs lack the requests' attribution:\n%s", out)
	}
}

// A follower counts a request it refused itself, and the leader one it ran
// or refused after forwarding, so each request is counted once in the cell.
func TestServiceRequestCountedOnce(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry(), func() float64 { return 0 })
	svc := &Service{Cell: testSite, Allowlist: testAllowlist, Elected: func() bool { return false }, Metrics: m}
	bad := validRequest(time.Now())
	bad.ApiMajor = 2
	if _, err := collect(t, svc, bad); errcode.Of(err) != errcode.VersionUnsupported {
		t.Fatalf("err = %v", err)
	}
	if _, err := collect(t, svc, validRequest(time.Now())); errcode.Of(err) != errcode.OwnershipLost {
		t.Fatalf("err = %v", err)
	}
	ping := string(query.TypePing)

	// The leader counts a forwarded request it refuses before executing it.
	leader := &Service{Cell: testSite, Allowlist: testAllowlist, Elected: elected, Metrics: m}
	gw := node.WithCaller(t.Context(), identity.Gateway(testSite))
	for _, env := range []*forwardv1.ForwardDiagnosticRequest{
		{Service: identity.Service(testSite, testService).URI(), Request: validRequest(time.Now())},
		{Service: "spiffe://fabric-api.datumapis.com/cell/other/service/x", Request: validRequest(time.Now())},
	} {
		stream := &chanStream{ctx: gw, events: make(chan *servicev1.DiagnosticEvent, 1)}
		if err := leader.Forwarder().ForwardDiagnostic(env, stream); err == nil {
			t.Fatal("an invalid forwarded request was accepted")
		}
	}
	for labels, want := range map[[2]string]float64{
		{ping, string(errcode.VersionUnsupported)}: 1,
		{ping, string(errcode.OwnershipLost)}:      1,
		{ping, string(errcode.InvalidQuery)}:       1,
		{ping, string(errcode.Unauthorized)}:       1,
	} {
		if got := testutil.ToFloat64(m.serviceRequests.WithLabelValues(labels[0], labels[1])); got != want {
			t.Errorf("service requests %v = %g, want %g", labels, got, want)
		}
	}
}
