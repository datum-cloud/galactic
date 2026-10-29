// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func requests(transport, outcome string) float64 {
	return testutil.ToFloat64(requestsTotal.WithLabelValues(transport, outcome))
}

func ends(transport, cause string) float64 {
	return testutil.ToFloat64(tunnelEnds.WithLabelValues(transport, cause))
}

func tunnelsOpen(transport string) float64 {
	return testutil.ToFloat64(openTunnels.WithLabelValues(transport))
}

// eventually fails the test unless cond holds within testTimeout.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTelemetryH3Lifecycle follows one HTTP/3 request from acceptance
// through forwarding to the client closing it.
func TestTelemetryH3Lifecycle(t *testing.T) {
	env := startServer(t, nil)
	accepted0, closed0 := requests(transportH3, outcomeAccepted), ends(transportH3, causeClientClosed)
	toVPC0 := testutil.ToFloat64(packetsForwarded.WithLabelValues(transportH3, toVPC))
	toClient0 := testutil.ToFloat64(packetsForwarded.WithLabelValues(transportH3, toClient))
	bytes0 := testutil.ToFloat64(bytesForwarded.WithLabelValues(transportH3, toVPC))
	tunnels0 := tunnelsOpen(transportH3)

	cc := newClientConn(t, env.dialQUIC(t))
	if got := testutil.ToFloat64(openConnections.WithLabelValues(transportH3)); got < 1 {
		t.Errorf("open h3 connections = %v, want at least 1", got)
	}
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	ping(t, s, 1, 200)

	if got := requests(transportH3, outcomeAccepted) - accepted0; got != 1 {
		t.Errorf("accepted h3 requests rose by %v, want 1", got)
	}
	if got := tunnelsOpen(transportH3) - tunnels0; got != 1 {
		t.Errorf("open h3 tunnels rose by %v, want 1", got)
	}
	// The proxy counts a packet after its write returns, so the reply can
	// reach the client before the count does.
	eventually(t, "one packet counted each way", func() bool {
		return testutil.ToFloat64(packetsForwarded.WithLabelValues(transportH3, toVPC))-toVPC0 == 1 &&
			testutil.ToFloat64(packetsForwarded.WithLabelValues(transportH3, toClient))-toClient0 == 1 &&
			testutil.ToFloat64(bytesForwarded.WithLabelValues(transportH3, toVPC))-bytes0 == 200
	})

	if err := s.conn.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the tunnel to end", func() bool { return ends(transportH3, causeClientClosed)-closed0 == 1 })
	eventually(t, "the tunnel gauge to drop", func() bool { return tunnelsOpen(transportH3) == tunnels0 })
}

// TestTelemetryRejections counts each refusal under its own outcome, so
// authentication, authorization, backend and limit failures stay apart.
func TestTelemetryRejections(t *testing.T) {
	env := startServer(t, nil)
	cc := newClientConn(t, env.dialQUIC(t))
	tests := []struct {
		name    string
		headers http.Header
		outcome string
	}{
		{"Unauthenticated", authHeaders("test-token-unknown", vpcBlue), outcomeUnauthenticated},
		{"Forbidden", authHeaders(tokenBob, vpcBlue), outcomeForbidden},
		{"BadRequest", authHeaders(tokenAlice, ""), outcomeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := requests(transportH3, tt.outcome)
			conn, _, err := cc.Dial(env.newRequest(t, tt.headers))
			if err == nil {
				_ = conn.Close()
				t.Fatal("request was accepted")
			}
			if got := requests(transportH3, tt.outcome) - before; got != 1 {
				t.Fatalf("%s requests rose by %v, want 1", tt.outcome, got)
			}
		})
	}

	t.Run("BackendUnavailable", func(t *testing.T) {
		env := startServer(t, func(c *Config) { c.Backend = failingBackend{} })
		before := requests(transportH3, outcomeBackendUnavailable)
		conn, _, err := newClientConn(t, env.dialQUIC(t)).Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		if err == nil {
			_ = conn.Close()
			t.Fatal("request was accepted")
		}
		if got := requests(transportH3, outcomeBackendUnavailable) - before; got != 1 {
			t.Fatalf("backend_unavailable requests rose by %v, want 1", got)
		}
	})
}

// TestTelemetryH2 labels HTTP/2 requests apart from HTTP/3, and counts a
// lease ended by its authority as lease_ended.
func TestTelemetryH2(t *testing.T) {
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })
	accepted0, leaseEnded0 := requests(transportH2, outcomeAccepted), ends(transportH2, causeLeaseEnded)
	h3Accepted0 := requests(transportH3, outcomeAccepted)
	denied0 := requests(transportH2, outcomeForbidden)

	c := env.dialH2(t)
	if _, status := c.request(t, env.addr, authHeaders(tokenBob, vpcBlue)); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	if got := requests(transportH2, outcomeForbidden) - denied0; got != 1 {
		t.Errorf("forbidden h2 requests rose by %v, want 1", got)
	}

	s, _ := env.openH2(t, c, tokenAlice, vpcBlue)
	sess := env.backend.nextOpened(t)
	if got := requests(transportH2, outcomeAccepted) - accepted0; got != 1 {
		t.Errorf("accepted h2 requests rose by %v, want 1", got)
	}
	if got := requests(transportH3, outcomeAccepted) - h3Accepted0; got != 0 {
		t.Errorf("accepted h3 requests rose by %v, want 0", got)
	}

	adm.mu.Lock()
	lease := adm.leases[vpcBlue][firstPrefix]
	adm.mu.Unlock()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	sess.waitClosed(t)
	s.waitEnded(t)
	eventually(t, "a lease_ended h2 tunnel end", func() bool {
		return ends(transportH2, causeLeaseEnded)-leaseEnded0 == 1
	})
}

// TestTelemetryBackendError counts a backend that fails a write as
// backend_error.
func TestTelemetryBackendError(t *testing.T) {
	backend := &brokenBackend{memoryBackend: newMemoryBackend()}
	env := startServer(t, func(c *Config) { c.Backend = backend })
	before := ends(transportH3, causeBackendError)
	s := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if _, err := s.conn.WritePacket(echoRequest(t, s.address, testTarget, 1, 100)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a backend_error tunnel end", func() bool {
		return ends(transportH3, causeBackendError)-before == 1
	})
}

// TestTelemetryBackendLeaseEnded counts a backend that stops a write
// because the request's lease ended as lease_ended, even while the lease's
// Done is still open (issue #1239).
func TestTelemetryBackendLeaseEnded(t *testing.T) {
	backend := &brokenBackend{memoryBackend: newMemoryBackend(),
		err: fmt.Errorf("forwarding stopped: %w", ErrLeaseEnded)}
	env := startServer(t, func(c *Config) { c.Backend = backend })
	leaseEnded0, backendError0 := ends(transportH3, causeLeaseEnded), ends(transportH3, causeBackendError)
	s := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if _, err := s.conn.WritePacket(echoRequest(t, s.address, testTarget, 1, 100)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a lease_ended tunnel end", func() bool {
		return ends(transportH3, causeLeaseEnded)-leaseEnded0 == 1
	})
	if got := ends(transportH3, causeBackendError) - backendError0; got != 0 {
		t.Fatalf("backend_error tunnel ends rose by %v, want 0", got)
	}
}

// brokenBackend opens sessions whose writes fail with err, or with a device
// error when err is nil.
type brokenBackend struct {
	*memoryBackend
	err error
}

func (b *brokenBackend) Open(ctx context.Context, info SessionInfo) (BackendSession, error) {
	s, err := b.memoryBackend.Open(ctx, info)
	if err != nil {
		return nil, err
	}
	if b.err != nil {
		return brokenSession{s, b.err}, nil
	}
	return brokenSession{s, errors.New("device gone")}, nil
}

type brokenSession struct {
	BackendSession
	err error
}

func (s brokenSession) WritePacket([]byte) error { return s.err }

// TestTelemetryLabelsAreBounded fails when a server metric gains a label
// that could carry a connector, principal, VPC, prefix, attachment or
// address, which would grow the series count with connector churn.
func TestTelemetryLabelsAreBounded(t *testing.T) {
	allowed := []string{labelTransport, labelDirection, labelCause, "outcome", "reason"}
	collectors := map[string]prometheus.Collector{
		"requests": requestsTotal, "admission": admissionSeconds, "connections": openConnections,
		"rejected": connsRejected, "admissions": admissionsInProgress, "tunnels": openTunnels,
		"ends": tunnelEnds, "packets": packetsForwarded, "bytes": bytesForwarded, "denied": packetsDenied,
	}
	// Every vector has at least one series by now only if the other tests
	// ran; create one per vector so the check never passes vacuously.
	requestsTotal.WithLabelValues(transportH3, outcomeAccepted)
	admissionSeconds.WithLabelValues(transportH3)
	openConnections.WithLabelValues(transportH3)
	connsRejected.WithLabelValues(transportH3, connReasonTotal)
	admissionsInProgress.WithLabelValues(transportH3)
	openTunnels.WithLabelValues(transportH3)
	tunnelEnds.WithLabelValues(transportH3, causeClientClosed)
	packetsForwarded.WithLabelValues(transportH3, toVPC)
	bytesForwarded.WithLabelValues(transportH3, toVPC)
	packetsDenied.WithLabelValues(toVPC, reasonSource)
	for name, c := range collectors {
		ch := make(chan prometheus.Metric, 256)
		go func() { c.Collect(ch); close(ch) }()
		n := 0
		for m := range ch {
			n++
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			for _, l := range pb.GetLabel() {
				if !slices.Contains(allowed, l.GetName()) {
					t.Errorf("%s has label %q, want only %v", name, l.GetName(), allowed)
				}
			}
		}
		if n == 0 {
			t.Errorf("%s exported no series", name)
		}
	}
}
