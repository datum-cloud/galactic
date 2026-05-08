// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package health

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

type fakeCache struct{ synced bool }

func (f *fakeCache) Synced() bool { return f.synced }

// healthOnly builds a Server with no BGP/reconciler — used to exercise
// the /healthz failure paths around socket and cache only. The BGP
// readiness path is exercised by an integration test against a real
// peering, not unit-tested here (would require a live RR).
func healthOnly(t *testing.T, socketExists bool, cacheSynced bool) *Server {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "agent.sock")
	if socketExists {
		f, err := os.Create(socket)
		if err != nil {
			t.Fatalf("create socket fixture: %v", err)
		}
		_ = f.Close()
	}
	return New(Config{
		ListenAddr: "127.0.0.1:0",
		SocketPath: socket,
		Cache:      &fakeCache{synced: cacheSynced},
		Registry:   prometheus.NewRegistry(),
	})
}

func get(t *testing.T, s *Server) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.handleHealthz(rr, req)
	return rr.Code, rr.Body.String()
}

func TestHealthz_AllFailing(t *testing.T) {
	s := healthOnly(t, false, false)
	code, body := get(t, s)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", code)
	}
	for _, want := range []string{"cni-socket", "informer:", "bgp:"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q condition: %s", want, body)
		}
	}
}

func TestHealthz_BGPMissing(t *testing.T) {
	s := healthOnly(t, true, true)
	code, body := get(t, s)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", code)
	}
	if !strings.Contains(body, "bgp:") {
		t.Errorf("body should still report bgp failure: %s", body)
	}
	if strings.Contains(body, "cni-socket") {
		t.Errorf("cni-socket condition should pass once file exists, body: %s", body)
	}
	if strings.Contains(body, "informer:") {
		t.Errorf("informer condition should pass once Synced() returns true, body: %s", body)
	}
}

func TestHealthz_CNISocketCheck(t *testing.T) {
	s := healthOnly(t, false, true)
	code, body := get(t, s)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", code)
	}
	if !strings.Contains(body, "cni-socket") {
		t.Errorf("body should report missing cni-socket, got: %s", body)
	}
}
