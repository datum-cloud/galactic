// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package service

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
)

func TestHealthHandler(t *testing.T) {
	var ready atomic.Bool
	h := HealthHandler(ready.Load)
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		return rec.Code
	}
	if code := get("/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if code := get("/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before ready = %d, want 503", code)
	}
	ready.Store(true)
	if code := get("/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz once ready = %d, want 200", code)
	}
	if code := get("/metrics"); code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", code)
	}
}

func TestPodFromEnv(t *testing.T) {
	bootID := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(bootID, []byte("boot-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"POD_NAMESPACE": "edge", "POD_NAME": "masque-0", "POD_UID": "uid-0", "NODE_NAME": "node-0"}
	p, err := podFromEnv(func(k string) string { return env[k] }, bootID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Namespace != "edge" || p.Name != "masque-0" || p.UID != "uid-0" || p.Node != "node-0" || p.BootID != "boot-1" {
		t.Fatalf("pod = %+v", p)
	}
	delete(env, "NODE_NAME")
	if _, err := podFromEnv(func(k string) string { return env[k] }, bootID); err == nil {
		t.Fatal("pod without NODE_NAME was accepted")
	}
}

func TestRunRequiresExtendedConnectForTCP(t *testing.T) {
	t.Setenv("GODEBUG", "")
	err := Run(t.Context(), Config{
		Client: fake.NewClientBuilder().Build(), Authorizer: nilAuthorizer{}, Listen: "127.0.0.1:0", ListenTCP: "127.0.0.1:0",
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
	})
	if !errors.Is(err, connectip.ErrExtendedConnectDisabled) {
		t.Fatalf("Run = %v, want ErrExtendedConnectDisabled", err)
	}
}

// nilAuthorizer is never called: Run must fail before admitting anything.
type nilAuthorizer struct{ masque.Authorizer }
