// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

const testAPIToken = "test-sidecar-token"

// newSocketAPIServer serves a TLS stub of the API's /version endpoint on a
// unix socket only, and returns the socket path, a client config pointing
// at an address nothing listens on, and a count of authenticated requests.
func newSocketAPIServer(t *testing.T) (string, *rest.Config, *atomic.Int32) {
	t.Helper()

	// A short directory keeps the path under the unix socket length limit,
	// which t.TempDir can exceed.
	dir, err := os.MkdirTemp("", "vrfapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")

	var authed atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The API server speaks HTTP/2, so the stub insists on it too.
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testAPIToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"major":"1","minor":"99","gitVersion":"v1.99.0"}`))
	}))
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Port 1 on loopback refuses connections, so any request that is not
	// dialed through the socket fails. The httptest certificate carries a
	// 127.0.0.1 IP SAN, so TLS verification against this host still passes
	// when the bytes arrive over the socket.
	cfg := &rest.Config{
		Host:        "https://127.0.0.1:1",
		BearerToken: testAPIToken,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
		},
	}
	return sock, cfg, &authed
}

func TestDialAPIThroughSocket(t *testing.T) {
	sock, cfg, authed := newSocketAPIServer(t)

	t.Run("without socket the host is unreachable", func(t *testing.T) {
		dc, err := discovery.NewDiscoveryClientForConfig(rest.CopyConfig(cfg))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dc.ServerVersion(); err == nil {
			t.Fatal("ServerVersion succeeded without the socket dialer, want a connection error")
		}
	})

	t.Run("through socket with TLS and token intact", func(t *testing.T) {
		before := authed.Load()
		c := rest.CopyConfig(cfg)
		dialAPIThroughSocket(c, sock)

		dc, err := discovery.NewDiscoveryClientForConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		v, err := dc.ServerVersion()
		if err != nil {
			t.Fatalf("ServerVersion through socket: %v", err)
		}
		if v.GitVersion != "v1.99.0" {
			t.Errorf("GitVersion = %q, want v1.99.0", v.GitVersion)
		}
		if authed.Load() == before {
			t.Error("no request reached the server with the sidecar's bearer token")
		}
		if c.Host != cfg.Host || c.BearerToken != cfg.BearerToken {
			t.Errorf("dialer changed host or credentials: host=%q", c.Host)
		}
	})

	t.Run("environment proxy is bypassed", func(t *testing.T) {
		c := rest.CopyConfig(cfg)
		dialAPIThroughSocket(c, sock)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, c.Host, nil)
		if err != nil {
			t.Fatal(err)
		}
		if u, err := c.Proxy(req); u != nil || err != nil {
			t.Errorf("Proxy = %v, %v; want no proxy so the socket's peer is the API server", u, err)
		}
	})
}
