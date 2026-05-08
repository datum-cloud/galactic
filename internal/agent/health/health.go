// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package health serves the agent's /healthz and /metrics HTTP
// endpoints. /healthz is a Kubernetes-style readiness probe; /metrics
// exposes the Prometheus gauges defined in internal/agent/metrics.
package health

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	agentbgp "go.datum.net/galactic/internal/agent/bgp"
	"go.datum.net/galactic/internal/agent/metrics"
	"go.datum.net/galactic/internal/agent/reconciler"
)

// CacheSyncProbe is the surface health uses against the informer cache.
type CacheSyncProbe interface {
	Synced() bool
}

// Config wires the health server's dependencies.
type Config struct {
	// ListenAddr is the HTTP listen address, e.g. ":8081".
	ListenAddr string

	// SocketPath is the Unix socket the CNI plugin connects to. The
	// /healthz check fails if this socket does not exist.
	SocketPath string

	BGP   *agentbgp.Server
	Cache CacheSyncProbe
	Recon *reconciler.Reconciler

	// Registry is the Prometheus registry to register metrics into
	// and serve on /metrics. Defaults to a fresh registry, NOT the
	// default global one — keeps the agent's metric surface
	// disjoint from controller-runtime's defaults if both run in the
	// same process (they don't currently, but cheap to be safe).
	Registry *prometheus.Registry
}

// Server is the health and metrics HTTP server.
type Server struct {
	cfg     Config
	metrics *metrics.Metrics
	mux     *http.ServeMux
}

// New constructs the server, registering metrics into cfg.Registry.
func New(cfg Config) *Server {
	if cfg.Registry == nil {
		cfg.Registry = prometheus.NewRegistry()
	}
	m := metrics.New(cfg.Registry)

	mux := http.NewServeMux()
	s := &Server{cfg: cfg, metrics: m, mux: mux}

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleHealthz)
	mux.Handle("/metrics", promhttp.HandlerFor(cfg.Registry, promhttp.HandlerOpts{}))
	return s
}

// Run starts the HTTP listener and the metrics refresh ticker. Blocks
// until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go s.refreshMetrics(ctx)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

// refreshMetrics polls the reconciler and BGP server every second to
// update Prometheus gauges. Avoids exposing internal state via Collector
// callbacks, which would couple the metrics layer to those types.
func (s *Server) refreshMetrics(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.cfg.Recon != nil {
				s.metrics.PendingAttachments.Set(float64(s.cfg.Recon.PendingCount()))
				s.metrics.OriginatedPaths.Set(float64(s.cfg.Recon.ActiveCount()))
				s.metrics.ReceivedPaths.Set(float64(s.cfg.Recon.ReceivedCount()))
				s.metrics.KernelRoutesProgrammed.Set(float64(s.cfg.Recon.ProgrammedKernelCount()))
			}
			if s.cfg.BGP != nil {
				for peer, st := range s.cfg.BGP.PeerStates() {
					s.metrics.BGPSessionState.WithLabelValues(peer).Set(float64(st))
				}
			}
		}
	}
}

// handleHealthz returns 200 when the agent is fully ready, 503 with a
// per-condition message when any condition is unmet. Conditions:
//  1. The CNI gRPC unix socket exists (the local server has bound).
//  2. The VPCAttachment informer cache has completed initial sync.
//  3. At least one configured BGP peer is in the Established state.
//
// This makes a misconfigured RR loud rather than silent — see
// PLAN-bgp-cutover.md "Health and observability."
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	var failures []string
	if _, err := os.Stat(s.cfg.SocketPath); err != nil {
		failures = append(failures, fmt.Sprintf("cni-socket: %v", err))
	}
	if s.cfg.Cache == nil || !s.cfg.Cache.Synced() {
		failures = append(failures, "informer: not synced")
	}
	if s.cfg.BGP == nil || !s.cfg.BGP.AnyEstablished() {
		failures = append(failures, "bgp: no peer in Established state")
	}

	if len(failures) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		for _, f := range failures {
			_, _ = fmt.Fprintln(w, f)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "ok")
}
