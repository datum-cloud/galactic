// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Package service runs one MASQUE provider pod: a CONNECT-IP server over
// HTTP/3 (internal/edge/connectip) in front of the provider adapter
// (internal/edge/masque), and an HTTP server for its probes and metrics.
// cmd/masque-provider and the conformance fixture both run it, and differ
// only in their Authorizer.
package service

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	instmetrics "go.miloapis.com/instrumentation/metrics"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/timing"
)

// DefaultShutdownTimeout bounds releasing the routes, attachments and lease
// after the transports stop. It fits a 30 second termination grace period.
const DefaultShutdownTimeout = 20 * time.Second

// Config configures Run.
type Config struct {
	// Client reaches the cell's API server as the pod's ServiceAccount.
	Client client.Client
	// Provider is the EdgeProvider this pod runs as.
	Provider string
	// Authority is the host[:port] clients send as :authority.
	Authority string
	// Listen is the UDP address the HTTP/3 server listens on.
	Listen string
	// HealthListen is the TCP address serving /healthz, /readyz and
	// /metrics. Empty serves none of them.
	HealthListen string
	// Pod is this pod's identity.
	Pod masque.Pod
	// Authorizer turns a request's credential into a grant.
	Authorizer masque.Authorizer
	// GetCertificate returns the server certificate for each handshake.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Limits bounds the CONNECT-IP server; zero fields take their defaults.
	Limits connectip.Limits
	// ShutdownTimeout is optional; see DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// Log is optional and defaults to slog.Default().
	Log *slog.Logger
}

// Run serves until ctx is done or a component fails. It holds the pod's
// EdgeInstance lease through the adapter, serves CONNECT-IP on Listen, and
// reports ready on /readyz while the listener is open and the lease held.
// On return the server has ended every session, then the adapter released
// the routes, deleted the attachments and released the lease.
func Run(ctx context.Context, cfg Config) error {
	switch {
	case cfg.Client == nil || cfg.Authorizer == nil || cfg.GetCertificate == nil:
		return errors.New("client, authorizer and certificate source are required")
	case cfg.Listen == "":
		return errors.New("listen address is required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("podName", cfg.Pod.Name)

	claims := &claim.Instance{
		ID: rand.Text(), Clock: timing.BootClock, Params: timing.Params,
		Store: provider.InstanceStore{Client: cfg.Client, Namespace: cfg.Pod.Namespace, Duration: timing.Params.Duration},
	}
	a, err := masque.New(masque.Config{
		Client: cfg.Client, Provider: cfg.Provider, Pod: cfg.Pod, Authorizer: cfg.Authorizer, Claims: claims,
		OpenDevice: masque.OpenTUN, Log: log,
	})
	if err != nil {
		return err
	}
	srv, err := connectip.NewServer(connectip.Config{
		Authority: cfg.Authority,
		TLSConfig: &tls.Config{GetCertificate: cfg.GetCertificate, MinVersion: tls.VersionTLS13},
		Limits:    cfg.Limits, Admission: a, Backend: a, Logger: log,
	})
	if err != nil {
		return err
	}
	// Both sockets open before the instance is registered, so a port that
	// cannot be bound leaves nothing behind in the API.
	var listening atomic.Bool
	health, err := serveHealth(ctx, cfg.HealthListen, func() bool { return listening.Load() && a.Ready() }, log)
	if err != nil {
		return err
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.Listen)
	if err != nil {
		return errors.Join(err, health.close())
	}
	if err := a.Start(ctx); err != nil {
		return errors.Join(err, pc.Close(), health.close())
	}
	listening.Store(true)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(pc) }()
	runCtx, cancelRun := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(runCtx) }()
	log.Info("serving CONNECT-IP", "listen", cfg.Listen, "authority", cfg.Authority, "provider", cfg.Provider)

	var stopped error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		stopped = fmt.Errorf("HTTP/3 server stopped: %w", err)
	case err := <-health.errc:
		stopped = fmt.Errorf("health server stopped: %w", err)
	case err := <-runErr:
		// Run ends early only when the instance's lease can never be held.
		// The process must still exit with an error, so the pod restarts.
		if err == nil {
			err = errors.New("adapter stopped before shutdown")
		}
		runErr <- err
	}
	// Sessions end before the routes, attachments and lease are released.
	listening.Store(false)
	_ = srv.Close()
	cancelRun()
	if err := <-runErr; err != nil {
		stopped = errors.Join(stopped, fmt.Errorf("adapter stopped: %w", err))
	}
	sctx, cancel := context.WithTimeout(context.Background(), cmp.Or(cfg.ShutdownTimeout, DefaultShutdownTimeout))
	defer cancel()
	return errors.Join(stopped, a.Shutdown(sctx), health.close())
}

// healthServer serves the probes and metrics, or nothing when its address
// is empty.
type healthServer struct {
	srv  *http.Server
	errc chan error
}

func serveHealth(ctx context.Context, addr string, ready func() bool, log *slog.Logger) (*healthServer, error) {
	h := &healthServer{errc: make(chan error, 1)}
	if addr == "" {
		return h, nil
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	h.srv = &http.Server{Handler: HealthHandler(ready), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := h.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			h.errc <- err
		}
	}()
	log.Info("serving probes and metrics", "listen", addr)
	return h, nil
}

func (h *healthServer) close() error {
	if h.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.srv.Shutdown(ctx)
}

// HealthHandler serves /healthz, which answers while the process runs,
// /readyz, which answers 200 only while ready reports true, and /metrics.
func HealthHandler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/metrics", instmetrics.Handler())
	return mux
}

// NewClient returns an uncached API client for the in-cluster or kubeconfig
// configuration, able to read and write what the adapter uses.
func NewClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{galacticv1alpha1.AddToScheme, coordinationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			return nil, err
		}
	}
	rest, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}
	// Every request gives up well before the next renewal is due.
	rest.Timeout = 3 * time.Second
	return client.New(rest, client.Options{Scheme: scheme})
}

// PodFromEnv reads the pod's identity from the downward API variables
// POD_NAMESPACE, POD_NAME, POD_UID and NODE_NAME, its user and group, and
// the node's boot ID.
func PodFromEnv() (masque.Pod, error) {
	return podFromEnv(os.Getenv, "/proc/sys/kernel/random/boot_id")
}

func podFromEnv(getenv func(string) string, bootIDFile string) (masque.Pod, error) {
	p := masque.Pod{
		Namespace: getenv("POD_NAMESPACE"), Name: getenv("POD_NAME"), UID: getenv("POD_UID"),
		Node: getenv("NODE_NAME"), RunAsUser: int64(os.Getuid()), RunAsGroup: int64(os.Getgid()),
	}
	if p.Namespace == "" || p.Name == "" || p.UID == "" || p.Node == "" {
		return p, errors.New("POD_NAMESPACE, POD_NAME, POD_UID and NODE_NAME must be set")
	}
	b, err := os.ReadFile(bootIDFile)
	if err != nil {
		return p, fmt.Errorf("read boot ID: %w", err)
	}
	p.BootID = strings.TrimSpace(string(b))
	return p, nil
}
