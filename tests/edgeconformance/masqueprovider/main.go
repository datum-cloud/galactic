// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Command masqueprovider is the Galactic Edge conformance suite's MASQUE
// fixture: a CONNECT-IP (RFC 9484) server over HTTP/3 that runs as an
// unprivileged Galactic Edge provider through internal/edge/masque, the
// MASQUE provider adapter. The adapter holds the pod's EdgeInstance lease,
// requests the PacketAccess attachment of each admitted connector's
// EdgeService, claims the connector's /96 EdgeRoute, and carries its
// packets on the packet device galactic-edge creates in the pod. It needs
// no host namespace, hostPath, NET_ADMIN or BPF.
//
// Authorization is a test fixture, not a product authority: each connector
// is a static bearer credential bound to one service's VPC and one /96.
//
// SIGTERM stops the server, which ends every session, then the adapter
// releases the routes, deletes the attachments and releases the lease.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	"go.datum.net/galactic/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "masqueprovider:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/masque/config.yaml", "configuration file")
	certPath := flag.String("tls-cert", "/etc/masque/tls/tls.crt", "server certificate")
	keyPath := flag.String("tls-key", "/etc/masque/tls/tls.key", "server key")
	flag.Parse()
	logging.SetupFile(os.Stderr, slog.LevelInfo)
	log := slog.Default()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return err
	}
	pod, err := podFromEnv()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{galacticv1alpha1.AddToScheme, coordinationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			return err
		}
	}
	rest, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	// Every request gives up well before the next renewal is due.
	rest.Timeout = 3 * time.Second
	c, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	claims := &claim.Instance{
		ID: rand.Text(), Clock: timing.BootClock, Params: timing.Params,
		Store: provider.InstanceStore{Client: c, Namespace: pod.Namespace, Duration: timing.Params.Duration},
	}
	a, err := masque.New(masque.Config{
		Client: c, Provider: cfg.Provider, Pod: pod, Authorizer: cfg, Claims: claims,
		OpenDevice: masque.OpenTUN, Log: log.With("podName", pod.Name),
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := a.Start(ctx); err != nil {
		return err
	}

	srv, err := connectip.NewServer(connectip.Config{
		Authority: cfg.Authority,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Admission: a, Backend: a, Logger: log,
	})
	if err != nil {
		return err
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.Listen)
	if err != nil {
		return err
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(pc) }()
	runCtx, cancelRun := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(runCtx) }()

	var stopped error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		stopped = fmt.Errorf("HTTP/3 server stopped: %w", err)
	case err := <-runErr:
		// Run ends early only when the instance's lease can never be held.
		runErr <- err
	}
	// Sessions end before the routes, attachments and lease are released.
	_ = srv.Close()
	cancelRun()
	if err := <-runErr; err != nil {
		stopped = errors.Join(stopped, fmt.Errorf("adapter stopped: %w", err))
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return errors.Join(stopped, a.Shutdown(sctx))
}

// podFromEnv reads the pod's identity from the downward API variables the
// Deployment sets, and the node's boot ID.
func podFromEnv() (masque.Pod, error) {
	p := masque.Pod{
		Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME"), UID: os.Getenv("POD_UID"),
		Node: os.Getenv("NODE_NAME"), RunAsUser: int64(os.Getuid()), RunAsGroup: int64(os.Getgid()),
	}
	if p.Namespace == "" || p.Name == "" || p.UID == "" || p.Node == "" {
		return p, errors.New("POD_NAMESPACE, POD_NAME, POD_UID and NODE_NAME must be set")
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return p, fmt.Errorf("read boot ID: %w", err)
	}
	p.BootID = strings.TrimSpace(string(b))
	return p, nil
}
