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
// By default authorization is a test fixture, not a product authority: each
// connector is a static bearer credential bound to one service's VPC and
// one /96. With grantAuthority set, the fixture authorizes through a MASQUE
// grant authority (cmd/masque-authority) instead.
//
// It runs internal/edge/masque/service, as cmd/masque-provider does, so the
// two differ only in their Authorizer.
//
// SIGTERM stops the server, which ends every session, then the adapter
// releases the routes, deletes the attachments and releases the lease.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.datum.net/galactic/internal/certreload"
	"go.datum.net/galactic/internal/edge/masque/service"
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

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	certs := &certreload.Reloader{CertFile: *certPath, KeyFile: *keyPath}
	if _, err := certs.GetCertificate(nil); err != nil {
		return err
	}
	pod, err := service.PodFromEnv()
	if err != nil {
		return err
	}
	c, err := service.NewClient()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return service.Run(ctx, service.Config{
		Client: c, Provider: cfg.Provider, Authority: cfg.Authority, Listen: cfg.Listen,
		Pod: pod, Authorizer: cfg.Authorizer(), GetCertificate: certs.GetCertificate,
	})
}
