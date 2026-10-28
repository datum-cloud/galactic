// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Command masque-provider is the MASQUE connector service: a CONNECT-IP
// (RFC 9484) server over HTTP/3 that runs as an unprivileged Galactic Edge
// provider (internal/edge/masque/service). Every request is authorized by
// the MASQUE grant authority (cmd/masque-authority); the command accepts no
// local credential. It serves /healthz, /readyz and /metrics on
// --health-listen.
//
// SIGTERM stops the server, which ends every session, then releases the
// routes, deletes the attachments and releases the lease.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/certreload"
	"go.datum.net/galactic/internal/edge/masque/authority"
	"go.datum.net/galactic/internal/edge/masque/service"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

type options struct {
	provider, authority, listen, healthListen string
	certFile, keyFile                         string
	authorityURL, authorityCA, tokenFile      string
}

func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	o := &options{}
	cmd := &cobra.Command{
		Use:          "masque-provider",
		Short:        "Serve MASQUE CONNECT-IP connectors into their gVPCs",
		Version:      metadata.Version,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		PreRunE: func(*cobra.Command, []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error { return run(cmd.Context(), o) },
	}
	logOpts.BindFlags(cmd.Flags())
	f := cmd.Flags()
	f.StringVar(&o.provider, "provider", "", "EdgeProvider this pod runs as (required)")
	f.StringVar(&o.authority, "authority", "", "host[:port] clients send as :authority (required)")
	f.StringVar(&o.listen, "listen", ":8443", "UDP address the HTTP/3 server listens on")
	f.StringVar(&o.healthListen, "health-listen", ":9188", "TCP address serving /healthz, /readyz and /metrics")
	f.StringVar(&o.certFile, "tls-cert", "/etc/masque-provider/tls/tls.crt", "Server certificate, reread on change")
	f.StringVar(&o.keyFile, "tls-key", "/etc/masque-provider/tls/tls.key", "Server key, reread on change")
	f.StringVar(&o.authorityURL, "grant-authority-url", "", "https:// base URL of the MASQUE grant authority (required)")
	f.StringVar(&o.authorityCA, "grant-authority-ca", "/etc/masque-provider/authority/ca.crt",
		"PEM roots the grant authority's certificate chains to, reread on change")
	f.StringVar(&o.tokenFile, "grant-authority-token", "/var/run/secrets/masque-authority/token",
		"Projected ServiceAccount token for the grant authority's audience, reread on every call")
	return cmd
}

func (o *options) validate() error {
	switch {
	case o.provider == "" || o.authority == "":
		return errors.New("--provider and --authority are required")
	case !strings.HasPrefix(o.authorityURL, "https://"):
		return errors.New("--grant-authority-url must be an https:// URL")
	case o.authorityCA == "" || o.tokenFile == "" || o.certFile == "" || o.keyFile == "":
		return errors.New("--grant-authority-ca, --grant-authority-token, --tls-cert and --tls-key must not be empty")
	}
	return nil
}

func run(parent context.Context, o *options) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	certs := &certreload.Reloader{CertFile: o.certFile, KeyFile: o.keyFile}
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
	return service.Run(ctx, service.Config{
		Client: c, Provider: o.provider, Authority: o.authority, Listen: o.listen, HealthListen: o.healthListen,
		Pod: pod, GetCertificate: certs.GetCertificate,
		Authorizer: &authority.Client{URL: o.authorityURL, CAFile: o.authorityCA, TokenFile: o.tokenFile},
	})
}
