// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command masque-authority is the MASQUE grant authority. "serve" answers
// the MASQUE provider pods' Authorize, Refresh and Retire calls over HTTPS
// and sweeps revoked authorizations. The "ledger" and "grant" commands are
// the operator's internal provisioning path: they create allocation ledgers
// and connector grants, print a new credential exactly once, and rotate,
// disable or retire connectors.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/certreload"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/masque/authority"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	var namespace string
	cmd := &cobra.Command{
		Use:          "masque-authority",
		Short:        "Authorize MASQUE connectors and provision their grants",
		Version:      metadata.Version,
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
	}
	logOpts.BindFlags(cmd.PersistentFlags())
	cmd.PersistentFlags().StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"),
		"Namespace holding the grant records and ledgers (env POD_NAMESPACE)")
	cmd.AddCommand(newServeCommand(&namespace), newLedgerCommand(&namespace), newGrantCommand(&namespace))
	return cmd
}

// newClient returns an uncached API client.
func newClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}
	// Every call gives up well before its two-second budget would let a
	// stale answer through.
	cfg.Timeout = 2 * time.Second
	return client.New(cfg, client.Options{Scheme: scheme})
}

func requireNamespace(ns string) error {
	if ns == "" {
		return errors.New("--namespace or POD_NAMESPACE is required")
	}
	return nil
}

type serveOptions struct {
	provider, providerSA, cell, listen, certFile, keyFile, audience string
	sweep                                                           time.Duration
}

func newServeCommand(namespace *string) *cobra.Command {
	o := &serveOptions{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the provider pods' Authorize, Refresh and Retire calls",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return serve(cmd.Context(), *namespace, o) },
	}
	f := cmd.Flags()
	f.StringVar(&o.provider, "provider", "", "EdgeProvider the issued EdgeServices grant (required)")
	f.StringVar(&o.providerSA, "provider-service-account", "",
		"namespace/name of the ServiceAccount the provider pods run as; no other caller is served (required)")
	f.StringVar(&o.cell, "cell", "", "This cell's name; only its grant records are honored (required)")
	f.StringVar(&o.listen, "listen", ":8443", "HTTPS listen address")
	f.StringVar(&o.certFile, "tls-cert", "/etc/masque-authority/tls/tls.crt", "Server certificate, reread on change")
	f.StringVar(&o.keyFile, "tls-key", "/etc/masque-authority/tls/tls.key", "Server key, reread on change")
	f.StringVar(&o.audience, "audience", authority.DefaultAudience, "Audience of the provider pods' tokens")
	f.DurationVar(&o.sweep, "sweep-interval", time.Second, "How often revoked authorizations are swept")
	return cmd
}

func serve(parent context.Context, namespace string, o *serveOptions) error {
	if err := requireNamespace(namespace); err != nil {
		return err
	}
	saNS, saName, ok := strings.Cut(o.providerSA, "/")
	if o.provider == "" || o.cell == "" || !ok || saNS == "" || saName == "" {
		return errors.New("--provider, --cell and --provider-service-account namespace/name are required")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := newClient()
	if err != nil {
		return err
	}
	certs := &certreload.Reloader{CertFile: o.certFile, KeyFile: o.keyFile}
	if _, err := certs.GetCertificate(nil); err != nil {
		return err
	}
	a := &authority.Authority{
		Client: c, Namespace: namespace, Provider: o.provider, Cell: o.cell,
		ProviderServiceAccount: admission.ServiceAccount{Namespace: saNS, Name: saName}, Log: slog.Default(),
	}
	reviewer := authority.KubeTokenReviewer{Client: c, Audience: o.audience}
	srv := &http.Server{
		Addr:              o.listen,
		Handler:           (&authority.Server{Authority: a, Reviewer: reviewer}).Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certs.GetCertificate},
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go a.RunSweeps(ctx, o.sweep)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	slog.Info("serving", "listen", o.listen, "provider", o.provider, "cell", o.cell)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func newLedgerCommand(namespace *string) *cobra.Command {
	var vpc, cell, connectors, pools string
	cmd := &cobra.Command{Use: "ledger", Short: "Manage connector allocation ledgers"}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the allocation ledger of a VPC in a cell",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireNamespace(*namespace); err != nil {
				return err
			}
			ref, err := parseVPC(vpc)
			if err != nil {
				return err
			}
			cp, err := netip.ParsePrefix(connectors)
			if err != nil {
				return fmt.Errorf("--connectors: %w", err)
			}
			pp, err := netip.ParsePrefix(pools)
			if err != nil {
				return fmt.Errorf("--pools: %w", err)
			}
			c, err := newClient()
			if err != nil {
				return err
			}
			l := authority.Ledgers{Client: c, Namespace: *namespace, Now: time.Now}
			return l.Init(cmd.Context(), ref, cell, cp, pp)
		},
	}
	f := initCmd.Flags()
	f.StringVar(&vpc, "vpc", "", "VPC as namespace/name (required)")
	f.StringVar(&cell, "cell", "", "Cell name (required)")
	f.StringVar(&connectors, "connectors", "", "Reserved IPv6 /80 the connector /96s come from (required)")
	f.StringVar(&pools, "pools", "", "Reserved IPv6 /80 the attachment /120 pools come from (required)")
	cmd.AddCommand(initCmd)
	return cmd
}

func newGrantCommand(namespace *string) *cobra.Command {
	cmd := &cobra.Command{Use: "grant", Short: "Provision, rotate, disable and retire connector grants"}
	grants := func() (authority.Grants, error) {
		if err := requireNamespace(*namespace); err != nil {
			return authority.Grants{}, err
		}
		c, err := newClient()
		return authority.Grants{Client: c, Namespace: *namespace, Now: time.Now}, err
	}

	var req authority.CreateRequest
	var vpc, ingress, egress string
	var routes []string
	create := &cobra.Command{
		Use:   "create",
		Short: "Allocate a connector and print its new credential once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g, err := grants()
			if err != nil {
				return err
			}
			if req.VPC, err = parseVPC(vpc); err != nil {
				return err
			}
			for _, r := range routes {
				p, err := netip.ParsePrefix(r)
				if err != nil {
					return fmt.Errorf("--route: %w", err)
				}
				req.Routes = append(req.Routes, p)
			}
			if ingress != "" || egress != "" {
				req.TrafficPolicy = &galacticv1alpha1.TrafficPolicyBindingSpec{}
				if ingress != "" {
					req.TrafficPolicy.IngressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: ingress}
				}
				if egress != "" {
					req.TrafficPolicy.EgressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: egress}
				}
			}
			issued, err := g.Create(cmd.Context(), req)
			if err != nil {
				return err
			}
			return printJSON(cmd, issued)
		},
	}
	f := create.Flags()
	f.StringVar(&vpc, "vpc", "", "VPC as namespace/name (required)")
	f.StringVar(&req.Cell, "cell", "", "Cell name (required)")
	f.StringVar(&req.Connector, "connector", "", "Connector UUID; empty generates one")
	f.DurationVar(&req.Lifetime, "lifetime", authority.MaxLifetime, "Credential lifetime, at most 24h")
	f.StringSliceVar(&routes, "route", nil, "gVPC destination prefix the connector may reach; repeatable")
	f.StringVar(&ingress, "ingress-policy", "", "TrafficPolicy for traffic delivered to the connector")
	f.StringVar(&egress, "egress-policy", "", "TrafficPolicy for traffic the connector sends")

	var lifetime time.Duration
	rotate := &cobra.Command{
		Use:   "rotate CONNECTOR",
		Short: "Replace a connector's credential and print the new one once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := grants()
			if err != nil {
				return err
			}
			issued, err := g.Rotate(cmd.Context(), args[0], lifetime)
			if err != nil {
				return err
			}
			return printJSON(cmd, issued)
		},
	}
	rotate.Flags().DurationVar(&lifetime, "lifetime", authority.MaxLifetime, "Credential lifetime, at most 24h")

	disable := &cobra.Command{
		Use:   "disable CONNECTOR",
		Short: "Revoke a connector; its allocation is kept",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := grants()
			if err != nil {
				return err
			}
			return g.Disable(cmd.Context(), args[0])
		},
	}
	retire := &cobra.Command{
		Use:   "retire CONNECTOR",
		Short: "Revoke a connector and tombstone its allocation for good",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := grants()
			if err != nil {
				return err
			}
			return g.Retire(cmd.Context(), args[0])
		},
	}
	cmd.AddCommand(create, rotate, disable, retire)
	return cmd
}

func parseVPC(s string) (authority.VPCRef, error) {
	ns, name, ok := strings.Cut(s, "/")
	if !ok || ns == "" || name == "" {
		return authority.VPCRef{}, fmt.Errorf("--vpc %q is not namespace/name", s)
	}
	return authority.VPCRef{Namespace: ns, Name: name}, nil
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
