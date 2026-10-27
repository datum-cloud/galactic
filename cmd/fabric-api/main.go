// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fabric-api is the fabric looking glass's galactic side. Its node
// subcommand runs as a sidecar in each fabric-router pod and answers bounded
// queries about FRR state and ICMP probes over mTLS gRPC. Its gateway
// subcommand runs once per edge cell, executes FabricQuery objects by fanning
// them out to the node sidecars, and serves an operator debug service. Its
// janitor subcommand deletes expired FabricQuery copies the federation failed
// to clean up, and query is an operator client for both services.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	_ "golang.org/x/crypto/x509roots/fallback"

	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "fabric-api"

	appDesc = `Fabric looking glass

 Answers bounded, asynchronous diagnostics about the fabric routers' FRR
 state, and runs ICMP probes from their fabric loopbacks.

 Find more information at: https://www.datum.net/docs`
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	cmd := &cobra.Command{
		Use:          appName,
		Short:        strings.Split(appDesc, "\n")[0],
		Long:         appDesc,
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				return nil
			}
			return cmd.Help()
		},
	}
	logOpts.BindFlags(cmd.PersistentFlags())
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	cmd.AddCommand(newNodeCommand(), newGatewayCommand(), newJanitorCommand(), newQueryCommand(), newCertSyncCommand())
	return cmd
}

// signalContext returns a context cancelled on SIGINT or SIGTERM.
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
