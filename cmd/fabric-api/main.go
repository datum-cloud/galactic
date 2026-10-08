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
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

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
	var logLevel, logFormat string
	cmd := &cobra.Command{
		Use:          appName,
		Short:        strings.Split(appDesc, "\n")[0],
		Long:         appDesc,
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return setupLogging(logLevel, logFormat)
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
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", envOr("LOG_LEVEL", "info"),
		"Log level: debug, info, warn, error (env LOG_LEVEL)")
	cmd.PersistentFlags().StringVar(&logFormat, "log-format", envOr("LOG_FORMAT", "json"),
		"Log format: json or text (env LOG_FORMAT)")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	cmd.AddCommand(newNodeCommand(), newGatewayCommand(), newJanitorCommand(), newQueryCommand(), newCertSyncCommand())
	return cmd
}

func setupLogging(level, format string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: l}
	switch format {
	case "json":
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, opts)))
	case "text":
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
	default:
		return fmt.Errorf("--log-format must be json or text, not %q", format)
	}
	return nil
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
