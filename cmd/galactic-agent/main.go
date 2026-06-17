// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/agent"
)

func main() {
	if err := newRootCommand().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	opts := &agent.Options{}

	cmd := &cobra.Command{
		Use:          "galactic-agent",
		Short:        "BGP Provider implementation for Cosmos",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return agent.Run(cmd.Context(), *opts)
		},
	}

	cmd.Flags().StringVar(&opts.NodeName, "node-name", "", "Override node name (default: NODE_NAME env var)")
	cmd.Flags().StringVar(&opts.Role, "role", "overlay",
		"Agent role published on the BGPProvider label galactic.io/role (overlay, overlay-rr)")
	cmd.Flags().IntVar(&opts.Port, "port", 33438,
		"Port for the gRPC server that cosmos uses to configure the BGP provider")
	cmd.Flags().IntVar(&opts.HealthPort, "health-port", 5000,
		"Port for the gRPC health server (Kubernetes liveness and readiness probes)")

	return cmd
}
