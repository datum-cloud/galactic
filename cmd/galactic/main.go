// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/cmd/agent"
	"go.datum.net/galactic/internal/cmd/cni"
	"go.datum.net/galactic/internal/cmd/operator"
	"go.datum.net/galactic/internal/cmd/version"
)

func main() {
	// Auto-detect CNI mode via CNI_COMMAND environment variable
	// When run as a CNI plugin, the CNI runtime sets this variable
	if os.Getenv("CNI_COMMAND") != "" {
		if err := cni.NewCommand().Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal CLI mode with subcommands
	rootCmd := &cobra.Command{
		Use:   "galactic",
		Short: "Galactic multi-cloud networking solution",
		Long: `Galactic provides VPC connectivity across multiple clouds using SRv6 packet routing.

This unified binary supports multiple modes of operation:
- operator: Kubernetes operator for VPC/VPCAttachment CRDs
- agent: Local network agent for SRv6 route management
- cni: CNI plugin for container network attachment
`,
	}

	// Add subcommands
	rootCmd.AddCommand(operator.NewCommand())
	rootCmd.AddCommand(agent.NewCommand())
	rootCmd.AddCommand(cni.NewCommand())
	rootCmd.AddCommand(version.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
