// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"github.com/spf13/cobra"

	cniimpl "go.datum.net/galactic/internal/cni"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni",
		Short: "Run as a CNI plugin",
		Long: `The CNI plugin is invoked by the container runtime to set up network interfaces
for pods. It configures VRF, veth pairs, routes, and communicates with the agent
via gRPC to register network attachments.

This command is typically invoked automatically by the container runtime when the
CNI_COMMAND environment variable is set. The main binary auto-detects CNI mode
and invokes this subcommand.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Delegate to the CNI implementation
			cniimpl.NewCommand().Run(cmd, args)
		},
	}

	return cmd
}
