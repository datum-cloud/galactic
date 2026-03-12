/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
