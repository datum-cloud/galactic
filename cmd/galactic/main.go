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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/cmd/agent"
	"go.datum.net/galactic/internal/cmd/cni"
	"go.datum.net/galactic/internal/cmd/cniinstall"
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
	rootCmd.AddCommand(cniinstall.NewCommand())
	rootCmd.AddCommand(version.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
