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

// Package cniinstall provides a command to install the galactic CNI binary
// into the host CNI plugin directory. This is used by the cni-installer DaemonSet
// init container which uses the distroless galactic image.
package cniinstall

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// NewCommand returns the cni-install cobra command.
func NewCommand() *cobra.Command {
	var dest string

	cmd := &cobra.Command{
		Use:   "cni-install",
		Short: "Install the galactic CNI binary to the host CNI directory",
		Long: `Copies the galactic binary from the container image to the host CNI plugin
directory. This is intended for use as an init container in the cni-installer
DaemonSet, where the container uses the distroless galactic image (which has
no shell) but needs to place the binary on the host filesystem.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srcPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("finding own executable path: %w", err)
			}

			if err := copyFile(srcPath, dest); err != nil {
				return fmt.Errorf("installing CNI binary to %s: %w", dest, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Installed galactic CNI binary to %s\n", dest)
			return nil
		},
	}

	cmd.Flags().StringVar(&dest, "dest", "/opt/cni/bin/galactic", "Destination path for the CNI binary")

	return cmd
}

// copyFile copies src to dst, creating or overwriting dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copying binary: %w", err)
	}

	return out.Close()
}
