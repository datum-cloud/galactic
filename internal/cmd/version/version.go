// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Version information - set via ldflags during build
	Version      = "dev"
	GitCommit    = "unknown"
	GitTreeState = "unknown"
	BuildDate    = "unknown"
	GoVersion    = runtime.Version()
	Platform     = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print the version, git commit, build date, and platform information for this binary.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Galactic Version: %s\n", Version)
			fmt.Printf("Git Commit: %s\n", GitCommit)
			fmt.Printf("Git Tree State: %s\n", GitTreeState)
			fmt.Printf("Build Date: %s\n", BuildDate)
			fmt.Printf("Go Version: %s\n", GoVersion)
			fmt.Printf("Platform: %s\n", Platform)
		},
	}

	return cmd
}
