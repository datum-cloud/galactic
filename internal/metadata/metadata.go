// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metadata exposes build-time variables stamped in via -ldflags.
package metadata

import (
	"fmt"
	"os"
	"runtime"
)

var (
	// Version is the release tag (e.g. v0.1.0). Set at build time.
	Version = "dev"
	// GitCommit is the short SHA of the build commit. Set at build time.
	GitCommit = "unknown"
	// GitTreeState is "clean" or "dirty". Set at build time.
	GitTreeState = "unknown"
	// BuildDate is the RFC3339 UTC timestamp of the build. Set at build time.
	BuildDate = "unknown"
	// GoVersion is the Go toolchain version used for the build.
	GoVersion = runtime.Version()
	// Platform is the OS/arch pair of the build host.
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	// Executable is the full path to the running binary as reported by the OS.
	Executable = func() string {
		exe, err := os.Executable()
		if err != nil {
			return "unknown"
		}
		return exe
	}()
)
