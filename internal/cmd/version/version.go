// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"fmt"
	"runtime"
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
