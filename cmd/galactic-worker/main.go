// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-worker is Galactic Worker: the node-local service agents
// call to deliver tenant traffic, and the single writer of shared host state
// (docs/worker/README.md). This binary wires internal/worker to its unix
// socket, the Kubernetes trusted sources, TokenReview, the allowlist, the
// ownership fence, metrics and a gRPC health server.
//
// No delivery module is built in yet: Local (#1435) and Fabric (#1436)
// register here. Until then every capability reports ModuleNotRunning and an
// accepted claim reports Programmed=False with that reason.
//
// Worker needs the host PID namespace and read access to the host's /proc
// to map a connecting process to its pod.
package main

import (
	"os"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
