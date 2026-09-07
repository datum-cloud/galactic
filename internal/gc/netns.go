// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gc provides garbage collection for stale Galactic resources left
// behind when containers are force-terminated and CNI DEL never fires.
package gc

import (
	"os"
	"path/filepath"
)

const netnsPath = "/var/run/netns"

// NetNSExists reports whether the network namespace at netnsPathStr, as recorded
// by the CNI plugin at ADD time, is still present on this node.
//
// The path cannot be reconstructed from a container ID: namespace bind mounts
// are named by the runtime's own convention, which bears no relationship to the
// ID the plugin receives. The exact path used at ADD must be recorded and
// checked verbatim.
func NetNSExists(netnsPathStr string) bool {
	if netnsPathStr == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(netnsPath, filepath.Base(netnsPathStr)))
	return err == nil
}
