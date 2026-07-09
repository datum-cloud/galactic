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

// NetNSExists checks whether the network namespace at the given path (as
// recorded by the CNI plugin at ADD time — see cni.netnsAnnotationKey) is
// still present on this node.
//
// This cannot be reconstructed from a container ID: netns bind-mounts are
// named by the container runtime's own convention (e.g. containerd's
// "cni-<uuid>"), which has no relationship to the container ID the CNI
// plugin receives. The exact path used at ADD time must be recorded and
// checked verbatim.
func NetNSExists(netnsPathStr string) bool {
	if netnsPathStr == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(netnsPath, filepath.Base(netnsPathStr)))
	return err == nil
}
