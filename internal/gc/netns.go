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

// ContainerNetNSExists checks whether a network namespace for the given
// container ID is still present on this node. It does this by listing the
// bind-mounts under /var/run/netns and checking whether any of them is
// named after the container ID prefix.
//
// CNI plugins (and the kubelet) create netns bind-mounts under
// /var/run/netns/<container-id-prefix>. When the container is fully
// torn down, these mounts are removed.
func ContainerNetNSExists(containerID string) bool {
	// Use the full container ID and the first 46 characters (same as
	// annotationContainerIDLen used in the CNI plugin for annotation keys).
	id := containerID
	if len(id) > 46 {
		id = id[:46]
	}

	entries, err := os.ReadDir(netnsPath)
	if err != nil {
		// If we can't read /var/run/netns, assume the namespace
		// does not exist (we cannot prove it does).
		return false
	}

	for _, entry := range entries {
		if entry.Name() == id {
			return true
		}
	}
	return false
}

// ContainerNetNSExistsByPath checks whether a network namespace at the
// given path still exists. Returns true if the path is accessible.
func ContainerNetNSExistsByPath(netnsPathStr string) bool {
	_, err := os.Stat(filepath.Join(netnsPath, filepath.Base(netnsPathStr)))
	return err == nil
}
