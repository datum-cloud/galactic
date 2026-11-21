// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// podAccessCapabilities are what a routed link's pod end needs: the kernel's
// ptrace access check refuses opening /proc/<pid>/ns/net of another user's
// process without CAP_SYS_PTRACE, and setns into it needs CAP_SYS_ADMIN.
var podAccessCapabilities = []struct {
	name string
	bit  int
}{
	{"CAP_SYS_PTRACE", unix.CAP_SYS_PTRACE},
	{"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN},
}

// PodAccess reports whether the calling thread can open and enter a pod's
// network namespace: nil when it holds every capability that needs, else an
// error naming those it lacks. Worker calls it at startup, before any thread
// changes its capabilities.
func PodAccess() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("local: read capabilities: %w", err)
	}
	var missing []string
	for _, c := range podAccessCapabilities {
		if data[c.bit/32].Effective&(1<<(c.bit%32)) == 0 {
			missing = append(missing, c.name)
		}
	}
	if len(missing) > 0 {
		return errors.New("Worker lacks " + strings.Join(missing, " and ") +
			", which a routed link's pod end needs; only a placement with routed links grants them")
	}
	return nil
}
