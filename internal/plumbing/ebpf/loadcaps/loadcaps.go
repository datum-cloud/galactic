// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loadcaps lets tests load eBPF programs with the capabilities a
// production container actually holds.
//
// The verifier applies a stricter ruleset to a loader without CAP_PERFMON. For
// example, it rejects adding a variable offset to a packet pointer. A test that
// loads as full root never sees that ruleset, so a program can pass CI and
// still be rejected on every node. The capability lists come from the
// DaemonSet manifests, so a test cannot drift from what a cluster runs.
package loadcaps

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"

	"golang.org/x/sys/unix"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

var capabilityBits = map[string]int{
	"BPF":              unix.CAP_BPF,
	"CHOWN":            unix.CAP_CHOWN,
	"DAC_OVERRIDE":     unix.CAP_DAC_OVERRIDE,
	"FOWNER":           unix.CAP_FOWNER,
	"NET_ADMIN":        unix.CAP_NET_ADMIN,
	"NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE,
	"NET_RAW":          unix.CAP_NET_RAW,
	"PERFMON":          unix.CAP_PERFMON,
	"SYS_ADMIN":        unix.CAP_SYS_ADMIN,
	"SYS_RESOURCE":     unix.CAP_SYS_RESOURCE,
}

// ContainerCapabilities returns the capabilities that the named container in a
// DaemonSet manifest adds.
//
// It requires the container to drop ALL. Otherwise the runtime's default set
// also applies, and the added list alone would understate what the container
// holds.
func ContainerCapabilities(manifestPath, containerName string) ([]string, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", manifestPath, err)
	}
	var ds appsv1.DaemonSet
	if err := yaml.Unmarshal(data, &ds); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", manifestPath, err)
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != containerName {
			continue
		}
		sc := c.SecurityContext
		if sc == nil || sc.Capabilities == nil || !slices.Contains(sc.Capabilities.Drop, "ALL") {
			return nil, fmt.Errorf("container %q in %s does not drop ALL capabilities", containerName, manifestPath)
		}
		added := make([]string, 0, len(sc.Capabilities.Add))
		for _, capName := range sc.Capabilities.Add {
			added = append(added, string(capName))
		}
		return added, nil
	}
	return nil, fmt.Errorf("no container %q in %s", containerName, manifestPath)
}

// Run calls fn on an OS thread whose effective and permitted capability sets
// hold exactly caps, and returns fn's error.
//
// Capabilities belong to a thread, so fn must make its bpf() calls from the
// calling goroutine. The thread is never unlocked, which makes the runtime
// discard it when fn returns instead of reusing it with reduced capabilities.
func Run(caps []string, fn func() error) error {
	var want [2]unix.CapUserData
	for _, name := range caps {
		bit, ok := capabilityBits[name]
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		want[bit/32].Effective |= 1 << (bit % 32)
		want[bit/32].Permitted |= 1 << (bit % 32)
	}

	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()

		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		if err := unix.Capset(&hdr, &want[0]); err != nil {
			errc <- fmt.Errorf("capset %v: %w", caps, err)
			return
		}
		var got [2]unix.CapUserData
		hdr = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		if err := unix.Capget(&hdr, &got[0]); err != nil {
			errc <- fmt.Errorf("capget: %w", err)
			return
		}
		for i := range got {
			if got[i].Effective != want[i].Effective {
				errc <- errors.New("thread capabilities do not match the requested set")
				return
			}
		}
		errc <- fn()
	}()
	return <-errc
}
