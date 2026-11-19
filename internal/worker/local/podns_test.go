// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// podB is a pod other than the one a test opens.
const podB = "pod-b"

// cgroupPods maps a process to its pod as the fixture's cgroup files say.
type cgroupPods map[int32]string

func (c cgroupPods) PodUID(pid int32) (string, error) {
	if uid, ok := c[pid]; ok {
		return uid, nil
	}
	return "", errors.New("no pod")
}

// procRoot builds a /proc with a directory per pid whose network namespace
// is the test's own, and a pid 1 whose namespace is the same: the host's.
func procRoot(t *testing.T, pids ...int32) string {
	t.Helper()
	root := t.TempDir()
	for _, pid := range append(pids, 1) {
		dir := filepath.Join(root, strconv.Itoa(int(pid)), "ns")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/proc/self/ns/net", filepath.Join(dir, "net")); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestProcPodsOpensOnlyTheCallersPod checks that a claim reaches no
// namespace but its own pod's: another pod's processes are never used, a
// pod with no process is not found, a claim without a pod reaches nothing,
// and a pod on the host's network is refused rather than given the host's
// namespace.
func TestProcPodsOpensOnlyTheCallersPod(t *testing.T) {
	root := procRoot(t, 100, 200)
	pods := &ProcPods{ProcRoot: root, Pods: cgroupPods{100: podB, 200: podB}}
	if h, err := pods.Open("pod-a"); !errors.Is(err, ErrPodNotFound) {
		_ = h.Close()
		t.Fatalf("Open(pod-a) with only pod-b's processes = %v, want ErrPodNotFound", err)
	}
	if h, err := pods.Open(""); !errors.Is(err, ErrPodNotFound) {
		_ = h.Close()
		t.Fatalf("Open with no pod = %v, want ErrPodNotFound", err)
	}
	// pod-b's processes share the host's namespace in this fixture.
	if h, err := pods.Open(podB); !errors.Is(err, ErrPodHostNetwork) {
		_ = h.Close()
		t.Fatalf("Open(pod-b) on the host's network = %v, want ErrPodHostNetwork", err)
	}
	// A process that moves to another pod after it was found is not used
	// again.
	pods.Pods = cgroupPods{200: "pod-c"}
	if h, err := pods.Open(podB); !errors.Is(err, ErrPodNotFound) {
		_ = h.Close()
		t.Fatalf("Open(pod-b) after its processes left = %v, want ErrPodNotFound", err)
	}
}

// TestProcPodsAlive checks that a pod runs while a process's cgroup names it.
func TestProcPodsAlive(t *testing.T) {
	pods := &ProcPods{ProcRoot: procRoot(t, 100), Pods: cgroupPods{100: podB}}
	if !pods.Alive(podB) || pods.Alive("pod-a") || pods.Alive("") {
		t.Fatal("Alive did not follow the processes' pods")
	}
}
