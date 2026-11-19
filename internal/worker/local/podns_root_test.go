// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netns"
)

// TestProcPodsOpensThePodRoot checks that the caller's pod's namespace is
// the one opened: a process whose cgroup names the pod and whose namespace
// is not the host's.
func TestProcPodsOpensThePodRoot(t *testing.T) {
	requireRoot(t)
	pod, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pod.Close() })
	root := procRoot(t, 100)
	podNet := filepath.Join(root, "300", "ns", "net")
	if err := os.MkdirAll(filepath.Dir(podNet), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("/proc/self/fd/%d", pod.Fd()), podNet); err != nil {
		t.Fatal(err)
	}
	pods := &ProcPods{ProcRoot: root, Pods: cgroupPods{100: podB, 300: "pod-a"}}
	h, err := pods.Open("pod-a")
	if err != nil {
		t.Fatalf("Open(pod-a): %v", err)
	}
	defer h.Close() //nolint:errcheck // test descriptor
	want := netns.NsHandle(int(pod.Fd()))
	if !h.Equal(want) {
		t.Fatalf("Open(pod-a) = %v, want the pod's namespace %v", h, want)
	}
}
