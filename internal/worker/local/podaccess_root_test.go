// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/yaml"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// The base capabilities every galactic-worker placement grants.
var baseCapabilities = []string{"NET_ADMIN", "BPF"}

// podEndAccess opens pid's network namespace through /proc and opens a
// netlink handle in it, as a routed link's pod end is opened and set up
// (podns.go, setUpInPod), on a thread holding only caps.
func podEndAccess(caps []string, pid int) (opened bool, err error) {
	err = loadcaps.Run(caps, func() error {
		h, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		defer h.Close() //nolint:errcheck // our own descriptor
		opened = true
		nh, err := netlink.NewHandleAt(h)
		if err != nil {
			return fmt.Errorf("enter: %w", err)
		}
		defer func() { _ = nh.Close() }()
		if _, err := nh.LinkList(); err != nil {
			return fmt.Errorf("list links: %w", err)
		}
		return nil
	})
	return opened, err
}

// routedLinkCapabilities returns the galactic-worker container's
// capabilities in a placement with the routed-link Component: the base
// manifest's and those the Component's patch adds.
func routedLinkCapabilities(t *testing.T) []string {
	t.Helper()
	cfg := filepath.Join("..", "..", "..", "config", "galactic-worker")
	caps, err := loadcaps.ContainerCapabilities(filepath.Join(cfg, "base", "daemonset.yaml"), "galactic-worker")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(cfg, "profiles", "routed-link", "patch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ops []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	if err := yaml.Unmarshal(b, &ops); err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if op.Op == "add" && strings.HasSuffix(op.Path, "/capabilities/add/-") {
			caps = append(caps, fmt.Sprint(op.Value))
		}
	}
	return caps
}

// TestRoutedLinkPodEndNeedsPtraceAndAdmin shows which capabilities a routed
// link's pod end needs when the pod runs as another user, as pods do: opening
// its network namespace through /proc passes the kernel's ptrace access check
// only with SYS_PTRACE, and entering it needs SYS_ADMIN. The galactic-worker
// container's set with the routed-link Component does both.
func TestRoutedLinkPodEndNeedsPtraceAndAdmin(t *testing.T) {
	requireRoot(t)
	// The pod stand-in: an unprivileged process in its own network
	// namespace, like a pod's first process.
	cmd := exec.CommandContext(t.Context(), "sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET,
		Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid

	opened, err := podEndAccess(baseCapabilities, pid)
	if opened || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("NET_ADMIN and BPF: opened %t, %v; want the open refused", opened, err)
	}
	opened, err = podEndAccess(append(slices.Clone(baseCapabilities), "SYS_PTRACE"), pid)
	// The netlink library reports setns's EPERM without wrapping it.
	if !opened || err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("with SYS_PTRACE: opened %t, %v; want it opened and entering refused", opened, err)
	}

	caps := routedLinkCapabilities(t)
	if _, err := podEndAccess(caps, pid); err != nil {
		t.Fatalf("the routed-link profile's capabilities %v cannot set up a pod end: %v", caps, err)
	}
}

// TestPodAccessDetectsCapabilities checks that PodAccess names what a thread
// without the routed link capabilities lacks, and passes one with them.
func TestPodAccessDetectsCapabilities(t *testing.T) {
	requireRoot(t)
	var got error
	if err := loadcaps.Run(baseCapabilities, func() error { got = PodAccess(); return nil }); err != nil {
		t.Fatal(err)
	}
	if got == nil || !strings.Contains(got.Error(), "CAP_SYS_PTRACE and CAP_SYS_ADMIN") {
		t.Fatalf("PodAccess with NET_ADMIN and BPF = %v, want both named", got)
	}
	if err := loadcaps.Run(append(slices.Clone(baseCapabilities), "SYS_PTRACE", "SYS_ADMIN"),
		func() error { got = PodAccess(); return nil }); err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("PodAccess with the routed link capabilities = %v, want nil", got)
	}
}

// TestRoutedLinkCapabilityStatus checks that a Local module without pod
// access reports local.routed_link and local.socket unavailable with
// RoutedLinkUnavailable and the others available, and one with it reports
// all four available.
func TestRoutedLinkCapabilityStatus(t *testing.T) {
	r := newRig(t, "capstatus", xdpmode.Native)
	for _, tc := range []struct {
		access error
		want   map[string]string
	}{
		{errors.New("Worker lacks CAP_SYS_PTRACE and CAP_SYS_ADMIN"), map[string]string{
			workerv1alpha1.CapabilityLocalTap: "", workerv1alpha1.CapabilityLocalVethPair: "",
			workerv1alpha1.CapabilityLocalRoutedLink: workerv1alpha1.ReasonRoutedLinkUnavailable,
			workerv1alpha1.CapabilityLocalSocket:     workerv1alpha1.ReasonRoutedLinkUnavailable}},
		{nil, map[string]string{workerv1alpha1.CapabilityLocalTap: "", workerv1alpha1.CapabilityLocalVethPair: "",
			workerv1alpha1.CapabilityLocalRoutedLink: "", workerv1alpha1.CapabilityLocalSocket: ""}},
	} {
		m, err := New(Config{Kernel: r.kernel, Node: testNode, PodAccess: tc.access})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, c := range m.Capabilities() {
			if c.Available != (c.Reason == "") {
				t.Fatalf("%s: available %t with reason %q", c.Name, c.Available, c.Reason)
			}
			got[c.Name] = c.Reason
		}
		if !maps.Equal(got, tc.want) {
			t.Fatalf("pod access %v: capabilities %v, want %v", tc.access, got, tc.want)
		}
	}
}
