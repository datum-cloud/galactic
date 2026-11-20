// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

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

// TestRoutedLinkPodEndNeedsPtraceAndAdmin shows which capabilities a routed
// link's pod end needs when the pod runs as another user, as pods do: opening
// its network namespace through /proc passes the kernel's ptrace access check
// only with SYS_PTRACE, and entering it needs SYS_ADMIN. The galactic-worker
// container's set from its manifest does both.
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

	opened, err := podEndAccess([]string{"NET_ADMIN", "BPF"}, pid)
	if opened || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("NET_ADMIN and BPF: opened %t, %v; want the open refused", opened, err)
	}
	opened, err = podEndAccess([]string{"NET_ADMIN", "BPF", "SYS_PTRACE"}, pid)
	// The netlink library reports setns's EPERM without wrapping it.
	if !opened || err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("with SYS_PTRACE: opened %t, %v; want it opened and entering refused", opened, err)
	}

	manifest := filepath.Join("..", "..", "..", "config", "galactic-worker", "base", "daemonset.yaml")
	caps, err := loadcaps.ContainerCapabilities(manifest, "galactic-worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := podEndAccess(caps, pid); err != nil {
		t.Fatalf("the galactic-worker container's capabilities %v cannot set up a pod end: %v", caps, err)
	}
}
