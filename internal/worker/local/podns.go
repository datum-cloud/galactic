// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/worker/auth"
)

// ErrPodNotFound means no process of the pod runs on this node, so its
// network namespace cannot be reached.
var ErrPodNotFound = errors.New("local: no process of the pod runs on this node")

// ErrPodHostNetwork means the pod shares the host's network namespace, where
// a routed link has no pod end to go.
var ErrPodHostNetwork = errors.New("local: the pod uses the host's network namespace")

// PodNetns opens the network namespace of a pod on this node.
type PodNetns interface {
	// Open returns a handle on podUID's network namespace, which the caller
	// closes.
	Open(podUID string) (netns.NsHandle, error)
}

// ProcPods is the PodNetns of the host's /proc. It never takes a process
// from a request: it finds one by the pod UID Worker authenticated the
// claim's owner as (auth.Authenticator), and opens that process's namespace
// only while the process's cgroup still names that pod, the same check the
// Worker API applies to its peers (D21). A caller therefore reaches only
// its own pod's namespace.
type ProcPods struct {
	// ProcRoot is the host's /proc, as Worker sees it.
	ProcRoot string
	// Pods maps a process to its pod by its cgroup.
	Pods auth.PodResolver

	mu sync.Mutex
	// last remembers the process each pod was last found by.
	last map[string]int32
}

var _ PodNetns = (*ProcPods)(nil)

// Open implements PodNetns.
func (p *ProcPods) Open(podUID string) (netns.NsHandle, error) {
	if podUID == "" {
		return netns.None(), fmt.Errorf("%w: the claim records no pod", ErrPodNotFound)
	}
	p.mu.Lock()
	pid, ok := p.last[podUID]
	p.mu.Unlock()
	if ok {
		if h, err := p.openPID(podUID, pid); err == nil || errors.Is(err, ErrPodHostNetwork) {
			return h, err
		}
	}
	entries, err := os.ReadDir(p.ProcRoot)
	if err != nil {
		return netns.None(), fmt.Errorf("local: read %s: %w", p.ProcRoot, err)
	}
	// The pod's lowest PID is its sandbox's first process, whose namespace
	// is the pod's; a later process may have unshared its own.
	var pids []int32
	for _, e := range entries {
		if n, err := strconv.ParseInt(e.Name(), 10, 32); err == nil && n > 0 {
			pids = append(pids, int32(n))
		}
	}
	slices.Sort(pids)
	for _, n := range pids {
		h, err := p.openPID(podUID, n)
		if errors.Is(err, errOtherPod) {
			continue
		}
		if err != nil {
			return netns.None(), err
		}
		p.mu.Lock()
		if p.last == nil {
			p.last = map[string]int32{}
		}
		p.last[podUID] = n
		p.mu.Unlock()
		return h, nil
	}
	return netns.None(), fmt.Errorf("%w: pod %s", ErrPodNotFound, podUID)
}

var errOtherPod = errors.New("local: the process belongs to another pod")

// Alive reports whether a process of the pod with podUID runs on this node.
func (p *ProcPods) Alive(podUID string) bool {
	if podUID == "" {
		return false
	}
	entries, err := os.ReadDir(p.ProcRoot)
	if err != nil {
		// Unknown counts as alive, so a pod is never displaced on a guess.
		return true
	}
	for _, e := range entries {
		n, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil || n <= 0 {
			continue
		}
		if uid, err := p.Pods.PodUID(int32(n)); err == nil && uid == podUID {
			return true
		}
	}
	return false
}

// openPID opens pid's network namespace when pid belongs to podUID, before
// and after the open, so a process that exits and has its PID reused in
// between is never mistaken for the pod's.
func (p *ProcPods) openPID(podUID string, pid int32) (netns.NsHandle, error) {
	if uid, err := p.Pods.PodUID(pid); err != nil || uid != podUID {
		return netns.None(), errOtherPod
	}
	h, err := netns.GetFromPath(filepath.Join(p.ProcRoot, strconv.Itoa(int(pid)), "ns", "net"))
	if err != nil {
		return netns.None(), errOtherPod
	}
	if uid, err := p.Pods.PodUID(pid); err != nil || uid != podUID {
		_ = h.Close()
		return netns.None(), errOtherPod
	}
	host, err := netns.GetFromPath(filepath.Join(p.ProcRoot, "1", "ns", "net"))
	if err != nil {
		_ = h.Close()
		return netns.None(), fmt.Errorf("local: open the host's network namespace: %w", err)
	}
	defer host.Close() //nolint:errcheck // our own descriptor
	if h.Equal(host) {
		_ = h.Close()
		return netns.None(), fmt.Errorf("%w: pod %s", ErrPodHostNetwork, podUID)
	}
	return h, nil
}
