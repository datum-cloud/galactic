// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ErrNamespaceReplaced is returned when the path a Namespace was opened from
// no longer names the namespace the handle holds: the pod sandbox was torn
// down and another namespace, possibly a replacement sandbox for the same
// pod, now sits at that path.
var ErrNamespaceReplaced = errors.New("hostattach: network namespace at path was replaced")

// Namespace is an open handle to one live network namespace, bound to the
// path it was opened from.
//
// The handle pins the namespace for as long as it stays open, so a mutation
// made through it can never land in an unrelated namespace that later reuses
// the path. Verify detects that reuse, so the caller can refuse to act on a
// sandbox it did not authenticate.
type Namespace struct {
	path string
	fd   netns.NsHandle
	dev  uint64
	ino  uint64
}

// OpenNamespace opens the network namespace at path, typically a sandbox's
// bind mount under /var/run/netns or /proc/<pid>/ns/net. The caller owns the
// returned handle and must Close it.
func OpenNamespace(path string) (*Namespace, error) {
	fd, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("hostattach: open network namespace %q: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(fd), &st); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("hostattach: stat network namespace %q: %w", path, err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		_ = fd.Close()
		return nil, fmt.Errorf("hostattach: %q is a directory, not a network namespace", path)
	}
	return &Namespace{path: path, fd: fd, dev: st.Dev, ino: st.Ino}, nil
}

// Path is the path the handle was opened from.
func (n *Namespace) Path() string { return n.path }

// Verify reports whether the path still names the namespace this handle
// holds. It wraps ErrNamespaceReplaced when another namespace, or nothing,
// is at the path now.
func (n *Namespace) Verify() error {
	var st unix.Stat_t
	if err := unix.Stat(n.path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: %q no longer exists", ErrNamespaceReplaced, n.path)
		}
		return fmt.Errorf("hostattach: stat network namespace %q: %w", n.path, err)
	}
	if st.Dev != n.dev || st.Ino != n.ino {
		return fmt.Errorf("%w: %q", ErrNamespaceReplaced, n.path)
	}
	return nil
}

// netlink returns a netlink handle that operates inside the namespace. The
// caller must Close it.
func (n *Namespace) netlink() (*netlink.Handle, error) {
	h, err := netlink.NewHandleAt(n.fd)
	if err != nil {
		return nil, fmt.Errorf("hostattach: netlink handle in %q: %w", n.path, err)
	}
	return h, nil
}

// do runs fn on a thread switched into the namespace, for the few operations
// that act on the calling thread's namespace rather than a netlink socket's:
// creating a TUN device and writing per-namespace sysctls.
func (n *Namespace) do(fn func() error) error {
	return runInNamespace(n.fd, fn)
}

// runInNamespace runs fn on a locked OS thread switched into target. If the
// thread cannot be switched back, it stays locked so the Go runtime retires it
// instead of reusing a thread left in the wrong namespace.
func runInNamespace(target netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	origin, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("hostattach: read current network namespace: %w", err)
	}
	defer func() { _ = origin.Close() }()
	if err := netns.Set(target); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("hostattach: enter network namespace: %w", err)
	}
	fnErr := fn()
	if err := netns.Set(origin); err != nil {
		return errors.Join(fnErr, fmt.Errorf("hostattach: restore network namespace: %w", err))
	}
	runtime.UnlockOSThread()
	return fnErr
}

// Close releases the handle.
func (n *Namespace) Close() error {
	if err := n.fd.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("hostattach: close network namespace %q: %w", n.path, err)
	}
	return nil
}
