// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// withoutSysAdmin runs fn with CAP_SYS_ADMIN cleared from the calling
// thread's effective set, as galactic-router runs, and restores it after.
// The capability stays permitted, so the thread can raise it again before
// leaving the test's namespace. The caller must be on a locked OS thread.
func withoutSysAdmin(fn func() error) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	const bit = uint32(1) << unix.CAP_SYS_ADMIN
	data[0].Effective &^= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop CAP_SYS_ADMIN: %w", err)
	}
	fnErr := fn()
	data[0].Effective |= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return errors.Join(fnErr, fmt.Errorf("restore CAP_SYS_ADMIN: %w", err))
	}
	return fnErr
}

// TestListHostNeedsNoSysAdmin lists a stamped link from the caller's own
// namespace without CAP_SYS_ADMIN, which galactic-router does not hold.
// Listing through a Namespace handle enters the namespace and is refused.
func TestListHostNeedsNoSysAdmin(t *testing.T) {
	requireRoot(t)
	host := newTestNS(t)
	id := LinkID("10", "uid")
	host.do(t, func() error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "gh0"}, PeerName: "gp0"}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("add veth: %w", err)
		}
		if err := netlink.LinkSetAlias(veth, ownerAlias(id)); err != nil {
			return fmt.Errorf("stamp veth: %w", err)
		}
		return withoutSysAdmin(func() error {
			got, err := ListHost()
			if err != nil {
				return fmt.Errorf("ListHost without CAP_SYS_ADMIN: %w", err)
			}
			if len(got) != 1 || got[0].ID != id || got[0].HostLink != "gh0" {
				return fmt.Errorf("ListHost = %+v, want the stamped veth %s", got, id)
			}
			self, err := OpenNamespace("/proc/thread-self/ns/net")
			if err != nil {
				return err
			}
			defer func() { _ = self.Close() }()
			// netlink reports the refused setns without wrapping its errno.
			if _, err := List(self); err == nil {
				return errors.New("List through a namespace handle succeeded without CAP_SYS_ADMIN")
			}
			return nil
		})
	})
}
