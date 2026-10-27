// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenTUN attaches to the existing TUN device name, as galactic-edge
// creates it in the provider pod for a PacketAccess attachment, and returns
// a nonblocking descriptor without packet-information headers. Attaching
// as the device's owner needs no capability.
func OpenTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attach to TUN %s: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}
