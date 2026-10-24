// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dataplane serves an attachment's traffic with no host privilege:
// a UDP echo socket bound to the attachment's pod VRF (SocketAccess), and a
// responder on the TUN device galactic-edge created in the pod
// (PacketAccess). Both answer with the provider's identity so a client can
// tell which instance answered.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/datum-cloud/galactic/examples/edge-provider/internal/packet"
	"golang.org/x/sys/unix"
)

// Server is one running data plane. Close stops it and waits for it.
type Server interface {
	Close() error
}

// Echo serves UDP on address and port, bound to the VRF vrf, replying with
// identity, a space and the request's payload. Binding a socket to a device
// needs no capability as long as the socket is not already bound to one.
func Echo(ctx context.Context, log *slog.Logger, vrf string, address netip.Addr, port uint16, identity string,
) (Server, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, vrf)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp6", net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("listen on [%s]:%d in VRF %s: %w", address, port, vrf, err)
	}
	s := &loop{closer: pc}
	s.wg.Go(func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Error("echo socket read failed", "vrf", vrf, "error", err)
				}
				return
			}
			reply := append([]byte(identity+" "), buf[:n]...)
			if _, err := pc.WriteTo(reply, from); err != nil {
				log.Warn("echo reply failed", "to", from, "error", err)
			}
		}
	})
	return s, nil
}

// TUN answers ICMPv6 echo requests and UDP datagrams arriving on the TUN
// device name, which this process opens as the device's owner without
// CAP_NET_ADMIN, while allow reports true; it drops everything it reads
// while allow reports false. /dev/net/tun must be available in the
// container.
func TUN(log *slog.Logger, name, identity string, allow func() bool) (Server, error) {
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
	f := os.NewFile(uintptr(fd), name)
	s := &loop{closer: f}
	s.wg.Go(func() {
		buf := make([]byte, 65535)
		for {
			n, err := f.Read(buf)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					log.Error("TUN read failed", "device", name, "error", err)
				}
				return
			}
			if !allow() {
				continue
			}
			reply, err := packet.Reply(buf[:n], identity)
			if err != nil {
				continue
			}
			if _, err := f.Write(reply); err != nil {
				log.Warn("TUN reply failed", "device", name, "error", err)
			}
		}
	})
	return s, nil
}

type closer interface{ Close() error }

type loop struct {
	closer closer
	wg     sync.WaitGroup
	once   sync.Once
	err    error
}

func (l *loop) Close() error {
	l.once.Do(func() {
		l.err = l.closer.Close()
		l.wg.Wait()
	})
	return l.err
}
