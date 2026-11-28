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
	"time"

	"github.com/datum-cloud/galactic/examples/edge-provider/internal/packet"
	"golang.org/x/sys/unix"
)

// Server is one running data plane. Close stops it and waits for it.
type Server interface {
	Close() error
}

// Echo serves UDP and TCP on address and port, bound to the VRF vrf. Each
// UDP datagram, and each read on a TCP connection, is answered with
// identity, a space and the bytes received. Binding a socket to a device
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
	hostPort := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	pc, err := lc.ListenPacket(ctx, "udp6", hostPort)
	if err != nil {
		return nil, fmt.Errorf("listen on UDP [%s]:%d in VRF %s: %w", address, port, vrf, err)
	}
	ln, err := lc.Listen(ctx, "tcp6", hostPort)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("listen on TCP [%s]:%d in VRF %s: %w", address, port, vrf, err)
	}
	conns := &connSet{conns: map[net.Conn]struct{}{}}
	s := &loop{closer: multiCloser{pc, ln, conns}}
	s.wg.Go(func() {
		var backoff time.Duration
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// A transient failure such as running out of descriptors
				// must not end TCP service while UDP keeps answering.
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				log.Error("echo listener accept failed", "vrf", vrf, "error", err, "retryIn", backoff)
				time.Sleep(backoff)
				continue
			}
			backoff = 0
			if !conns.add(c) {
				_ = c.Close()
				return
			}
			s.wg.Go(func() {
				defer conns.remove(c)
				buf := make([]byte, 4096)
				for {
					_ = c.SetReadDeadline(time.Now().Add(tcpIdle))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(append([]byte(identity+" "), buf[:n]...)); err != nil {
						log.Warn("echo reply failed", "to", c.RemoteAddr(), "error", err)
						return
					}
				}
			})
		}
	})
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

// tcpIdle is how long a TCP echo connection may stay silent before the
// server closes it.
const tcpIdle = time.Minute

type closer interface{ Close() error }

// multiCloser closes each of its members and returns the first error.
type multiCloser []closer

func (m multiCloser) Close() error {
	var first error
	for _, c := range m {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// connSet holds the open TCP echo connections, so closing the server ends
// them and its wait returns. Once closed it refuses new connections.
type connSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func (s *connSet) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *connSet) remove(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

func (s *connSet) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	return nil
}

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
