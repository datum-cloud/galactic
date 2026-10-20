// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// tunQueueLen bounds the packets buffered per session; the reader drops a
// packet for a session whose queue is full.
const tunQueueLen = 256

// TUNBackend is a PacketBackend for one VPC that exchanges packets with a
// Linux TUN device. Packets from clients are written to the device, and
// packets read from the device are delivered to the session whose assigned
// address matches their destination.
type TUNBackend struct {
	vpc string
	dev *os.File

	mu       sync.Mutex
	sessions map[netip.Addr]*tunSession

	readerDone chan struct{}
}

// OpenTUN attaches to the TUN device name, creating it when it does not exist,
// and returns a backend serving vpc. The device is opened without packet
// information headers, so every read and write is one bare IP packet.
func OpenTUN(name, vpc string) (*TUNBackend, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("could not build request for %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("could not attach to TUN device %q: %w", name, err)
	}
	b := &TUNBackend{
		vpc:        vpc,
		dev:        os.NewFile(uintptr(fd), "/dev/net/tun"),
		sessions:   map[netip.Addr]*tunSession{},
		readerDone: make(chan struct{}),
	}
	go b.readLoop()
	return b, nil
}

// Close closes the device and ends every session's ReadPacket.
func (b *TUNBackend) Close() error {
	err := b.dev.Close()
	<-b.readerDone
	return err
}

// Open registers a session for info.Address. It returns an error when info
// is for another VPC or the address already has a session.
func (b *TUNBackend) Open(_ context.Context, info SessionInfo) (BackendSession, error) {
	if info.VPC != b.vpc {
		return nil, fmt.Errorf("TUN backend serves VPC %q, not %q", b.vpc, info.VPC)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.sessions[info.Address]; dup {
		return nil, fmt.Errorf("address %s already has a session", info.Address)
	}
	s := &tunSession{backend: b, addr: info.Address, in: make(chan []byte, tunQueueLen), closed: make(chan struct{})}
	b.sessions[info.Address] = s
	return s, nil
}

func (b *TUNBackend) readLoop() {
	defer close(b.readerDone)
	defer b.closeSessions()
	buf := make([]byte, maxPacketSize)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			return
		}
		dst, ok := packetDestination(buf[:n])
		if !ok {
			continue
		}
		b.mu.Lock()
		s := b.sessions[dst]
		b.mu.Unlock()
		if s == nil {
			continue
		}
		select {
		case s.in <- append([]byte(nil), buf[:n]...):
		default:
		}
	}
}

func (b *TUNBackend) closeSessions() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for addr, s := range b.sessions {
		s.closeOnce.Do(func() { close(s.closed) })
		delete(b.sessions, addr)
	}
}

type tunSession struct {
	backend   *TUNBackend
	addr      netip.Addr
	in        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *tunSession) WritePacket(pkt []byte) error {
	if _, err := s.backend.dev.Write(pkt); err != nil {
		return fmt.Errorf("could not write to TUN device: %w", err)
	}
	return nil
}

func (s *tunSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case pkt := <-s.in:
		return copy(buf, pkt), nil
	case <-s.closed:
		return 0, errors.New("session closed")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *tunSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if s.backend.sessions[s.addr] == s {
		delete(s.backend.sessions, s.addr)
	}
	return nil
}

// packetDestination returns the destination address of an IPv4 or IPv6
// packet.
func packetDestination(pkt []byte) (netip.Addr, bool) {
	switch {
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	default:
		return netip.Addr{}, false
	}
}
