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
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// tunQueueLen and tunQueueBytes bound the packets and bytes buffered per
// session; the reader drops a packet for a session whose queue is full.
const (
	tunQueueLen   = 128
	tunQueueBytes = 256 << 10
)

// TUNBackend is a PacketBackend for one VPC that exchanges packets with a
// Linux TUN device. Packets from clients are written to the device, and
// packets read from the device are delivered to the session whose delegated
// /96 contains their destination. The caller must wrap this packet adapter
// with attachment/claim validation and independent forwarding expiry.
type TUNBackend struct {
	vpc string
	dev *os.File

	mu       sync.Mutex
	closed   bool
	sessions map[netip.Prefix]*tunSession

	readerDone chan struct{}
}

// NewTUNBackend takes ownership of an already provisioned, nonblocking TUN
// descriptor without packet-information headers. The provisioner owns namespace,
// link and route setup; this backend only performs packet I/O for one gVPC.
func NewTUNBackend(dev *os.File, vpc string) (*TUNBackend, error) {
	if dev == nil || vpc == "" {
		return nil, errors.New("TUN descriptor and gVPC are required")
	}
	raw, err := dev.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("could not access TUN descriptor: %w", err)
	}
	var flags int
	var flagErr error
	if err := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		return nil, fmt.Errorf("could not inspect TUN descriptor: %w", err)
	}
	if flagErr != nil {
		return nil, fmt.Errorf("could not read TUN flags: %w", flagErr)
	}
	if flags&unix.O_NONBLOCK == 0 {
		return nil, errors.New("TUN descriptor must be nonblocking")
	}
	b := &TUNBackend{
		vpc:        vpc,
		dev:        dev,
		sessions:   map[netip.Prefix]*tunSession{},
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

// Open registers a session for a masked /96. It rejects another gVPC,
// an invalid prefix or a prefix already bound to a session.
func (b *TUNBackend) Open(_ context.Context, info SessionInfo) (BackendSession, error) {
	if !info.Prefix.IsValid() || !info.Prefix.Addr().Is6() || info.Prefix.Addr().Is4In6() ||
		info.Prefix.Bits() != 96 || info.Prefix != info.Prefix.Masked() {
		return nil, errors.New("invalid connector prefix")
	}
	if info.VPC != b.vpc {
		return nil, fmt.Errorf("TUN backend serves VPC %q, not %q", b.vpc, info.VPC)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("TUN backend closed")
	}
	if _, dup := b.sessions[info.Prefix]; dup {
		return nil, fmt.Errorf("prefix %s already has a session", info.Prefix)
	}
	s := &tunSession{backend: b, prefix: info.Prefix, in: make(chan []byte, tunQueueLen), closed: make(chan struct{})}
	b.sessions[info.Prefix] = s
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
		switch {
		case !ok:
			deny(toClient, reasonMalformed)
			continue
		case !dst.Is6():
			deny(toClient, reasonIPv4)
			continue
		}
		b.mu.Lock()
		s := b.sessions[netip.PrefixFrom(dst, 96).Masked()]
		b.mu.Unlock()
		if s == nil {
			// The kernel sends its own multicast and link-local traffic,
			// such as MLD reports, on the device; only count what was
			// routed here.
			if !dst.IsMulticast() && !dst.IsLinkLocalUnicast() {
				deny(toClient, reasonNoSession)
			}
			continue
		}
		s.enqueue(buf[:n])
	}
}

func (b *TUNBackend) closeSessions() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for addr, s := range b.sessions {
		s.closeOnce.Do(func() { close(s.closed) })
		delete(b.sessions, addr)
	}
}

type tunSession struct {
	backend   *TUNBackend
	prefix    netip.Prefix
	in        chan []byte
	queued    atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once
}

// enqueue queues a copy of pkt for the client, or drops it when the queue
// is full by packets or bytes.
func (s *tunSession) enqueue(pkt []byte) bool {
	if s.queued.Add(int64(len(pkt))) > tunQueueBytes {
		s.queued.Add(-int64(len(pkt)))
		return false
	}
	select {
	case s.in <- append([]byte(nil), pkt...):
		return true
	default:
		s.queued.Add(-int64(len(pkt)))
		return false
	}
}

func (s *tunSession) WritePacket(pkt []byte) error {
	// Serialize session release with a single nonblocking write. A full device
	// fails this request instead of blocking shutdown or another connector.
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if s.backend.closed || s.backend.sessions[s.prefix] != s {
		return errors.New("session closed")
	}
	raw, err := s.backend.dev.SyscallConn()
	if err != nil {
		return fmt.Errorf("could not access TUN descriptor: %w", err)
	}
	var writeErr error
	var n int
	if err := raw.Control(func(fd uintptr) { n, writeErr = unix.Write(int(fd), pkt) }); err != nil {
		return fmt.Errorf("could not access TUN descriptor: %w", err)
	}
	if writeErr != nil {
		return fmt.Errorf("could not write to TUN device: %w", writeErr)
	}
	if n != len(pkt) {
		return errors.New("short TUN write")
	}
	return nil
}

func (s *tunSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case pkt := <-s.in:
		s.queued.Add(-int64(len(pkt)))
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
	if s.backend.sessions[s.prefix] == s {
		delete(s.backend.sessions, s.prefix)
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
