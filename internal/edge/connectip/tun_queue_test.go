// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import "testing"

func TestTUNSessionQueueByteLimit(t *testing.T) {
	s := &tunSession{in: make(chan []byte, tunQueueLen), closed: make(chan struct{})}
	pkt := make([]byte, maxPacketSize)
	fits := tunQueueBytes / maxPacketSize
	for i := range fits {
		if !s.enqueue(pkt) {
			t.Fatalf("packet %d dropped below the byte cap", i)
		}
	}
	if s.enqueue(pkt) {
		t.Fatalf("packet %d queued past the %d-byte cap", fits, tunQueueBytes)
	}
	if got := s.queued.Load(); got != int64(fits*maxPacketSize) {
		t.Fatalf("queued = %d bytes, want %d", got, fits*maxPacketSize)
	}
	buf := make([]byte, maxPacketSize)
	if _, err := s.ReadPacket(t.Context(), buf); err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !s.enqueue(pkt) {
		t.Fatal("packet dropped after the queue drained")
	}
}

func TestTUNSessionQueuePacketLimit(t *testing.T) {
	s := &tunSession{in: make(chan []byte, tunQueueLen), closed: make(chan struct{})}
	for i := range tunQueueLen {
		if !s.enqueue([]byte{6 << 4}) {
			t.Fatalf("packet %d dropped below the packet cap", i)
		}
	}
	if s.enqueue([]byte{6 << 4}) {
		t.Fatal("packet queued past the packet cap")
	}
	if got := s.queued.Load(); got != tunQueueLen {
		t.Fatalf("queued = %d bytes, want %d", got, tunQueueLen)
	}
}
