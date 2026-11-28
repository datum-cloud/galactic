// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// TestEchoUDPAndTCP binds the echo to the loopback device, which needs no
// capability, and checks that both protocols answer with the identity
// prefix and that Close ends an open TCP connection.
func TestEchoUDPAndTCP(t *testing.T) {
	ctx := context.Background()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	addr := net.JoinHostPort("::1", strconv.Itoa(port))

	d := net.Dialer{Timeout: 2 * time.Second}
	s, err := Echo(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "lo",
		netip.MustParseAddr("::1"), uint16(port), "id-1")
	if err != nil {
		t.Skipf("cannot bind to lo: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for _, network := range []string{"udp6", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, err := c.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(buf[:n]); got != "id-1 ping" {
				t.Fatalf("reply %q, want %q", got, "id-1 ping")
			}
		})
	}

	// An answered exchange proves the server accepted the connection, so
	// Close must end it rather than racing its accept.
	c, err := d.DialContext(ctx, "tcp6", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("hold")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return with a TCP connection open")
	}
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection stayed open after Close")
	}
}
