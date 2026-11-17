// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	connectip "github.com/quic-go/connect-ip-go"
	"golang.org/x/net/ipv6"
)

// narrowTunnel is a tunnel whose path carries packets of at most limit
// bytes. Like connect-ip-go over a QUIC path that shrank, it answers a larger
// packet with a Packet Too Big reporting MinInnerMTU.
type narrowTunnel struct {
	limit  int
	once   sync.Once
	closed chan struct{}
}

func newNarrowTunnel(limit int) *narrowTunnel {
	return &narrowTunnel{limit: limit, closed: make(chan struct{})}
}

func (t *narrowTunnel) ReadPacket([]byte) (int, error) {
	<-t.closed
	return 0, context.Canceled
}

func (t *narrowTunnel) WritePacket(b []byte) ([]byte, error) {
	if len(b) <= t.limit {
		return nil, nil
	}
	return packetTooBig(b, MinInnerMTU)
}

func (t *narrowTunnel) AssignAddresses([]netip.Prefix) error     { return nil }
func (t *narrowTunnel) AdvertiseRoute([]connectip.IPRoute) error { return nil }

func (t *narrowTunnel) receiveAddressRequest(ctx context.Context) (addressRequest, error) {
	select {
	case <-ctx.Done():
	case <-t.closed:
	}
	return addressRequest{}, context.Canceled
}

func (t *narrowTunnel) abort() { _ = t.Close() }

func (*narrowTunnel) pathLost() <-chan struct{} { return nil }

func (t *narrowTunnel) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *narrowTunnel) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// runProxySession runs proxySession over tun and a fresh backend session
// until the test ends or the session does, which closes the returned
// channel after sending the session's end cause on it.
func runProxySession(t *testing.T, tun tunnel) (*memorySession, <-chan string) {
	t.Helper()
	bs, err := newMemoryBackend().Open(t.Context(), SessionInfo{})
	if err != nil {
		t.Fatal(err)
	}
	sess := bs.(*memorySession)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() {
		defer close(done)
		done <- (&Server{}).proxySession(ctx, slog.Default(), tun, sess,
			newPacketPolicy(firstPrefix, []netip.Prefix{policyRoute}), newForwardCounters(transportH3))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sess, done
}

// TestProxyEndsSessionBelowMinimumMTU is the reproduction from #982: once the
// path cannot carry a MinInnerMTU packet toward the client, the session used
// to stay open and answer with a Packet Too Big reporting MinInnerMTU, which
// the sender cannot act on. RFC 9484 section 10.1 ends the tunnel instead.
func TestProxyEndsSessionBelowMinimumMTU(t *testing.T) {
	before := testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonPathMTU))
	tun := newNarrowTunnel(MinInnerMTU - 1)
	sess, done := runProxySession(t, tun)
	sess.inject(echoRequest(t, policyTarget, firstClient, 1, MinInnerMTU))
	select {
	case cause := <-done:
		if cause != causePathMTU {
			t.Errorf("session ended with cause %q, want %q", cause, causePathMTU)
		}
	case <-time.After(testTimeout):
		t.Fatalf("session still open after a %d-byte packet could not be sent", MinInnerMTU)
	}
	if !tun.isClosed() || !sess.isClosed() {
		t.Fatal("tunnel and backend session must both be closed")
	}
	for _, pkt := range sess.packets() {
		if p, err := tryParseICMPv6(pkt); err == nil && p.msg.Type == ipv6.ICMPTypePacketTooBig {
			t.Fatal("backend received a Packet Too Big for a packet the sender cannot shrink")
		}
	}
	if got := testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonPathMTU)) - before; got != 1 {
		t.Fatalf("%s/%s denials = %v, want 1", toClient, reasonPathMTU, got)
	}
}

// TestProxyKeepsSessionAboveMinimumMTU checks that a path still carrying
// MinInnerMTU packets answers a larger packet with Packet Too Big and keeps
// the session.
func TestProxyKeepsSessionAboveMinimumMTU(t *testing.T) {
	tun := newNarrowTunnel(MinInnerMTU)
	sess, done := runProxySession(t, tun)
	sess.inject(echoRequest(t, policyTarget, firstClient, 1, MinInnerMTU+1))
	pollUntil(t, "a Packet Too Big reaches the backend", func() bool {
		for _, pkt := range sess.packets() {
			if p, err := tryParseICMPv6(pkt); err == nil && p.msg.Type == ipv6.ICMPTypePacketTooBig {
				return true
			}
		}
		return false
	})
	select {
	case <-done:
		t.Fatal("session ended although the path carries the minimum inner MTU")
	default:
	}
}
