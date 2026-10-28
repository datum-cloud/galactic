// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// stallConn is a client UDP socket that discards everything it receives
// once stalled, as a client that stopped reading would.
type stallConn struct {
	net.PacketConn
	stalled atomic.Bool
}

func (c *stallConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.stalled.Load() {
			return n, addr, err
		}
	}
}

func shortenDeliveryTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := deliveryTimeout
	deliveryTimeout = d
	t.Cleanup(func() { deliveryTimeout = old })
}

func slowClientEnds() float64 {
	return testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonSlowClient))
}

// TestH3StalledClientEndsOnlyItsSession stops one HTTP/3 client reading
// while packets keep arriving for it. Its datagram send queue fills, and
// the session ends after deliveryTimeout rather than the 30 s QUIC idle
// timeout. A session on another connection keeps forwarding.
func TestH3StalledClientEndsOnlyItsSession(t *testing.T) {
	shortenDeliveryTimeout(t, 300*time.Millisecond)
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sc := &stallConn{PacketConn: udp}
	tr := &quic.Transport{Conn: sc}
	t.Cleanup(func() { _ = tr.Close() })
	raddr, err := net.ResolveUDPAddr("udp4", env.addr)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := tr.Dial(t.Context(), raddr, env.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("dial QUIC: %v", err)
	}
	slow := open(t, newClientConn(t, qconn), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	slowSess := env.backend.nextOpened(t)
	fast := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
	fastSess := env.backend.nextOpened(t)

	before := slowClientEnds()
	sc.stalled.Store(true)
	start := time.Now()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case slowSess.toClient <- echoRequest(t, testTarget, slow.address, i%60000, 1200):
			case <-stop:
				return
			case <-slowSess.closed:
				return
			}
		}
	})
	defer func() { close(stop); wg.Wait() }()
	slowSess.waitClosed(t)
	if took := time.Since(start); took > 10*deliveryTimeout {
		t.Fatalf("stalled session ended after %v, want about %v", took, deliveryTimeout)
	}
	adm.waitReleased(t, slowSess.info)
	if got := slowClientEnds() - before; got != 1 {
		t.Fatalf("slow_client count rose by %v, want 1", got)
	}

	if _, err := fast.conn.WritePacket(echoRequest(t, fast.address, testTarget, 70, 200)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if id := echoID(t, parseICMPv6(t, readPacket(t, fast.conn))); id != 70 {
		t.Fatalf("reply id %d, want 70", id)
	}
	if fastSess.isClosed() {
		t.Fatal("the other connection's session closed")
	}
}

// TestTUNQueueFullDropIsCounted fills one session's queue toward the client
// from the device and counts each packet past the cap as queue_full. A
// SOCK_SEQPACKET socket stands in for the TUN descriptor.
func TestTUNQueueFullDropIsCounted(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	peer := os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() { _ = peer.Close() })
	b, err := NewTUNBackend(os.NewFile(uintptr(fds[0]), "dev"), vpcBlue)
	if err != nil {
		t.Fatalf("NewTUNBackend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	info := SessionInfo{ID: 1, VPC: vpcBlue, Prefix: firstPrefix}
	if _, err := b.Open(t.Context(), info); err != nil {
		t.Fatalf("Open: %v", err)
	}
	queueFull := func() float64 {
		return testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonQueueFull))
	}
	before := queueFull()
	const extra = 5
	pkt := echoRequest(t, testTarget, firstClient, 1, 200)
	for range tunQueueLen + extra {
		if _, err := unix.Write(fds[1], pkt); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	pollUntil(t, "queue_full drops", func() bool { return queueFull()-before == extra })
}
