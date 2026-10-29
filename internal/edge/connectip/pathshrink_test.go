// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/icmp"
)

// maxH3InnerPacket is the largest inner packet a DefaultInitialPacketSize
// QUIC packet carries on a connection's first request.
const maxH3InnerPacket = 1311

// shrinkingPath relays UDP between one client and the server on loopback.
// Datagrams toward the client larger than its limit are dropped without an
// ICMP error, the way a path whose MTU fell behind a router that does not
// signal it, or whose signal the server ignores, behaves.
type shrinkingPath struct {
	front    *net.UDPConn
	back     *net.UDPConn
	limit    atomic.Int64
	dropped  atomic.Int64
	clientMu sync.Mutex
	client   *net.UDPAddr
}

// newShrinkingPath relays to the server at serverAddr and returns once the
// relay listens. Its limit starts at 0, which drops nothing.
func newShrinkingPath(t *testing.T, serverAddr string) *shrinkingPath {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	server, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		t.Fatalf("resolve server: %v", err)
	}
	back, err := net.DialUDP("udp4", nil, server)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	p := &shrinkingPath{front: front, back: back}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.clientMu.Lock()
			p.client = from
			p.clientMu.Unlock()
			_, _ = back.Write(buf[:n])
		}
	})
	wg.Go(func() {
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if limit := p.limit.Load(); limit > 0 && int64(n) > limit {
				p.dropped.Add(1)
				continue
			}
			p.clientMu.Lock()
			client := p.client
			p.clientMu.Unlock()
			if client != nil {
				_, _ = front.WriteToUDP(buf[:n], client)
			}
		}
	})
	t.Cleanup(func() {
		_ = front.Close()
		_ = back.Close()
		wg.Wait()
	})
	return p
}

func (p *shrinkingPath) addr() string { return p.front.LocalAddr().String() }

// shrink makes the path drop every UDP payload toward the client larger than
// limit bytes; 0 restores it.
func (p *shrinkingPath) shrink(limit int) { p.limit.Store(int64(limit)) }

// dialThrough opens a client QUIC connection to env's server through path.
func (e *testEnv) dialThrough(t *testing.T, path *shrinkingPath) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, path.addr(), e.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("dial QUIC through relay: %v", err)
	}
	t.Cleanup(func() { _ = qconn.CloseWithError(0, "") })
	return qconn
}

// countPacketTooBig counts the ICMPv6 Packet Too Big messages reporting mtu
// that sess received.
func countPacketTooBig(sess *memorySession, mtu int) int {
	var n int
	for _, pkt := range sess.packets() {
		p, err := tryParseICMPv6(pkt)
		if err != nil {
			continue
		}
		if ptb, ok := p.msg.Body.(*icmp.PacketTooBig); ok && ptb.MTU == mtu {
			n++
		}
	}
	return n
}

// TestH3PathShrinkAboveFloorAnswersPacketTooBig is the first half of #1237:
// the path toward the client shrinks after the handshake but still carries
// a MinInnerMTU packet. A larger gVPC packet must draw an ICMPv6 Packet Too
// Big reporting MinInnerMTU instead of vanishing on the path.
func TestH3PathShrinkAboveFloorAnswersPacketTooBig(t *testing.T) {
	env := startServer(t, nil)
	path := newShrinkingPath(t, env.addr)
	cc := newClientConn(t, env.dialThrough(t, path))
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess := env.backend.nextOpened(t)

	sess.inject(echoRequest(t, testTarget, s.address, 1, MinInnerMTU))
	if got := len(readPacket(t, s.conn)); got != MinInnerMTU {
		t.Fatalf("delivered %d bytes, want %d", got, MinInnerMTU)
	}
	// Give path MTU discovery, if the server runs it, time to grow past the
	// size the path is about to shrink to.
	time.Sleep(500 * time.Millisecond)
	path.shrink(1400)

	// Before the fix the server had grown its packets past 1400 bytes, so
	// this packet left as one and the path dropped it.
	sess.inject(echoRequest(t, testTarget, s.address, 2, 1400))
	pollUntil(t, "a Packet Too Big reporting the minimum inner MTU reaches the backend", func() bool {
		return countPacketTooBig(sess, MinInnerMTU) == 1
	})
	sess.inject(echoRequest(t, testTarget, s.address, 4, maxH3InnerPacket+1))
	pollUntil(t, "a second Packet Too Big reaches the backend", func() bool {
		return countPacketTooBig(sess, MinInnerMTU) == 2
	})
	// A fixed 1350-byte QUIC packet carries 1311 inner bytes on a request
	// whose quarter stream ID takes one byte.
	sess.inject(echoRequest(t, testTarget, s.address, 3, maxH3InnerPacket))
	if got := len(readPacket(t, s.conn)); got != maxH3InnerPacket {
		t.Fatalf("after the shrink, delivered %d bytes, want %d", got, maxH3InnerPacket)
	}
	if n := path.dropped.Load(); n != 0 {
		t.Fatalf("the path dropped %d datagrams toward the client, want none", n)
	}
}

// TestH3PathShrinkBelowFloorEndsTunnel is the second half of #1237: once the
// path toward the client can no longer carry a MinInnerMTU packet, the
// request ends as path_mtu, a new request on the same connection is refused
// by the admission probe, and one is accepted again once the path recovers.
// The gVPC either keeps sending MinInnerMTU packets, which keeps restarting
// quic-go's probe timeout, or sends one and falls silent.
func TestH3PathShrinkBelowFloorEndsTunnel(t *testing.T) {
	t.Run("steady", func(t *testing.T) { testPathShrinkBelowFloor(t, 50*time.Millisecond) })
	t.Run("single", func(t *testing.T) { testPathShrinkBelowFloor(t, 0) })
}

// testPathShrinkBelowFloor sends a MinInnerMTU packet toward the client
// every interval after the path shrinks, or only one when interval is 0.
func testPathShrinkBelowFloor(t *testing.T, interval time.Duration) {
	env := startServer(t, nil)
	path := newShrinkingPath(t, env.addr)
	cc := newClientConn(t, env.dialThrough(t, path))
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess := env.backend.nextOpened(t)

	sess.inject(echoRequest(t, testTarget, s.address, 1, MinInnerMTU))
	if got := len(readPacket(t, s.conn)); got != MinInnerMTU {
		t.Fatalf("delivered %d bytes, want %d", got, MinInnerMTU)
	}
	endsBefore := ends(transportH3, causePathMTU)
	deniedBefore := testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonPathMTU))
	refusedBefore := requests(transportH3, outcomeMTU)

	// A MinInnerMTU packet travels in a UDP payload of more than 1300 bytes.
	path.shrink(1300)
	shrunk := time.Now()
	stopPinging := make(chan struct{})
	var pinging sync.WaitGroup
	pinging.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stopPinging:
				return
			case <-sess.closed:
				return
			case sess.toClient <- echoRequest(t, testTarget, s.address, 10+i, MinInnerMTU):
			default:
			}
			if interval == 0 {
				return
			}
			time.Sleep(interval)
		}
	})
	defer func() {
		close(stopPinging)
		pinging.Wait()
	}()

	select {
	case <-sess.closed:
	case <-time.After(3 * testTimeout):
		t.Fatalf("tunnel still open %v after the path stopped carrying %d-byte packets", 3*testTimeout, MinInnerMTU)
	}
	t.Logf("tunnel ended %v after the path shrank", time.Since(shrunk))
	eventually(t, "the tunnel end is counted as path_mtu", func() bool {
		return ends(transportH3, causePathMTU)-endsBefore == 1
	})
	if got := testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonPathMTU)) - deniedBefore; got != 1 {
		t.Fatalf("%s/%s denials = %v, want 1", toClient, reasonPathMTU, got)
	}

	dialed := time.Now()
	conn, rsp, err := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	t.Logf("request over the shrunk path answered in %v", time.Since(dialed))
	if err == nil {
		_ = conn.Close()
	}
	if rsp == nil || rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request over the shrunk path: response %v, error %v; want 503", rsp, err)
	}
	if got := requests(transportH3, outcomeMTU) - refusedBefore; got != 1 {
		t.Fatalf("%s/%s requests = %v, want 1", transportH3, outcomeMTU, got)
	}

	path.shrink(0)
	s = open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess = env.backend.nextOpened(t)
	sess.inject(echoRequest(t, testTarget, s.address, 2, MinInnerMTU))
	if got := len(readPacket(t, s.conn)); got != MinInnerMTU {
		t.Fatalf("after the path recovered, delivered %d bytes, want %d", got, MinInnerMTU)
	}
}
